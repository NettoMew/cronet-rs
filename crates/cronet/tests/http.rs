//! `http::Client` against a local HTTP/1.1 server.

#![cfg(feature = "http")]

mod common;

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use common::{TestResponse, http_server, http_server_with, silent_server};
use cronet::{
    Executor, NetError, UrlResponseInfo,
    http::{Body, Client, Error},
};
use http_body::{Body as _, Frame, SizeHint};
use tokio::sync::mpsc;

fn client() -> Client {
    Client::with_engine(common::engine(), Executor::thread())
}

/// A body fed through a channel, a chunk at a time.
struct ChannelBody {
    chunks: mpsc::Receiver<Bytes>,
    length: Option<u64>,
}

impl http_body::Body for ChannelBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        self.chunks
            .poll_recv(cx)
            .map(|chunk| chunk.map(|chunk| Ok(Frame::data(chunk))))
    }

    fn size_hint(&self) -> SizeHint {
        self.length.map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

/// A body sent from a task, a chunk at a time with pauses in between, so that
/// the upload has to wait for it.
fn channel_body(chunks: &'static [&'static str], length: Option<u64>) -> Body {
    let (sender, receiver) = mpsc::channel(1);
    tokio::spawn(async move {
        for chunk in chunks {
            tokio::time::sleep(Duration::from_millis(20)).await;
            sender.send(Bytes::from_static(chunk.as_bytes())).await.unwrap();
        }
    });
    Body::wrap(ChannelBody {
        chunks: receiver,
        length,
    })
}

/// Echoes the method, a request header and the body.
fn echo_server() -> std::net::SocketAddr {
    http_server_with(|request| TestResponse {
        status: 200,
        headers: vec![("X-Method".into(), request.method.clone())],
        body: [
            request.header("x-echo").unwrap_or("-").as_bytes(),
            b"|",
            request.header("transfer-encoding").unwrap_or("-").as_bytes(),
            b"|",
            &request.body,
        ]
        .concat(),
    })
}

#[tokio::test]
async fn get_sends_headers_and_reads_the_body() {
    if !common::library() {
        return;
    }
    let server = echo_server();
    let request = http::Request::get(format!("http://{server}/get"))
        .header("X-Echo", "first")
        .header("X-Echo", "second")
        .body(Body::empty())
        .unwrap();
    let response = client().send(request).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.version(), http::Version::HTTP_11);
    assert_eq!(response.headers()["x-test"], "yes");
    assert_eq!(response.headers()["x-method"], "GET");
    let info = response
        .extensions()
        .get::<UrlResponseInfo>()
        .expect("the response info rides along");
    assert_eq!(info.url(), format!("http://{server}/get"));
    let body = response.into_body().bytes().await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.starts_with("first, second|"), "{body}");
    assert!(body.ends_with("|-|"), "{body}");
}

#[tokio::test]
async fn post_uploads_an_in_memory_body() {
    if !common::library() {
        return;
    }
    let server = echo_server();
    let request = http::Request::post(format!("http://{server}/post"))
        .header("Content-Type", "text/plain")
        .body(Body::from("in memory"))
        .unwrap();
    let response = client().send(request).await.unwrap();
    assert_eq!(response.headers()["x-method"], "POST");
    assert_eq!(response.into_body().bytes().await.unwrap(), "-|-|in memory");
}

#[tokio::test]
async fn post_streams_a_chunked_body() {
    if !common::library() {
        return;
    }
    let server = echo_server();
    let request = http::Request::post(format!("http://{server}/stream"))
        .header("Content-Type", "application/octet-stream")
        .body(channel_body(&["one ", "two ", "three"], None))
        .unwrap();
    let response = client().send(request).await.unwrap();
    assert_eq!(response.into_body().bytes().await.unwrap(), "-|chunked|one two three");
}

#[tokio::test]
async fn post_streams_a_body_of_known_length() {
    if !common::library() {
        return;
    }
    let server = echo_server();
    let request = http::Request::put(format!("http://{server}/stream"))
        .header("Content-Type", "application/octet-stream")
        .body(channel_body(&["abc", "def"], Some(6)))
        .unwrap();
    let response = client().send(request).await.unwrap();
    assert_eq!(response.headers()["x-method"], "PUT");
    assert_eq!(response.into_body().bytes().await.unwrap(), "-|-|abcdef");
}

#[tokio::test]
async fn a_short_body_fails_the_request() {
    if !common::library() {
        return;
    }
    let server = echo_server();
    let request = http::Request::post(format!("http://{server}/short"))
        .header("Content-Type", "application/octet-stream")
        .body(channel_body(&["abc"], Some(10)))
        .unwrap();
    let error = client().send(request).await.unwrap_err();
    assert!(matches!(error, Error::Request(_)), "{error:?}");
}

/// Answers `/from` with a redirect to `/to`, and `/to` with `arrived`.
fn redirect_server() -> std::net::SocketAddr {
    http_server_with(|request| match request.path.as_str() {
        "/from" => TestResponse {
            status: 302,
            headers: vec![("Location".into(), "/to".into())],
            body: Vec::new(),
        },
        _ => TestResponse {
            status: 200,
            headers: Vec::new(),
            body: b"arrived".to_vec(),
        },
    })
}

#[tokio::test]
async fn redirects_are_followed_by_default() {
    if !common::library() {
        return;
    }
    let server = redirect_server();
    let request = http::Request::get(format!("http://{server}/from"))
        .body(Body::empty())
        .unwrap();
    let response = client().send(request).await.unwrap();
    assert_eq!(response.status(), 200);
    let chain: Vec<String> = response
        .extensions()
        .get::<UrlResponseInfo>()
        .unwrap()
        .url_chain()
        .map(Into::into)
        .collect();
    assert_eq!(chain, [format!("http://{server}/from"), format!("http://{server}/to")]);
    assert_eq!(response.into_body().bytes().await.unwrap(), "arrived");
}

#[tokio::test]
async fn a_refused_redirect_is_the_response() {
    if !common::library() {
        return;
    }
    let server = redirect_server();
    let client = client().redirect_policy(move |url| !url.ends_with("/to"));
    let request = http::Request::get(format!("http://{server}/from"))
        .body(Body::empty())
        .unwrap();
    let response = client.send(request).await.unwrap();
    assert_eq!(response.status(), 302);
    assert_eq!(response.headers()["location"], "/to");
    assert!(response.body().is_end_stream());
    assert_eq!(response.into_body().bytes().await.unwrap(), "");
}

#[tokio::test]
async fn dropping_the_body_early_cancels_the_request() {
    if !common::library() {
        return;
    }
    let server = http_server(|_, _, _| (200, vec![7; 8 << 20]));
    let client = client();
    for _ in 0..3 {
        let request = http::Request::get(format!("http://{server}/large"))
            .body(Body::empty())
            .unwrap();
        let mut body = client.send(request).await.unwrap().into_body();
        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        assert!(!frame.into_data().unwrap().is_empty());
        drop(body);
    }
    let request = http::Request::get(format!("http://{server}/large"))
        .body(Body::empty())
        .unwrap();
    let body = client.send(request).await.unwrap().into_body().bytes().await.unwrap();
    assert_eq!(body.len(), 8 << 20);
}

#[tokio::test]
async fn dropping_the_send_future_cancels_the_request() {
    if !common::library() {
        return;
    }
    let silent = silent_server();
    let client = client();
    let request = http::Request::get(format!("http://{silent}/"))
        .body(Body::empty())
        .unwrap();
    let outcome = tokio::time::timeout(Duration::from_millis(300), client.send(request)).await;
    assert!(outcome.is_err(), "the silent server never answers");

    let server = http_server(|_, _, _| (200, b"still works".to_vec()));
    let request = http::Request::get(format!("http://{server}/"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        client.send(request).await.unwrap().into_body().bytes().await.unwrap(),
        "still works"
    );
}

#[tokio::test]
async fn connection_refused_is_a_request_error() {
    if !common::library() {
        return;
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let request = http::Request::get(format!("http://127.0.0.1:{port}/"))
        .body(Body::empty())
        .unwrap();
    match client().send(request).await {
        Err(Error::Request(error)) => {
            assert_eq!(error.internal_error_code(), NetError::CONNECTION_REFUSED);
            assert_eq!(
                std::io::Error::from(Error::Request(error)).kind(),
                std::io::ErrorKind::ConnectionRefused
            );
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_body_needs_no_content_type() {
    if !common::library() {
        return;
    }
    // Cronet's Java API refuses an upload without `Content-Type`; the native one sends it.
    let server = echo_server();
    let request = http::Request::post(format!("http://{server}/"))
        .body(Body::from("no type"))
        .unwrap();
    assert_eq!(
        client().send(request).await.unwrap().into_body().bytes().await.unwrap(),
        "-|-|no type"
    );
}
