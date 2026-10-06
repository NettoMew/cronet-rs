//! Bidirectional streams against a local HTTP/2 server over TLS, trusted
//! through the engine's own root certificates.

#![cfg(feature = "tokio")]

mod common;

use std::{
    net::{SocketAddr, TcpStream as StdTcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use cronet::{
    BidirectionalConn, BidirectionalStream, Buffer, ConnOptions, Engine, EngineParams, ErrorRef, Executor, Headers,
    NetError, Socket, Stream, StreamCallback, StreamError, StreamPriority, UrlRequest, UrlRequestCallback,
    UrlRequestParams, UrlResponseInfoRef,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        crypto::ring,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};

const NO_HEADERS: &[(&str, &str)] = &[];

/// A CA, and a certificate for 127.0.0.1 it signed, valid for a few days
/// around now so that no validity limit gets in the way.
fn certificates() -> (String, ServerConfig) {
    let now = time::OffsetDateTime::now_utc();
    let validity = |params: &mut CertificateParams| {
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(7);
    };

    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.distinguished_name.push(DnType::CommonName, "cronet-rs test CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    validity(&mut ca);
    let ca_certificate = ca.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca, ca_key);

    let server_key = KeyPair::generate().unwrap();
    let mut server = CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
    server.distinguished_name.push(DnType::CommonName, "127.0.0.1");
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    validity(&mut server);
    let server_certificate = server.signed_by(&server_key, &issuer).unwrap();

    let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_certificate.der().clone(), ca_certificate.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    (ca_certificate.pem(), config)
}

/// An HTTP/2 server: `/hello` answers `hello` and a trailer; anything else
/// echoes the request body back as it arrives, and ends with it.
async fn h2_server(config: ServerConfig) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let Ok(mut connection) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    tokio::spawn(async move {
                        let path = request.uri().path().to_owned();
                        let mut body = request.into_body();
                        let Ok(mut send) = respond.send_response(http::Response::new(()), false) else {
                            return;
                        };
                        if path == "/hello" {
                            let _ = send.send_data(Bytes::from_static(b"hello"), false);
                            let mut trailers = http::HeaderMap::new();
                            trailers.insert("x-trailer", http::HeaderValue::from_static("done"));
                            let _ = send.send_trailers(trailers);
                            return;
                        }
                        while let Some(Ok(chunk)) = body.data().await {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            if send.send_data(chunk, false).is_err() {
                                return;
                            }
                        }
                        let _ = send.send_data(Bytes::new(), true);
                    });
                }
            });
        }
    });
    address
}

/// An engine that trusts the test CA, and the address of a server it trusts.
async fn setup() -> (Engine, SocketAddr) {
    let (ca, config) = certificates();
    let address = h2_server(config).await;
    let mut params = EngineParams::new();
    params.set_enable_quic(false).set_enable_http2(true);
    let engine = Engine::builder()
        .trusted_root_certificates(&ca)
        .unwrap()
        .start(&params)
        .unwrap();
    (engine, address)
}

#[derive(Debug, PartialEq)]
enum Event {
    Headers(Option<u16>, String),
    Data(Vec<u8>),
    Trailers(Option<String>),
    Succeeded,
    Failed(NetError),
    Canceled,
}

/// Reads everything, and reports each event.
struct Record(mpsc::Sender<Event>);

impl StreamCallback for Record {
    fn on_response_headers_received(&mut self, stream: &Stream, headers: &Headers<'_>, protocol: &str) {
        self.0
            .send(Event::Headers(headers.status(), protocol.to_owned()))
            .unwrap();
        stream.read(BytesMut::with_capacity(1024)).unwrap();
    }

    fn on_read_completed(&mut self, stream: &Stream, buffer: BytesMut, bytes_read: usize) {
        if bytes_read > 0 {
            self.0.send(Event::Data(buffer.to_vec())).unwrap();
        }
        let _ = stream.read(BytesMut::with_capacity(1024));
    }

    fn on_response_trailers_received(&mut self, _: &Stream, trailers: &Headers<'_>) {
        self.0
            .send(Event::Trailers(trailers.get("x-trailer").map(Into::into)))
            .unwrap();
    }

    fn on_succeeded(&mut self, _: &Stream) {
        self.0.send(Event::Succeeded).unwrap();
    }

    fn on_failed(&mut self, _: &Stream, error: NetError) {
        self.0.send(Event::Failed(error)).unwrap();
    }

    fn on_canceled(&mut self, _: &Stream) {
        self.0.send(Event::Canceled).unwrap();
    }
}

fn next(events: &mpsc::Receiver<Event>) -> Event {
    events
        .recv_timeout(Duration::from_secs(10))
        .expect("the stream reports")
}

#[tokio::test(flavor = "multi_thread")]
async fn callbacks_see_headers_data_trailers_and_the_end() {
    if !common::library() {
        return;
    }
    let (engine, address) = setup().await;
    let (sender, events) = mpsc::channel();
    let stream = BidirectionalStream::new(&engine, Record(sender));
    let url = format!("https://{address}/hello");
    stream
        .start("GET", &url, &[("x-test", "1")], StreamPriority::Medium, true)
        .unwrap();
    let events = tokio::task::spawn_blocking(move || {
        let mut seen = vec![next(&events)];
        while !matches!(seen.last(), Some(Event::Succeeded | Event::Failed(_) | Event::Canceled)) {
            seen.push(next(&events));
        }
        seen
    })
    .await
    .unwrap();
    assert_eq!(events.first(), Some(&Event::Headers(Some(200), "h2".to_owned())));
    assert!(events.contains(&Event::Data(b"hello".to_vec())), "{events:?}");
    assert!(events.contains(&Event::Trailers(Some("done".to_owned()))), "{events:?}");
    assert_eq!(events.last(), Some(&Event::Succeeded));
    assert_eq!(
        stream.start("GET", &url, NO_HEADERS, StreamPriority::Medium, true),
        Err(StreamError::Closed)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn conn_echoes_and_half_closes() {
    if !common::library() {
        return;
    }
    let (engine, address) = setup().await;
    let options = ConnOptions {
        read_wait_headers: true,
        write_wait_headers: false,
    };
    let mut conn = BidirectionalConn::new(&engine, options);
    conn.start(
        "POST",
        &format!("https://{address}/echo"),
        NO_HEADERS,
        StreamPriority::Medium,
        false,
    )
    .unwrap();

    conn.write_all(b"ping").await.unwrap();
    conn.flush().await.unwrap();
    let headers = conn.headers().await.unwrap();
    assert_eq!(headers.status(), Some(200));
    assert_eq!(headers.negotiated_protocol, "h2");
    let mut echoed = [0; 4];
    conn.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");

    // Megabytes each way at once, then the request side ends and the
    // response follows it to the end.
    let large: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let expected = large.clone();
    let (mut reader, mut writer) = tokio::io::split(conn);
    let write = tokio::spawn(async move {
        writer.write_all(&large).await.unwrap();
        writer.shutdown().await.unwrap();
    });
    let mut received = Vec::new();
    reader.read_to_end(&mut received).await.unwrap();
    write.await.unwrap();
    assert_eq!(received.len(), expected.len());
    assert!(received == expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_a_started_stream_cancels_it() {
    if !common::library() {
        return;
    }
    let (engine, address) = setup().await;
    let (sender, events) = mpsc::channel();
    let stream = BidirectionalStream::new(&engine, Record(sender));
    let url = format!("https://{address}/echo");
    stream
        .start("POST", &url, NO_HEADERS, StreamPriority::Medium, false)
        .unwrap();
    let (first, events) = tokio::task::spawn_blocking(move || (next(&events), events))
        .await
        .unwrap();
    assert!(matches!(first, Event::Headers(Some(200), _)), "{first:?}");

    drop(stream);
    let end = tokio::task::spawn_blocking(move || {
        loop {
            match next(&events) {
                Event::Data(_) => continue,
                end => return end,
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(end, Event::Canceled);
    // With the stream gone, the engine shuts down cleanly.
    drop(engine);
}

/// Reports the status of the response, then cancels.
struct Status(mpsc::Sender<i32>);

impl UrlRequestCallback for Status {
    fn on_response_started(&mut self, request: &UrlRequest, info: &UrlResponseInfoRef) {
        self.0.send(info.status_code()).unwrap();
        request.cancel();
    }

    fn on_read_completed(&mut self, _: &UrlRequest, _: &UrlResponseInfoRef, _: Buffer, _: u64) {}

    fn on_succeeded(&mut self, _: &UrlRequest, _: &UrlResponseInfoRef) {}

    fn on_failed(&mut self, _: &UrlRequest, _: Option<&UrlResponseInfoRef>, error: &ErrorRef) {
        panic!("{error}");
    }

    fn on_canceled(&mut self, _: &UrlRequest, _: Option<&UrlResponseInfoRef>) {}
}

#[test]
fn a_custom_dialer_makes_the_connections() {
    if !common::library() {
        return;
    }
    let server = common::http_server(|_, _, _| (200, b"dialed".to_vec()));
    let dials = Arc::new(AtomicUsize::new(0));
    let counted = dials.clone();
    let engine = Engine::builder()
        .dialer(move |address| {
            counted.fetch_add(1, Ordering::SeqCst);
            StdTcpStream::connect(address)
                .map(Socket::from)
                .map_err(|error| NetError::from_io_error(&error))
        })
        .start(&EngineParams::new())
        .unwrap();

    let (status, statuses) = mpsc::channel();
    let url = format!("http://{server}/");
    let request = UrlRequest::new(
        &engine,
        &url,
        UrlRequestParams::new(),
        Status(status),
        &Executor::thread(),
    )
    .unwrap();
    request.start().unwrap();
    assert_eq!(statuses.recv_timeout(Duration::from_secs(10)).unwrap(), 200);
    assert_eq!(dials.load(Ordering::SeqCst), 1);
}
