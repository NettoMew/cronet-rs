//! URL requests against a local HTTP/1.1 server.

mod common;

use std::{
    io::Cursor,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use cronet::{
    Buffer, ErrorRef, Executor, FinishedReason, RequestFinishedListener, RequestStatus, UrlRequest, UrlRequestCallback,
    UrlRequestParams, UrlResponseInfoRef,
};

/// What a request ended with.
#[derive(Debug)]
enum Outcome {
    Succeeded {
        status: i32,
        header: Option<String>,
        body: Vec<u8>,
    },
    Failed(String),
    Canceled,
}

/// Collects the body, then reports how the request ended.
struct Collect {
    body: Vec<u8>,
    status: i32,
    header: Option<String>,
    done: mpsc::Sender<Outcome>,
}

impl Collect {
    fn new() -> (Self, mpsc::Receiver<Outcome>) {
        let (done, outcome) = mpsc::channel();
        (
            Self {
                body: Vec::new(),
                status: 0,
                header: None,
                done,
            },
            outcome,
        )
    }
}

impl UrlRequestCallback for Collect {
    fn on_response_started(&mut self, request: &UrlRequest, info: &UrlResponseInfoRef) {
        self.status = info.status_code();
        self.header = info.header("x-test").map(Into::into);
        request.read(Buffer::zeroed(4)).unwrap();
    }

    fn on_read_completed(&mut self, request: &UrlRequest, _: &UrlResponseInfoRef, buffer: Buffer, bytes_read: u64) {
        self.body.extend_from_slice(&buffer[..bytes_read as usize]);
        request.read(buffer).unwrap();
    }

    fn on_succeeded(&mut self, _: &UrlRequest, _: &UrlResponseInfoRef) {
        let body = std::mem::take(&mut self.body);
        self.done
            .send(Outcome::Succeeded {
                status: self.status,
                header: self.header.take(),
                body,
            })
            .unwrap();
    }

    fn on_failed(&mut self, _: &UrlRequest, _: Option<&UrlResponseInfoRef>, error: &ErrorRef) {
        self.done.send(Outcome::Failed(error.to_string())).unwrap();
    }

    fn on_canceled(&mut self, _: &UrlRequest, _: Option<&UrlResponseInfoRef>) {
        self.done.send(Outcome::Canceled).unwrap();
    }
}

fn wait(outcome: &mpsc::Receiver<Outcome>) -> Outcome {
    outcome.recv_timeout(Duration::from_secs(10)).expect("the request ends")
}

#[test]
fn get_reads_the_whole_body() {
    if !common::library() {
        return;
    }
    let server = common::http_server(|method, path, _| (200, format!("{method} {path} answered").into_bytes()));
    let engine = common::engine();
    let (callback, outcome) = Collect::new();
    let url = format!("http://{server}/hello");
    let request = UrlRequest::new(&engine, &url, UrlRequestParams::new(), callback, &Executor::thread()).unwrap();
    request.start().unwrap();
    match wait(&outcome) {
        Outcome::Succeeded { status, header, body } => {
            assert_eq!(status, 200);
            assert_eq!(header.as_deref(), Some("yes"));
            assert_eq!(body, b"GET /hello answered");
        }
        other => panic!("{other:?}"),
    }
    assert!(request.is_done());
    assert_eq!(
        request.start(),
        Err(cronet::ApiError::IllegalStateRequestAlreadyStarted)
    );
}

#[test]
fn post_uploads_the_body_and_reports_when_finished() {
    if !common::library() {
        return;
    }
    let server = common::http_server(|method, _, body| (201, [method.as_bytes(), b":", body].concat()));
    let engine = common::engine();
    let executor = Executor::thread();

    let (finished_sender, finished) = mpsc::channel();
    let finished_sender = Mutex::new(finished_sender);
    let listener = RequestFinishedListener::new(move |info, response, error| {
        let sent = (
            info.finished_reason(),
            info.annotations().collect::<Vec<_>>(),
            response.map(|r| r.status_code()),
        );
        assert!(error.is_none());
        assert!(info.metrics().and_then(|metrics| metrics.request_start()).is_some());
        finished_sender.lock().unwrap().send(sent).unwrap();
    });

    let mut params = UrlRequestParams::new();
    params
        .set_method("POST")
        .add_header("Content-Type", "text/plain")
        .add_annotation(42);
    params.set_upload(Cursor::new(b"uploaded body".to_vec()), &executor);
    params.set_request_finished_listener(&listener, &executor);

    let (callback, outcome) = Collect::new();
    let request = UrlRequest::new(&engine, &format!("http://{server}/"), params, callback, &executor).unwrap();
    request.start().unwrap();
    match wait(&outcome) {
        Outcome::Succeeded { status, body, .. } => {
            assert_eq!(status, 201);
            assert_eq!(body, b"POST:uploaded body");
        }
        other => panic!("{other:?}"),
    }
    let (reason, annotations, status) = finished.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(reason, FinishedReason::Succeeded);
    assert_eq!(annotations, [42]);
    assert_eq!(status, Some(201));
}

#[test]
fn connection_refused_fails_with_net_error() {
    if !common::library() {
        return;
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let engine = common::engine();
    let (callback, outcome) = Collect::new();
    let url = format!("http://127.0.0.1:{port}/");
    let request = UrlRequest::new(&engine, &url, UrlRequestParams::new(), callback, &Executor::thread()).unwrap();
    request.start().unwrap();
    match wait(&outcome) {
        Outcome::Failed(message) => assert!(message.contains("CONNECTION_REFUSED"), "{message}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn cancel_and_status() {
    if !common::library() {
        return;
    }
    // A server that never answers.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", silent.local_addr().unwrap());
    let engine = common::engine();
    let (callback, outcome) = Collect::new();
    let request = UrlRequest::new(&engine, &url, UrlRequestParams::new(), callback, &Executor::thread()).unwrap();
    request.start().unwrap();

    let (status_sender, status) = mpsc::channel();
    let status_sender = Arc::new(Mutex::new(status_sender));
    request.status(move |status| status_sender.lock().unwrap().send(status).unwrap());
    let reported = status.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_ne!(reported, RequestStatus::Invalid);

    request.cancel();
    assert!(matches!(wait(&outcome), Outcome::Canceled));
    drop(silent);
}
