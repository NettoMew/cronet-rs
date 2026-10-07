//! What every runtime test needs: the library, an engine, and small servers.

#![allow(dead_code)]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
};

/// Whether libcronet is available. Linked, it always is, `dynamic` or not;
/// loaded at run time, it is when `CRONET_LIBRARY` names it, and the test is
/// skipped otherwise.
pub(crate) fn library() -> bool {
    #[cfg(feature = "dynamic")]
    if !cronet::sys::is_loaded() {
        let Some(path) = std::env::var_os("CRONET_LIBRARY") else {
            eprintln!("CRONET_LIBRARY is not set; skipping");
            return false;
        };
        cronet::load_library(path).expect("libcronet loads");
    }
    true
}

/// An engine with HTTP/2 and no QUIC, for local servers.
pub(crate) fn engine() -> cronet::Engine {
    let mut params = cronet::EngineParams::new();
    params
        .set_user_agent("cronet-rs tests")
        .set_enable_quic(false)
        .set_enable_http2(true);
    cronet::Engine::start(&params).expect("engine starts")
}

/// A request the test server received.
#[derive(Debug, Clone, Default)]
pub(crate) struct TestRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: Vec<(String, String)>,
    /// The body, with chunked transfer coding removed.
    pub(crate) body: Vec<u8>,
}

impl TestRequest {
    /// The first value of `name`, ignoring ASCII case.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// What the test server answers.
#[derive(Debug, Clone, Default)]
pub(crate) struct TestResponse {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

type Respond = dyn Fn(&TestRequest) -> TestResponse + Send + Sync;

/// An HTTP/1.1 server answering each connection's request with `respond`,
/// which sees the method, path and body. Every response carries
/// `X-Test: yes`.
pub(crate) fn http_server(respond: impl Fn(&str, &str, &[u8]) -> (u16, Vec<u8>) + Send + Sync + 'static) -> SocketAddr {
    http_server_with(move |request| {
        let (status, body) = respond(&request.method, &request.path, &request.body);
        TestResponse {
            status,
            headers: Vec::new(),
            body,
        }
    })
}

/// An HTTP/1.1 server answering each request with `respond`, which sees it
/// whole and picks the status, the headers (after `X-Test: yes`) and the body.
pub(crate) fn http_server_with(respond: impl Fn(&TestRequest) -> TestResponse + Send + Sync + 'static) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let respond: Arc<Respond> = Arc::new(respond);
    thread::spawn(move || {
        for connection in listener.incoming() {
            let Ok(connection) = connection else { return };
            let respond = respond.clone();
            thread::spawn(move || serve(connection, &*respond));
        }
    });
    address
}

/// A server that accepts connections and never answers.
pub(crate) fn silent_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let mut connections = Vec::new();
        for connection in listener.incoming() {
            let Ok(connection) = connection else { return };
            connections.push(connection);
        }
    });
    address
}

fn serve(connection: TcpStream, respond: &Respond) {
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let mut writer = connection;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = line.split_whitespace();
        let mut request = TestRequest {
            method: parts.next().unwrap_or("").to_owned(),
            path: parts.next().unwrap_or("").to_owned(),
            ..TestRequest::default()
        };
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                request.headers.push((name.trim().to_owned(), value.trim().to_owned()));
            }
        }
        if request
            .header("transfer-encoding")
            .is_some_and(|coding| coding.eq_ignore_ascii_case("chunked"))
        {
            request.body = read_chunked(&mut reader);
        } else {
            let length = request
                .header("content-length")
                .map_or(0, |length| length.parse().unwrap());
            request.body = vec![0; length];
            reader.read_exact(&mut request.body).unwrap();
        }
        let response = respond(&request);
        let mut head = format!(
            "HTTP/1.1 {} X\r\nContent-Length: {}\r\nX-Test: yes\r\n",
            response.status,
            response.body.len()
        );
        for (name, value) in &response.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        if writer
            .write_all(head.as_bytes())
            .and_then(|()| writer.write_all(&response.body))
            .is_err()
        {
            return;
        }
    }
}

fn read_chunked(reader: &mut impl BufRead) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let mut size = String::new();
        reader.read_line(&mut size).unwrap();
        let size = usize::from_str_radix(size.trim().split(';').next().unwrap(), 16).unwrap();
        let mut chunk = vec![0; size + 2];
        reader.read_exact(&mut chunk).unwrap();
        if size == 0 {
            return body;
        }
        body.extend_from_slice(&chunk[..size]);
    }
}
