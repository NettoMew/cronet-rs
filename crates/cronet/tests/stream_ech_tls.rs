//! In-memory stream dialers, synthetic ECH endpoints, unified TLS verification,
//! and standalone `tls::Client` streams — all without touching OS sockets or DNS.

#![cfg(feature = "tokio")]

mod common;

use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use cronet::{
    BidirectionalConn, ConnOptions, Endpoint, Engine, EngineParams, Lower, NetError, StreamPriority, Target, tls,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PublicKeyData,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        RootCertStore, ServerConfig,
        crypto::ring,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        server::WebPkiClientVerifier,
    },
};

const NO_HEADERS: &[(&str, &str)] = &[];

/// Pure-Rust SHA-256 (FIPS 180-4) for computing certificate and SPKI pin digests
/// in tests without pulling in extra dev-dependencies.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (s, delta) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(delta);
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

struct TestPki {
    ca_pem: String,
    server_cert_sha256: [u8; 32],
    server_spki_sha256: [u8; 32],
    server_config: ServerConfig,
    mtls_server_config: ServerConfig,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

fn generate_pki(san_name: &str) -> TestPki {
    let now = time::OffsetDateTime::now_utc();
    let validity = |params: &mut CertificateParams| {
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(7);
    };

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "cronet-rs test root CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    validity(&mut ca_params);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();
    let ca_der = ca_cert.der().clone();
    let issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(vec![san_name.to_owned()]).unwrap();
    server_params.distinguished_name.push(DnType::CommonName, san_name);
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    validity(&mut server_params);
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
    let server_cert_sha256 = sha256(server_cert.der());
    let server_spki_sha256 = sha256(&server_key.subject_public_key_info());

    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(vec!["client.example".to_owned()]).unwrap();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "client.example");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    validity(&mut client_params);
    let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

    let provider = Arc::new(ring::default_provider());
    let mut server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_cert.der().clone(), ca_der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let mut client_roots = RootCertStore::empty();
    client_roots.add(ca_der.clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider.clone())
        .build()
        .unwrap();
    let mut mtls_server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_cert.der().clone(), ca_der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .unwrap();
    mtls_server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    TestPki {
        ca_pem,
        server_cert_sha256,
        server_spki_sha256,
        server_config,
        mtls_server_config,
        client_cert_pem: client_cert.pem().into_bytes(),
        client_key_pem: client_key.serialize_pem().into_bytes(),
    }
}

/// Spawns an HTTP/2 echo server over a single `DuplexStream`.
fn serve_h2_stream(server_io: DuplexStream, acceptor: TlsAcceptor) {
    tokio::spawn(async move {
        let Ok(tls) = acceptor.accept(server_io).await else {
            return;
        };
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
                    let _ = send.send_data(Bytes::from_static(b"hello"), true);
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

/// Spawns a raw TLS echo server over a single stream.
fn serve_tls_echo<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(server_io: S, acceptor: TlsAcceptor) {
    tokio::spawn(async move {
        let Ok(tls) = acceptor.accept(server_io).await else {
            return;
        };
        let (mut reader, mut writer) = tokio::io::split(tls);
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if writer.write_all(&buf[..n]).await.is_err() || writer.flush().await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = writer.shutdown().await;
    });
}

/// Builds a wire-encoded RFC 9849 `ECHConfigList` (`0xfe0d`, X25519 +
/// HKDF-SHA256 + AES-128-GCM) for `public_name`.
fn build_ech_config_list(config_id: u8, public_name: &str) -> Vec<u8> {
    let mut public_key = [0u8; 32];
    public_key[0] = 9; // Standard Curve25519 basepoint u = 9.
    let name_bytes = public_name.as_bytes();

    let mut contents = Vec::new();
    contents.push(config_id);
    contents.extend_from_slice(&0x0020u16.to_be_bytes()); // DHKEM(X25519, HKDF-SHA256)
    contents.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    contents.extend_from_slice(&public_key);
    // cipher_suites: 4 bytes -> [HKDF-SHA256 (0x0001), AES-128-GCM (0x0001)]
    contents.extend_from_slice(&4u16.to_be_bytes());
    contents.extend_from_slice(&0x0001u16.to_be_bytes());
    contents.extend_from_slice(&0x0001u16.to_be_bytes());
    contents.push(0); // maximum_name_length
    contents.push(name_bytes.len() as u8);
    contents.extend_from_slice(name_bytes);
    contents.extend_from_slice(&0u16.to_be_bytes()); // extensions: empty

    let mut ech_config = Vec::new();
    ech_config.extend_from_slice(&0xfe0du16.to_be_bytes());
    ech_config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    ech_config.extend_from_slice(&contents);

    let mut list = Vec::new();
    list.extend_from_slice(&(ech_config.len() as u16).to_be_bytes());
    list.extend_from_slice(&ech_config);
    list
}

/// Structural layout extracted from a TLS 1.3 ClientHello record, excluding
/// per-connection random and ephemeral key bytes.
#[derive(Debug, PartialEq, Eq)]
struct ClientHelloLayout {
    legacy_version: u16,
    cipher_suites: Vec<u16>,
    compression_methods: Vec<u8>,
    extensions: Vec<(u16, Option<usize>)>,
    sni: Option<String>,
}

fn is_grease(val: u16) -> bool {
    (val & 0x0f0f) == 0x0a0a && (val >> 8) == (val & 0xff)
}

fn parse_client_hello_layout(record: &[u8]) -> ClientHelloLayout {
    assert!(record.len() > 9 && record[0] == 0x16, "expected TLS Handshake record");
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let hs = &record[5..5 + record_len];
    assert_eq!(hs[0], 0x01, "expected ClientHello");
    let ch_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    let body = &hs[4..4 + ch_len];

    let legacy_version = u16::from_be_bytes([body[0], body[1]]);
    let mut pos = 2 + 32; // version + random
    let session_id_len = body[pos] as usize;
    pos += 1 + session_id_len;

    let cs_bytes = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let mut cipher_suites = Vec::new();
    for chunk in body[pos..pos + cs_bytes].as_chunks::<2>().0 {
        let suite = u16::from_be_bytes(*chunk);
        cipher_suites.push(if is_grease(suite) { 0x0a0a } else { suite });
    }
    pos += cs_bytes;

    let comp_len = body[pos] as usize;
    pos += 1;
    let compression_methods = body[pos..pos + comp_len].to_vec();
    pos += comp_len;

    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let end = pos + ext_total;
    let mut extensions = Vec::new();
    let mut sni = None;
    while pos < end {
        let ext_id = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        let payload = &body[pos..pos + ext_len];
        pos += ext_len;

        if ext_id == 0x0000 && payload.len() >= 5 {
            let name_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
            sni = Some(String::from_utf8_lossy(&payload[5..5 + name_len]).into_owned());
        }
        let norm_id = if is_grease(ext_id) { 0x0a0a } else { ext_id };
        // Padding (21) and GREASE vary in length by randomizer; ECH (0xfe0d)
        // and structural extensions have deterministic lengths for fixed inputs.
        let deterministic_len = (!matches!(norm_id, 0x0a0a | 21)).then_some(ext_len);
        extensions.push((norm_id, deterministic_len));
    }
    // Chromium permutes non-GREASE/non-padding extensions randomly unless
    // canonicalized by sorting; sort extensions to compare exact feature sets
    // and payload sizes deterministically.
    extensions.sort_unstable();

    ClientHelloLayout {
        legacy_version,
        cipher_suites,
        compression_methods,
        extensions,
        sni,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_dialer_multiplexes_h2_over_duplex_and_reports_connection_id() {
    if !common::library() {
        return;
    }
    let pki = generate_pki("origin.example");
    let acceptor = TlsAcceptor::from(Arc::new(pki.server_config));
    let targets: Arc<Mutex<Vec<Target>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = targets.clone();

    let mut params = EngineParams::new();
    params.set_enable_quic(false).set_enable_http2(true);
    let engine = Engine::builder()
        .tls_config(&tls::Config {
            root_certificates_pem: Some(pki.ca_pem),
            ..tls::Config::default()
        })
        .unwrap()
        .endpoint(
            "origin.example",
            Endpoint {
                alpn: vec!["h2".into()],
                ..Endpoint::default()
            },
        )
        .stream_dialer(move |target| -> io::Result<Box<dyn Lower>> {
            recorded.lock().unwrap().push(target);
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            serve_h2_stream(server_io, acceptor.clone());
            Ok(Box::new(client_io))
        })
        .start(&params)
        .unwrap();

    // Open the first stream to establish the HTTP/2 session while keeping it
    // open, then multiplex 4 additional concurrent streams over the same
    // underlying Lower connection.
    let mut first = BidirectionalConn::new(
        &engine,
        ConnOptions {
            read_wait_headers: true,
            write_wait_headers: false,
        },
    );
    first
        .start(
            "POST",
            "https://origin.example/echo",
            NO_HEADERS,
            StreamPriority::Medium,
            false,
        )
        .unwrap();
    let first_headers = first.headers().await.unwrap();
    assert_eq!(first_headers.status(), Some(200));
    assert_eq!(first_headers.negotiated_protocol, "h2");
    let first_id = first.connection_id();

    let mut handles = Vec::new();
    for idx in 1..5usize {
        let engine = engine.clone();
        handles.push(tokio::spawn(async move {
            let mut conn = BidirectionalConn::new(
                &engine,
                ConnOptions {
                    read_wait_headers: true,
                    write_wait_headers: false,
                },
            );
            conn.start(
                "POST",
                "https://origin.example/echo",
                NO_HEADERS,
                StreamPriority::Medium,
                false,
            )
            .unwrap();
            let msg = format!("stream-{idx}-payload").into_bytes();
            conn.write_all(&msg).await.unwrap();
            conn.shutdown().await.unwrap();
            let headers = conn.headers().await.unwrap();
            assert_eq!(headers.status(), Some(200));
            assert_eq!(headers.negotiated_protocol, "h2");
            let active_id = conn.connection_id();
            let mut echoed = Vec::new();
            conn.read_to_end(&mut echoed).await.unwrap();
            assert_eq!(echoed, msg);
            let after_id = conn.connection_id();
            assert_eq!(active_id, after_id);
            active_id
        }));
    }

    first.write_all(b"stream-0-payload").await.unwrap();
    first.shutdown().await.unwrap();
    let mut first_echo = Vec::new();
    first.read_to_end(&mut first_echo).await.unwrap();
    assert_eq!(first_echo, b"stream-0-payload");

    let mut conn_ids = vec![first_id];
    for handle in handles {
        conn_ids.push(handle.await.unwrap());
    }
    let dialed = targets.lock().unwrap().clone();
    assert_eq!(dialed.len(), 1, "all 5 H2 streams should multiplex onto 1 Lower stream");
    assert_eq!(dialed[0].host, "origin.example");
    assert_eq!(dialed[0].port, 443);
    assert_ne!(dialed[0].connection_id, 0);
    for id in conn_ids {
        assert_eq!(id, dialed[0].connection_id);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn async_stream_dialer_awaits_connect_and_propagates_dial_errors() {
    if !common::library() {
        return;
    }
    let pki = generate_pki("async.example");
    let acceptor = TlsAcceptor::from(Arc::new(pki.server_config));

    let mut params = EngineParams::new();
    params.set_enable_quic(false).set_enable_http2(true);
    let engine = Engine::builder()
        .tls_config(&tls::Config {
            root_certificates_pem: Some(pki.ca_pem),
            ..tls::Config::default()
        })
        .unwrap()
        .async_stream_dialer(move |target| {
            let acceptor = acceptor.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(15)).await;
                if target.host == "refused.example" {
                    return Err(NetError::CONNECTION_REFUSED.into());
                }
                let (client_io, server_io) = tokio::io::duplex(32 * 1024);
                serve_h2_stream(server_io, acceptor);
                Ok(client_io)
            }
        })
        .start(&params)
        .unwrap();

    let mut ok_conn = BidirectionalConn::new(&engine, ConnOptions::default());
    ok_conn
        .start(
            "GET",
            "https://async.example/hello",
            NO_HEADERS,
            StreamPriority::Medium,
            true,
        )
        .unwrap();
    assert_eq!(ok_conn.headers().await.unwrap().status(), Some(200));
    let mut body = Vec::new();
    ok_conn.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"hello");

    let bad_conn = BidirectionalConn::new(&engine, ConnOptions::default());
    bad_conn
        .start(
            "GET",
            "https://refused.example/hello",
            NO_HEADERS,
            StreamPriority::Medium,
            true,
        )
        .unwrap();
    let err = bad_conn.headers().await.unwrap_err();
    assert_eq!(NetError::from_io_error(&err), NetError::CONNECTION_REFUSED);
}

#[tokio::test(flavor = "multi_thread")]
async fn strict_endpoint_ech_sends_extension_and_never_retries_in_cleartext() {
    if !common::library() {
        return;
    }
    // Trusted cover server valid for "cover.example" that does not negotiate ECH.
    let pki = generate_pki("cover.example");
    let acceptor = TlsAcceptor::from(Arc::new(pki.server_config));
    let ech_list = build_ech_config_list(7, "cover.example");

    let dials = Arc::new(AtomicUsize::new(0));
    let dials_clone = dials.clone();
    let captured_hello: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = captured_hello.clone();

    let mut params = EngineParams::new();
    params.set_enable_quic(false).set_enable_http2(true);
    let engine = Engine::builder()
        .tls_config(&tls::Config {
            root_certificates_pem: Some(pki.ca_pem),
            ..tls::Config::default()
        })
        .unwrap()
        .endpoint(
            "inner.example",
            Endpoint {
                ech: ech_list,
                alpn: vec!["h2".into()],
                strict: true,
            },
        )
        .stream_dialer(move |_target| -> io::Result<Box<dyn Lower>> {
            dials_clone.fetch_add(1, Ordering::SeqCst);
            let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
            let acceptor = acceptor.clone();
            let store = captured_clone.clone();
            tokio::spawn(async move {
                // Peek/forward the first TLS record so we inspect the exact
                // ClientHello on the wire while letting rustls complete the
                // cover server handshake without ECH acceptance.
                let (mut proxy_side, rustls_side) = tokio::io::duplex(64 * 1024);
                serve_h2_stream(rustls_side, acceptor);
                let mut first = vec![0u8; 4096];
                let Ok(n) = server_io.read(&mut first).await else {
                    return;
                };
                if n > 0 {
                    *store.lock().unwrap() = first[..n].to_vec();
                    if proxy_side.write_all(&first[..n]).await.is_err() {
                        return;
                    }
                }
                let _ = tokio::io::copy_bidirectional(&mut server_io, &mut proxy_side).await;
            });
            Ok(Box::new(client_io))
        })
        .start(&params)
        .unwrap();

    let conn = BidirectionalConn::new(&engine, ConnOptions::default());
    conn.start(
        "GET",
        "https://inner.example/hello",
        NO_HEADERS,
        StreamPriority::Medium,
        true,
    )
    .unwrap();
    let err = conn.headers().await.unwrap_err();
    assert_eq!(NetError::from_io_error(&err), NetError::ECH_NOT_NEGOTIATED);
    assert_eq!(
        dials.load(Ordering::SeqCst),
        1,
        "strict ECH must fail after 1 attempt without retrying in cleartext"
    );

    let hello = captured_hello.lock().unwrap().clone();
    assert!(
        !hello.windows(b"inner.example".len()).any(|w| w == b"inner.example"),
        "inner_sni must never appear in cleartext on the wire"
    );
    let layout = parse_client_hello_layout(&hello);
    assert_eq!(layout.sni.as_deref(), Some("cover.example"));
    assert!(
        layout.extensions.iter().any(|(id, _)| *id == 0xfe0d),
        "ClientHello must include TLS ECH extension 0xfe0d"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn carrier_and_tls_client_emit_identical_client_hello_layout() {
    if !common::library() {
        return;
    }
    let ech_list = build_ech_config_list(11, "cover.example");

    // 1. Capture ClientHello from Engine (BidirectionalConn + Endpoint ECH).
    let carrier_hello: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let carrier_store = carrier_hello.clone();
    let mut params = EngineParams::new();
    params.set_enable_quic(false).set_enable_http2(true);
    let engine = Engine::builder()
        .endpoint(
            "inner.example",
            Endpoint {
                ech: ech_list.clone(),
                alpn: vec!["h2".into(), "http/1.1".into()],
                strict: true,
            },
        )
        .stream_dialer(move |_| -> io::Result<Box<dyn Lower>> {
            let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);
            let store = carrier_store.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                if let Ok(n) = server_io.read(&mut buf).await
                    && n > 0
                {
                    *store.lock().unwrap() = buf[..n].to_vec();
                }
            });
            Ok(Box::new(client_io))
        })
        .start(&params)
        .unwrap();

    let conn = BidirectionalConn::new(&engine, ConnOptions::default());
    conn.start(
        "GET",
        "https://inner.example/hello",
        NO_HEADERS,
        StreamPriority::Medium,
        true,
    )
    .unwrap();
    let _ = conn.headers().await;

    // 2. Capture ClientHello from standalone `tls::Client` with identical parameters.
    let tls_client = tls::Client::new(
        &engine,
        tls::Config {
            alpn: vec!["h2".into(), "http/1.1".into()],
            ech: ech_list,
            strict_ech: true,
            ..tls::Config::default()
        },
    )
    .unwrap();
    let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);
    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let n = server_io.read(&mut buf).await.unwrap();
        buf.truncate(n);
        buf
    });
    let _ = tls_client.connect("inner.example", client_io).await;
    let standalone_bytes = read_task.await.unwrap();
    let carrier_bytes = carrier_hello.lock().unwrap().clone();

    let carrier_layout = parse_client_hello_layout(&carrier_bytes);
    let standalone_layout = parse_client_hello_layout(&standalone_bytes);
    assert_eq!(carrier_layout, standalone_layout);
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_client_echoes_megabytes_and_verifies_roots_names_pins_and_mtls() {
    if !common::library() {
        return;
    }
    let engine = common::engine();
    let pki = generate_pki("cert.example");
    let other_pki = generate_pki("cert.example");

    // 1. Custom exclusive root + 2 MiB concurrent echo over a bounded 4 KiB
    //    duplex pipe (exercising backpressure and write-drain signaling).
    let client = tls::Client::new(
        &engine,
        tls::Config {
            root_certificates_pem: Some(pki.ca_pem.clone()),
            alpn: vec!["h2".into(), "http/1.1".into()],
            ..tls::Config::default()
        },
    )
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(pki.server_config));
    let (client_io, server_io) = tokio::io::duplex(4096);
    serve_tls_echo(server_io, acceptor.clone());
    let tls_stream = client.connect("cert.example", client_io).await.unwrap();
    assert_eq!(tls_stream.alpn(), Some("h2"));
    assert!(!tls_stream.ech_accepted());

    let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let (mut reader, mut writer) = tokio::io::split(tls_stream);
    let write_half = tokio::spawn(async move {
        writer.write_all(&payload).await.unwrap();
        writer.flush().await.unwrap();
        writer.shutdown().await.unwrap();
        writer
    });
    let mut received = vec![0u8; expected.len()];
    reader.read_exact(&mut received).await.unwrap();
    let _writer = write_half.await.unwrap();
    assert_eq!(received, expected);

    // 2. Exclusive root isolation: server signed by `other_pki` must be rejected.
    let other_acceptor = TlsAcceptor::from(Arc::new(other_pki.server_config));
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    serve_tls_echo(server_io, other_acceptor.clone());
    let err = client.connect("cert.example", client_io).await.unwrap_err();
    assert_eq!(NetError::from_io_error(&err), NetError::CERT_AUTHORITY_INVALID);

    // 3. `verify_name`: SNI is `sni.example`, certificate SAN is `cert.example`.
    let verify_name_client = tls::Client::new(
        &engine,
        tls::Config {
            root_certificates_pem: Some(pki.ca_pem.clone()),
            verify_name: Some("cert.example".into()),
            ..tls::Config::default()
        },
    )
    .unwrap();
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    serve_tls_echo(server_io, acceptor.clone());
    let mut renamed = verify_name_client.connect("sni.example", client_io).await.unwrap();
    renamed.write_all(b"ok").await.unwrap();
    renamed.flush().await.unwrap();
    let mut two = [0u8; 2];
    renamed.read_exact(&mut two).await.unwrap();
    assert_eq!(&two, b"ok");

    // 4. SHA-256 certificate pin and SPKI pin (without trusting the CA):
    //    matching SPKI pin succeeds, mismatched pin fails.
    let spki_pinned = tls::Client::new(
        &engine,
        tls::Config {
            spki_pins_sha256: vec![pki.server_spki_sha256],
            ..tls::Config::default()
        },
    )
    .unwrap();
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    serve_tls_echo(server_io, acceptor.clone());
    let _ = spki_pinned.connect("cert.example", client_io).await.unwrap();

    let cert_pinned = tls::Client::new(
        &engine,
        tls::Config {
            cert_pins_sha256: vec![pki.server_cert_sha256],
            ..tls::Config::default()
        },
    )
    .unwrap();
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    serve_tls_echo(server_io, acceptor);
    let _ = cert_pinned.connect("cert.example", client_io).await.unwrap();

    let wrong_pin = tls::Client::new(
        &engine,
        tls::Config {
            spki_pins_sha256: vec![[0xaa; 32]],
            ..tls::Config::default()
        },
    )
    .unwrap();
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    serve_tls_echo(server_io, other_acceptor);
    let err = wrong_pin.connect("cert.example", client_io).await.unwrap_err();
    assert_eq!(NetError::from_io_error(&err), NetError::CERT_AUTHORITY_INVALID);

    // 5. Mutual TLS (`client_identity`) on both `tls::Client` and `EngineBuilder::tls_config`.
    let mtls_acceptor = TlsAcceptor::from(Arc::new(pki.mtls_server_config));
    let mtls_tls_cfg = tls::Config {
        root_certificates_pem: Some(pki.ca_pem),
        client_identity: Some((pki.client_cert_pem, pki.client_key_pem)),
        ..tls::Config::default()
    };
    let mtls_client = tls::Client::new(&engine, &mtls_tls_cfg).unwrap();
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    serve_tls_echo(server_io, mtls_acceptor.clone());
    let mut mtls_stream = mtls_client.connect("cert.example", client_io).await.unwrap();
    mtls_stream.write_all(b"mtls").await.unwrap();
    mtls_stream.flush().await.unwrap();
    let mut four = [0u8; 4];
    mtls_stream.read_exact(&mut four).await.unwrap();
    assert_eq!(&four, b"mtls");

    let mut params = EngineParams::new();
    params.set_enable_quic(false).set_enable_http2(true);
    let mtls_engine = Engine::builder()
        .tls_config(&mtls_tls_cfg)
        .unwrap()
        .stream_dialer(move |_| -> io::Result<Box<dyn Lower>> {
            let (client_io, server_io) = tokio::io::duplex(32 * 1024);
            serve_h2_stream(server_io, mtls_acceptor.clone());
            Ok(Box::new(client_io))
        })
        .start(&params)
        .unwrap();
    let mut mtls_h2 = BidirectionalConn::new(&mtls_engine, ConnOptions::default());
    mtls_h2
        .start(
            "GET",
            "https://cert.example/hello",
            NO_HEADERS,
            StreamPriority::Medium,
            true,
        )
        .unwrap();
    assert_eq!(mtls_h2.headers().await.unwrap().status(), Some(200));
    let mut out = Vec::new();
    mtls_h2.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"hello");
}
