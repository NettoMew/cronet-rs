//! Integration tests for QUIC Brutal congestion control (`BRTL` /
//! `Engine::set_quic_send_rate`) and session-level HTTP/3 `connection_id`
//! against a self-contained local QUIC v1 + HTTP/3 server (`rustls::quic`).

#![cfg(feature = "tokio")]

mod common;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use cronet::{
    BidirectionalConn, ConnOptions, Endpoint, Engine, EngineParams, Lower, QuicHint, StreamPriority, Target, tls,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig, Side,
        crypto::ring,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        quic::{DirectionalKeys, KeyChange, Keys, ServerConnection, Version},
    },
};

const NO_HEADERS: &[(&str, &str)] = &[];
const QUIC_SESSION_ID_BIT: u64 = 1 << 63;

fn generate_certs(san_names: &[&str]) -> (String, ServerConfig, ServerConfig) {
    let now = time::OffsetDateTime::now_utc();
    let validity = |params: &mut CertificateParams| {
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(7);
    };

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "cronet-rs quic test root CA");
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
    let mut server_params =
        CertificateParams::new(san_names.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()).unwrap();
    server_params.distinguished_name.push(DnType::CommonName, san_names[0]);
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    validity(&mut server_params);
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

    let provider = Arc::new(ring::default_provider());
    let make_cfg = |alpn: &[u8]| {
        let mut cfg = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![server_cert.der().clone(), ca_der.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .unwrap();
        cfg.alpn_protocols = vec![alpn.to_vec()];
        cfg.max_early_data_size = 0;
        cfg.send_tls13_tickets = 0;
        cfg
    };

    (ca_pem, make_cfg(b"h3"), make_cfg(b"h2"))
}

// --- Minimal RFC 9000 / RFC 9001 / RFC 9114 QUIC v1 + HTTP/3 test server ---

fn push_varint(out: &mut Vec<u8>, v: u64) {
    if v < (1 << 6) {
        out.push(v as u8);
    } else if v < (1 << 14) {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < (1 << 30) {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    let len = 1usize << (first >> 6);
    if buf.len() < *pos + len {
        return None;
    }
    let mut val = u64::from(first & 0x3f);
    for &b in &buf[*pos + 1..*pos + len] {
        val = (val << 8) | u64::from(b);
    }
    *pos += len;
    Some(val)
}

fn encode_transport_params(odcid: &[u8], scid: &[u8]) -> Vec<u8> {
    fn bytes_param(out: &mut Vec<u8>, id: u64, data: &[u8]) {
        push_varint(out, id);
        push_varint(out, data.len() as u64);
        out.extend_from_slice(data);
    }
    fn int_param(out: &mut Vec<u8>, id: u64, val: u64) {
        let mut tmp = Vec::with_capacity(8);
        push_varint(&mut tmp, val);
        push_varint(out, id);
        push_varint(out, tmp.len() as u64);
        out.extend_from_slice(&tmp);
    }
    let mut out = Vec::new();
    bytes_param(&mut out, 0x00, odcid); // original_destination_connection_id
    int_param(&mut out, 0x01, 30_000); // max_idle_timeout (30s)
    int_param(&mut out, 0x03, 1472); // max_udp_payload_size
    int_param(&mut out, 0x04, 256 * 1024 * 1024); // initial_max_data
    int_param(&mut out, 0x05, 64 * 1024 * 1024); // initial_max_stream_data_bidi_local
    int_param(&mut out, 0x06, 64 * 1024 * 1024); // initial_max_stream_data_bidi_remote
    int_param(&mut out, 0x07, 4 * 1024 * 1024); // initial_max_stream_data_uni
    int_param(&mut out, 0x08, 128); // initial_max_streams_bidi
    int_param(&mut out, 0x09, 16); // initial_max_streams_uni
    int_param(&mut out, 0x0e, 4); // active_connection_id_limit
    bytes_param(&mut out, 0x0f, scid); // initial_source_connection_id
    out
}

fn decode_packet_number(largest_pn: Option<u64>, truncated: u64, pn_nbits: usize) -> u64 {
    let Some(largest) = largest_pn else {
        return truncated;
    };
    let expected = largest + 1;
    let win = 1u64 << pn_nbits;
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate + hwin <= expected && candidate < (1u64 << 62) - win {
        candidate + win
    } else if candidate > expected + hwin && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

#[derive(Default)]
struct Reassembler {
    next_offset: u64,
    chunks: BTreeMap<u64, Vec<u8>>,
    fin_offset: Option<u64>,
}

impl Reassembler {
    fn push(&mut self, offset: u64, data: &[u8], fin: bool) -> Vec<u8> {
        if fin {
            self.fin_offset = Some(offset + data.len() as u64);
        }
        if offset + (data.len() as u64) > self.next_offset {
            let trim = self.next_offset.saturating_sub(offset) as usize;
            let start = offset + trim as u64;
            let slice = &data[trim..];
            let entry = self.chunks.entry(start).or_default();
            if slice.len() > entry.len() {
                *entry = slice.to_vec();
            }
        }
        let mut ready = Vec::new();
        while let Some((&start, _)) = self.chunks.first_key_value() {
            if start > self.next_offset {
                break;
            }
            let chunk = self.chunks.pop_first().unwrap().1;
            let skip = (self.next_offset - start) as usize;
            if skip < chunk.len() {
                ready.extend_from_slice(&chunk[skip..]);
                self.next_offset += (chunk.len() - skip) as u64;
            }
        }
        ready
    }

    fn is_complete(&self) -> bool {
        self.fin_offset == Some(self.next_offset)
    }
}

#[derive(Default)]
struct PnSpace {
    received: BTreeSet<u64>,
    largest_rx: Option<u64>,
    next_tx: u64,
    crypto_rx: Reassembler,
    crypto_tx_offset: u64,
}

impl PnSpace {
    fn record_rx(&mut self, pn: u64) -> bool {
        let gap = self.largest_rx.is_some_and(|l| pn > l + 1 || pn < l);
        self.largest_rx = Some(self.largest_rx.map_or(pn, |l| l.max(pn)));
        self.received.insert(pn);
        while self.received.len() > 512 {
            self.received.pop_first();
        }
        gap
    }

    fn encode_ack(&self, out: &mut Vec<u8>) -> bool {
        let Some(&largest) = self.received.last() else {
            return false;
        };
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for &pn in self.received.iter().rev() {
            if let Some(last) = ranges.last_mut()
                && pn + 1 == last.0
            {
                last.0 = pn;
            } else {
                ranges.push((pn, pn));
                if ranges.len() == 24 {
                    break;
                }
            }
        }
        out.push(0x02); // ACK frame (no ECN)
        push_varint(out, largest);
        push_varint(out, 0); // ack_delay = 0
        push_varint(out, (ranges.len() - 1) as u64);
        push_varint(out, ranges[0].1 - ranges[0].0);
        for pair in ranges.windows(2) {
            let prev_smallest = pair[0].0;
            let (cur_smallest, cur_largest) = pair[1];
            push_varint(out, prev_smallest - cur_largest - 2);
            push_varint(out, cur_largest - cur_smallest);
        }
        true
    }
}

#[derive(Clone, Copy)]
enum H3Route {
    Echo,
    Sink,
}

#[derive(Default)]
struct H3StreamState {
    rx: Reassembler,
    buf: Vec<u8>,
    route: Option<H3Route>,
    headers_sent: bool,
    tx_offset: u64,
    uploaded_data_bytes: u64,
    finished: bool,
}

/// Decodes the `:path` pseudo-header from a request QPACK header block without
/// dynamic table entries (covers static indexed `/` and literal `:path`).
fn parse_qpack_path(block: &[u8]) -> String {
    if block.len() < 2 {
        return "/".into();
    }
    let mut pos = 2usize; // Skip Required Insert Count (0) + Delta Base (0).
    while pos < block.len() {
        let b = block[pos];
        if (b & 0x80) != 0 {
            // Indexed Field Line (1 T Index(6+))
            let static_table = (b & 0x40) != 0;
            let idx = read_prefixed_int(block, &mut pos, 6).unwrap_or(0);
            if static_table && idx == 1 {
                return "/".into();
            }
        } else if (b & 0x40) != 0 {
            // Literal Field Line With Name Reference (01 N T NameIndex(4+))
            let static_table = (b & 0x10) != 0;
            let name_idx = read_prefixed_int(block, &mut pos, 4).unwrap_or(0);
            let val = read_qpack_str(block, &mut pos).unwrap_or_default();
            if static_table && name_idx == 1 {
                return String::from_utf8_lossy(&val).into_owned();
            }
        } else if (b & 0x20) != 0 {
            // Literal Field Line With Literal Name (001 N H NameLen(3+))
            let name = read_qpack_str_with_prefix(block, &mut pos, 3).unwrap_or_default();
            let val = read_qpack_str(block, &mut pos).unwrap_or_default();
            if name.eq_ignore_ascii_case(b":path") {
                return String::from_utf8_lossy(&val).into_owned();
            }
        } else {
            break;
        }
    }
    "/".into()
}

fn read_prefixed_int(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> Option<u64> {
    let mask = (1u8 << prefix_bits) - 1;
    let first = *buf.get(*pos)? & mask;
    *pos += 1;
    let mut val = u64::from(first);
    if first < mask {
        return Some(val);
    }
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos)?;
        *pos += 1;
        val = val.checked_add(u64::from(b & 0x7f).checked_shl(shift)?)?;
        if (b & 0x80) == 0 {
            return Some(val);
        }
        shift += 7;
    }
}

fn read_qpack_str(buf: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    read_qpack_str_with_prefix(buf, pos, 7)
}

fn read_qpack_str_with_prefix(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> Option<Vec<u8>> {
    let huffman = (*buf.get(*pos)? & (1u8 << prefix_bits)) != 0;
    let len = read_prefixed_int(buf, pos, prefix_bits)? as usize;
    if buf.len() < *pos + len {
        return None;
    }
    let raw = &buf[*pos..*pos + len];
    *pos += len;
    if huffman {
        Some(hpack_huffman_decode(raw))
    } else {
        Some(raw.to_vec())
    }
}

/// RFC 7541 Appendix B Huffman decoder for QPACK header strings.
fn hpack_huffman_decode(src: &[u8]) -> Vec<u8> {
    const CODES: [u32; 256] = [
        0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7, 0xfffffe8, 0xffffea,
        0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec, 0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0,
        0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9,
        0xffffffa, 0xffffffb, 0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa,
        0x16, 0x17, 0x18, 0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb,
        0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
        0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22, 0x7ffd, 0x3,
        0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7, 0x2b, 0x76, 0x2c, 0x8, 0x9,
        0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc, 0xfffe6, 0x3fffd2, 0xfffe7,
        0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde,
        0xffffeb, 0x7fffdf, 0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3, 0x7fffe4,
        0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, 0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb,
        0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb,
        0x7fffec, 0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2,
        0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, 0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7,
        0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1,
        0x1ffffed, 0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2, 0x1fffe4,
        0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5, 0xfffec, 0xfffff3, 0xfffed,
        0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3, 0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5,
        0x3ffffea, 0x7ffff4, 0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
        0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
    ];
    const LENS: [u8; 256] = [
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28,
        28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15,
        6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
        15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22,
        20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23,
        23, 24, 22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22,
        22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26,
        27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27,
        26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    ];
    let mut bits: u64 = 0;
    let mut nbits: u8 = 0;
    let mut out = Vec::new();
    for &byte in src {
        bits = (bits << 8) | u64::from(byte);
        nbits += 8;
        'next: while nbits >= 5 {
            for sym in 0..256usize {
                let clen = LENS[sym];
                if nbits >= clen {
                    let mask = (1u64 << clen) - 1;
                    if ((bits >> (nbits - clen)) & mask) == u64::from(CODES[sym]) {
                        out.push(sym as u8);
                        nbits -= clen;
                        continue 'next;
                    }
                }
            }
            break;
        }
    }
    out
}

fn encode_stream_frame(out: &mut Vec<u8>, stream_id: u64, offset: u64, data: &[u8], fin: bool) {
    let mut ty = 0x08u8 | 0x02; // STREAM + LEN
    if offset > 0 {
        ty |= 0x04;
    }
    if fin {
        ty |= 0x01;
    }
    out.push(ty);
    push_varint(out, stream_id);
    if offset > 0 {
        push_varint(out, offset);
    }
    push_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn encode_h3_data_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 8);
    push_varint(&mut out, 0x00); // H3 DATA
    push_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

struct QuicConnState {
    peer: SocketAddr,
    client_scid: Vec<u8>,
    server_scid: [u8; 8],
    tls: ServerConnection,
    initial_keys: Keys,
    handshake_keys: Option<Keys>,
    one_rtt_keys: Option<Keys>,
    initial_space: PnSpace,
    handshake_space: PnSpace,
    app_space: PnSpace,
    handshake_done_sent: bool,
    streams: HashMap<u64, H3StreamState>,
    rx_1rtt_counter: usize,
    total_rx_stream_bytes: u64,
    closed: bool,
}

impl QuicConnState {
    fn new(peer: SocketAddr, odcid: &[u8], client_scid: Vec<u8>, server_scid: [u8; 8], cfg: Arc<ServerConfig>) -> Self {
        let suite = ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .quic_suite()
            .unwrap();
        let initial_keys = suite.keys(odcid, Side::Server, Version::V1);
        let params = encode_transport_params(odcid, &server_scid);
        let tls = ServerConnection::new(cfg, Version::V1, params).unwrap();
        Self {
            peer,
            client_scid,
            server_scid,
            tls,
            initial_keys,
            handshake_keys: None,
            one_rtt_keys: None,
            initial_space: PnSpace::default(),
            handshake_space: PnSpace::default(),
            app_space: PnSpace::default(),
            handshake_done_sent: false,
            streams: HashMap::new(),
            rx_1rtt_counter: 0,
            total_rx_stream_bytes: 0,
            closed: false,
        }
    }

    fn seal_short(&mut self, plain: Vec<u8>) -> Option<Vec<u8>> {
        let keys = &self.one_rtt_keys.as_ref()?.local;
        let pn = self.app_space.next_tx;
        self.app_space.next_tx += 1;
        let mut hdr = Vec::with_capacity(1 + self.client_scid.len() + 4);
        hdr.push(0x40 | 0x03); // Fixed bit + 4-byte PN
        hdr.extend_from_slice(&self.client_scid);
        let pn_offset = hdr.len();
        hdr.extend_from_slice(&(pn as u32).to_be_bytes());
        let mut body = plain;
        let tag = keys.packet.encrypt_in_place(pn, &hdr, &mut body).unwrap();
        let mut pkt = hdr;
        pkt.extend_from_slice(&body);
        pkt.extend_from_slice(tag.as_ref());
        let sample = pkt[pn_offset + 4..pn_offset + 4 + keys.header.sample_len()].to_vec();
        let (head, tail) = pkt.split_at_mut(pn_offset);
        keys.header
            .encrypt_in_place(&sample, &mut head[0], &mut tail[..4])
            .unwrap();
        Some(pkt)
    }

    fn drain_tls_writes(&mut self, out_datagrams: &mut Vec<Vec<u8>>) {
        loop {
            let mut hs_bytes = Vec::new();
            let key_change = self.tls.write_hs(&mut hs_bytes);
            if !hs_bytes.is_empty() {
                if let Some(hs_keys) = self.handshake_keys.as_ref() {
                    for chunk in hs_bytes.chunks(1000) {
                        let off = self.handshake_space.crypto_tx_offset;
                        self.handshake_space.crypto_tx_offset += chunk.len() as u64;
                        let mut plain = Vec::new();
                        let _ = self.handshake_space.encode_ack(&mut plain);
                        plain.push(0x06);
                        push_varint(&mut plain, off);
                        push_varint(&mut plain, chunk.len() as u64);
                        plain.extend_from_slice(chunk);
                        let pn = self.handshake_space.next_tx;
                        self.handshake_space.next_tx += 1;
                        out_datagrams.push(seal_long_raw(
                            2,
                            pn,
                            &self.client_scid,
                            &self.server_scid,
                            &hs_keys.local,
                            plain,
                            false,
                        ));
                    }
                } else {
                    for chunk in hs_bytes.chunks(900) {
                        let off = self.initial_space.crypto_tx_offset;
                        self.initial_space.crypto_tx_offset += chunk.len() as u64;
                        let mut plain = Vec::new();
                        let _ = self.initial_space.encode_ack(&mut plain);
                        plain.push(0x06);
                        push_varint(&mut plain, off);
                        push_varint(&mut plain, chunk.len() as u64);
                        plain.extend_from_slice(chunk);
                        let pn = self.initial_space.next_tx;
                        self.initial_space.next_tx += 1;
                        out_datagrams.push(seal_long_raw(
                            0,
                            pn,
                            &self.client_scid,
                            &self.server_scid,
                            &self.initial_keys.local,
                            plain,
                            true,
                        ));
                    }
                }
            }
            match key_change {
                Some(KeyChange::Handshake { keys }) => {
                    self.handshake_keys = Some(keys);
                }
                Some(KeyChange::OneRtt { keys, .. }) => {
                    self.one_rtt_keys = Some(keys);
                }
                None => break,
            }
        }
    }
}

fn seal_long_raw(
    pkt_type: u8,
    pn: u64,
    dcid: &[u8],
    scid: &[u8],
    keys: &DirectionalKeys,
    mut plain: Vec<u8>,
    pad_1200: bool,
) -> Vec<u8> {
    let first = 0xc0 | ((pkt_type & 0x03) << 4) | 0x03;
    let mut hdr = Vec::with_capacity(64);
    hdr.push(first);
    hdr.extend_from_slice(&1u32.to_be_bytes());
    hdr.push(dcid.len() as u8);
    hdr.extend_from_slice(dcid);
    hdr.push(scid.len() as u8);
    hdr.extend_from_slice(scid);
    if pkt_type == 0 {
        hdr.push(0);
    }
    if pad_1200 {
        let min_plain = 1200usize.saturating_sub(hdr.len() + 2 + 4 + 16);
        if plain.len() < min_plain {
            plain.resize(min_plain, 0x00);
        }
    }
    let rem_len = 4 + plain.len() + 16;
    push_varint(&mut hdr, rem_len as u64);
    let pn_offset = hdr.len();
    hdr.extend_from_slice(&(pn as u32).to_be_bytes());
    let tag = keys.packet.encrypt_in_place(pn, &hdr, &mut plain).unwrap();
    let mut pkt = hdr;
    pkt.extend_from_slice(&plain);
    pkt.extend_from_slice(tag.as_ref());
    let sample = pkt[pn_offset + 4..pn_offset + 4 + keys.header.sample_len()].to_vec();
    let (head, tail) = pkt.split_at_mut(pn_offset);
    keys.header
        .encrypt_in_place(&sample, &mut head[0], &mut tail[..4])
        .unwrap();
    pkt
}

#[derive(Default)]
struct QuicServerControl {
    /// Drop 1 out of every `N` incoming 1-RTT packets (`0` = no packet loss).
    drop_every_n: AtomicUsize,
}

struct LocalQuicServer {
    addr: SocketAddr,
    control: Arc<QuicServerControl>,
}

async fn start_quic_h3_server(server_cfg: ServerConfig) -> LocalQuicServer {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let cfg = Arc::new(server_cfg);
    let control = Arc::new(QuicServerControl::default());
    let ctrl_loop = control.clone();

    tokio::spawn(async move {
        let mut conns: HashMap<[u8; 8], QuicConnState> = HashMap::new();
        let mut by_odcid: HashMap<Vec<u8>, [u8; 8]> = HashMap::new();
        let mut next_conn_seq: u64 = 1;
        let mut rx_buf = vec![0u8; 65536];

        while let Ok((n, peer)) = sock.recv_from(&mut rx_buf).await {
            let datagram = &rx_buf[..n];
            let mut out_datagrams: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
            let mut pos = 0usize;

            while pos < datagram.len() {
                let first = datagram[pos];
                if (first & 0x80) != 0 {
                    // Long header packet.
                    if datagram.len() < pos + 7 {
                        break;
                    }
                    let pkt_type = (first >> 4) & 0x03;
                    let version = u32::from_be_bytes(datagram[pos + 1..pos + 5].try_into().unwrap());
                    let mut cur = pos + 5;
                    let dcid_len = *datagram.get(cur).unwrap_or(&0) as usize;
                    cur += 1;
                    if datagram.len() < cur + dcid_len + 1 {
                        break;
                    }
                    let dcid = datagram[cur..cur + dcid_len].to_vec();
                    cur += dcid_len;
                    let scid_len = datagram[cur] as usize;
                    cur += 1;
                    if datagram.len() < cur + scid_len {
                        break;
                    }
                    let scid = datagram[cur..cur + scid_len].to_vec();
                    cur += scid_len;
                    if version != 1 {
                        break;
                    }
                    if pkt_type == 0 {
                        let Some(tok_len) = read_varint(datagram, &mut cur) else {
                            break;
                        };
                        cur += tok_len as usize;
                    }
                    let Some(rem_len) = read_varint(datagram, &mut cur) else {
                        break;
                    };
                    let pkt_end = cur + rem_len as usize;
                    if datagram.len() < pkt_end || rem_len < 20 {
                        break;
                    }
                    let mut pkt = datagram[pos..pkt_end].to_vec();
                    let pn_offset = cur - pos;
                    pos = pkt_end;

                    let scid_key = if let Ok(arr) = <[u8; 8]>::try_from(dcid.as_slice())
                        && conns.contains_key(&arr)
                    {
                        arr
                    } else if let Some(&mapped) = by_odcid.get(&dcid) {
                        mapped
                    } else if pkt_type == 0 {
                        let mut srv_cid = [0u8; 8];
                        srv_cid[..4].copy_from_slice(b"QSRV");
                        srv_cid[4..].copy_from_slice(&(next_conn_seq as u32).to_be_bytes());
                        next_conn_seq += 1;
                        by_odcid.insert(dcid.clone(), srv_cid);
                        conns.insert(srv_cid, QuicConnState::new(peer, &dcid, scid, srv_cid, cfg.clone()));
                        srv_cid
                    } else {
                        continue;
                    };

                    let conn = conns.get_mut(&scid_key).unwrap();
                    conn.peer = peer;
                    let mut reply = Vec::new();
                    process_long_packet(conn, pkt_type, &mut pkt, pn_offset, &mut reply);
                    for d in reply {
                        out_datagrams.push((peer, d));
                    }
                } else {
                    // 1-RTT short header packet (rest of UDP datagram).
                    if datagram.len() < pos + 1 + 8 + 20 {
                        break;
                    }
                    let Ok(srv_cid) = <[u8; 8]>::try_from(&datagram[pos + 1..pos + 9]) else {
                        break;
                    };
                    let mut pkt = datagram[pos..].to_vec();
                    pos = datagram.len();
                    let Some(conn) = conns.get_mut(&srv_cid) else {
                        break;
                    };
                    conn.peer = peer;
                    let drop_n = ctrl_loop.drop_every_n.load(Ordering::Relaxed);
                    conn.rx_1rtt_counter = conn.rx_1rtt_counter.wrapping_add(1);
                    if drop_n > 0 && conn.rx_1rtt_counter % drop_n == 0 {
                        // Deterministic packet loss for Brutal loss-compensation testing.
                        continue;
                    }
                    let mut reply = Vec::new();
                    process_short_packet(conn, &mut pkt, 9, &mut reply);
                    for d in reply {
                        out_datagrams.push((peer, d));
                    }
                }
            }

            for (dst, bytes) in out_datagrams {
                let _ = sock.send_to(&bytes, dst).await;
            }
        }
    });

    LocalQuicServer { addr, control }
}

fn process_long_packet(
    conn: &mut QuicConnState,
    pkt_type: u8,
    pkt: &mut [u8],
    pn_offset: usize,
    out: &mut Vec<Vec<u8>>,
) {
    let (remote_keys, space_largest) = match pkt_type {
        0 => (&conn.initial_keys.remote, conn.initial_space.largest_rx),
        2 => {
            let Some(hs) = conn.handshake_keys.as_ref() else {
                return;
            };
            (&hs.remote, conn.handshake_space.largest_rx)
        }
        _ => return,
    };
    let sample_len = remote_keys.header.sample_len();
    if pkt.len() < pn_offset + 4 + sample_len {
        return;
    }
    let sample = pkt[pn_offset + 4..pn_offset + 4 + sample_len].to_vec();
    let (head, tail) = pkt.split_at_mut(pn_offset);
    if remote_keys
        .header
        .decrypt_in_place(&sample, &mut head[0], &mut tail[..4])
        .is_err()
    {
        return;
    }
    let pn_len = ((head[0] & 0x03) + 1) as usize;
    let mut trunc = 0u64;
    for &b in &tail[..pn_len] {
        trunc = (trunc << 8) | u64::from(b);
    }
    let pn = decode_packet_number(space_largest, trunc, pn_len * 8);
    let (aad, cipher) = pkt.split_at_mut(pn_offset + pn_len);
    let Ok(plain) = remote_keys.packet.decrypt_in_place(pn, aad, cipher) else {
        return;
    };
    let plain = plain.to_vec();

    let space = if pkt_type == 0 {
        &mut conn.initial_space
    } else {
        &mut conn.handshake_space
    };
    space.record_rx(pn);

    let mut ack_eliciting = false;
    let mut crypto_ready = Vec::new();
    let mut p = 0usize;
    while p < plain.len() {
        let Some(ft) = read_varint(&plain, &mut p) else {
            break;
        };
        match ft {
            0x00 => {}
            0x01 => ack_eliciting = true,
            0x02 | 0x03 => {
                let _ = skip_ack_frame(&plain, &mut p, ft == 0x03);
            }
            0x06 => {
                ack_eliciting = true;
                let Some(off) = read_varint(&plain, &mut p) else {
                    break;
                };
                let Some(len) = read_varint(&plain, &mut p) else {
                    break;
                };
                if plain.len() < p + len as usize {
                    break;
                }
                let data = &plain[p..p + len as usize];
                p += len as usize;
                crypto_ready.extend_from_slice(&space.crypto_rx.push(off, data, false));
            }
            0x1c | 0x1d => {
                conn.closed = true;
                return;
            }
            _ => break,
        }
    }

    let before_count = out.len();
    if !crypto_ready.is_empty() && conn.tls.read_hs(&crypto_ready).is_ok() {
        conn.drain_tls_writes(out);
    }
    if ack_eliciting && out.len() == before_count {
        if pkt_type == 0 {
            let mut ack = Vec::new();
            if conn.initial_space.encode_ack(&mut ack) {
                let tx_pn = conn.initial_space.next_tx;
                conn.initial_space.next_tx += 1;
                out.push(seal_long_raw(
                    0,
                    tx_pn,
                    &conn.client_scid,
                    &conn.server_scid,
                    &conn.initial_keys.local,
                    ack,
                    true,
                ));
            }
        } else if let Some(hs) = conn.handshake_keys.as_ref() {
            let mut ack = Vec::new();
            if conn.handshake_space.encode_ack(&mut ack) {
                let tx_pn = conn.handshake_space.next_tx;
                conn.handshake_space.next_tx += 1;
                out.push(seal_long_raw(
                    2,
                    tx_pn,
                    &conn.client_scid,
                    &conn.server_scid,
                    &hs.local,
                    ack,
                    false,
                ));
            }
        }
    }

    if !conn.tls.is_handshaking() && !conn.handshake_done_sent && conn.one_rtt_keys.is_some() {
        conn.handshake_done_sent = true;
        let mut plain1 = vec![0x1e]; // HANDSHAKE_DONE
        // Open HTTP/3 unidirectional control stream (ID 3): type 0x00 + empty SETTINGS [0x04, 0x00].
        encode_stream_frame(&mut plain1, 3, 0, &[0x00, 0x04, 0x00], false);
        if let Some(pkt1) = conn.seal_short(plain1) {
            out.push(pkt1);
        }
    }
}

fn process_short_packet(conn: &mut QuicConnState, pkt: &mut [u8], pn_offset: usize, out: &mut Vec<Vec<u8>>) {
    let Some(one_rtt) = conn.one_rtt_keys.as_ref() else {
        return;
    };
    let sample_len = one_rtt.remote.header.sample_len();
    if pkt.len() < pn_offset + 4 + sample_len {
        return;
    }
    let sample = pkt[pn_offset + 4..pn_offset + 4 + sample_len].to_vec();
    let (head, tail) = pkt.split_at_mut(pn_offset);
    if one_rtt
        .remote
        .header
        .decrypt_in_place(&sample, &mut head[0], &mut tail[..4])
        .is_err()
    {
        return;
    }
    let pn_len = ((head[0] & 0x03) + 1) as usize;
    let mut trunc = 0u64;
    for &b in &tail[..pn_len] {
        trunc = (trunc << 8) | u64::from(b);
    }
    let pn = decode_packet_number(conn.app_space.largest_rx, trunc, pn_len * 8);
    let (aad, cipher) = pkt.split_at_mut(pn_offset + pn_len);
    let Ok(plain) = one_rtt.remote.packet.decrypt_in_place(pn, aad, cipher) else {
        return;
    };
    let plain = plain.to_vec();
    let _saw_gap = conn.app_space.record_rx(pn);

    let mut ack_eliciting = false;
    let mut path_responses: Vec<[u8; 8]> = Vec::new();
    let mut touched_streams: Vec<u64> = Vec::new();
    let mut p = 0usize;

    while p < plain.len() {
        let Some(ft) = read_varint(&plain, &mut p) else {
            break;
        };
        match ft {
            0x00 => {}
            0x01 => ack_eliciting = true,
            0x02 | 0x03 => {
                let _ = skip_ack_frame(&plain, &mut p, ft == 0x03);
            }
            0x04 => {
                ack_eliciting = true;
                let _ = (
                    read_varint(&plain, &mut p),
                    read_varint(&plain, &mut p),
                    read_varint(&plain, &mut p),
                );
            }
            0x05 => {
                ack_eliciting = true;
                let _ = (read_varint(&plain, &mut p), read_varint(&plain, &mut p));
            }
            0x06 => {
                ack_eliciting = true;
                let Some(_off) = read_varint(&plain, &mut p) else { break };
                let Some(len) = read_varint(&plain, &mut p) else { break };
                p = (p + len as usize).min(plain.len());
            }
            0x07 => {
                ack_eliciting = true;
                let Some(len) = read_varint(&plain, &mut p) else { break };
                p = (p + len as usize).min(plain.len());
            }
            0x08..=0x0f => {
                ack_eliciting = true;
                let has_off = (ft & 0x04) != 0;
                let has_len = (ft & 0x02) != 0;
                let fin = (ft & 0x01) != 0;
                let Some(stream_id) = read_varint(&plain, &mut p) else {
                    break;
                };
                let off = if has_off {
                    let Some(o) = read_varint(&plain, &mut p) else { break };
                    o
                } else {
                    0
                };
                let len = if has_len {
                    let Some(l) = read_varint(&plain, &mut p) else { break };
                    l as usize
                } else {
                    plain.len().saturating_sub(p)
                };
                if plain.len() < p + len {
                    break;
                }
                let data = &plain[p..p + len];
                p += len;
                conn.total_rx_stream_bytes += len as u64;
                if stream_id % 4 == 0 {
                    // Client-initiated bidirectional HTTP/3 request stream.
                    let st = conn.streams.entry(stream_id).or_default();
                    let contig = st.rx.push(off, data, fin);
                    if !contig.is_empty() {
                        st.buf.extend_from_slice(&contig);
                    }
                    if !touched_streams.contains(&stream_id) {
                        touched_streams.push(stream_id);
                    }
                }
            }
            0x10 => {
                ack_eliciting = true;
                let _ = read_varint(&plain, &mut p);
            }
            0x11 => {
                ack_eliciting = true;
                let _ = (read_varint(&plain, &mut p), read_varint(&plain, &mut p));
            }
            0x12 | 0x13 | 0x14 | 0x16 | 0x17 | 0x19 => {
                ack_eliciting = true;
                let _ = read_varint(&plain, &mut p);
            }
            0x15 => {
                ack_eliciting = true;
                let _ = (read_varint(&plain, &mut p), read_varint(&plain, &mut p));
            }
            0x18 => {
                ack_eliciting = true;
                let _ = (read_varint(&plain, &mut p), read_varint(&plain, &mut p));
                let Some(&cid_len) = plain.get(p) else { break };
                p = (p + 1 + cid_len as usize + 16).min(plain.len());
            }
            0x1a => {
                ack_eliciting = true;
                if plain.len() >= p + 8 {
                    path_responses.push(plain[p..p + 8].try_into().unwrap());
                    p += 8;
                } else {
                    break;
                }
            }
            0x1b => {
                ack_eliciting = true;
                p = (p + 8).min(plain.len());
            }
            0x1c | 0x1d => {
                conn.closed = true;
                return;
            }
            _ => break,
        }
    }

    let mut tx_frames: Vec<Vec<u8>> = Vec::new();
    for challenge in path_responses {
        let mut f = vec![0x1b];
        f.extend_from_slice(&challenge);
        tx_frames.push(f);
    }

    // Replenish connection-level flow control generously.
    if conn.total_rx_stream_bytes > 0 && conn.total_rx_stream_bytes % (512 * 1024) < 2048 {
        let mut max_data = vec![0x10];
        push_varint(&mut max_data, 256 * 1024 * 1024 + conn.total_rx_stream_bytes * 2);
        tx_frames.push(max_data);
    }

    for sid in touched_streams {
        let Some(st) = conn.streams.get_mut(&sid) else {
            continue;
        };
        // Replenish stream-level flow control generously.
        if st.rx.next_offset > 0 && st.rx.next_offset % (256 * 1024) < 2048 {
            let mut msd = vec![0x11];
            push_varint(&mut msd, sid);
            push_varint(&mut msd, 64 * 1024 * 1024 + st.rx.next_offset * 2);
            tx_frames.push(msd);
        }

        // Parse complete HTTP/3 frames from `st.buf`.
        loop {
            let mut cur = 0usize;
            let Some(h3_type) = read_varint(&st.buf, &mut cur) else {
                break;
            };
            let Some(h3_len) = read_varint(&st.buf, &mut cur) else {
                break;
            };
            let h3_len = h3_len as usize;
            if st.buf.len() < cur + h3_len {
                break;
            }
            let payload = st.buf[cur..cur + h3_len].to_vec();
            st.buf.drain(..cur + h3_len);

            match h3_type {
                0x01 => {
                    // H3 HEADERS frame.
                    let path = parse_qpack_path(&payload);
                    let route = if path.starts_with("/sink") {
                        H3Route::Sink
                    } else {
                        H3Route::Echo
                    };
                    st.route = Some(route);
                    if !st.headers_sent {
                        st.headers_sent = true;
                        // QPACK static `:status: 200` (index 25 => 0xd9): HEADERS frame [0x01, 0x03, 0x00, 0x00, 0xd9].
                        let resp_hdrs = [0x01u8, 0x03, 0x00, 0x00, 0xd9];
                        let mut sf = Vec::new();
                        encode_stream_frame(&mut sf, sid, st.tx_offset, &resp_hdrs, false);
                        st.tx_offset += resp_hdrs.len() as u64;
                        tx_frames.push(sf);
                    }
                }
                0x00 => {
                    // H3 DATA frame.
                    st.uploaded_data_bytes += payload.len() as u64;
                    if matches!(st.route, Some(H3Route::Echo)) {
                        for piece in payload.chunks(1000) {
                            let h3_data = encode_h3_data_frame(piece);
                            let mut sf = Vec::new();
                            encode_stream_frame(&mut sf, sid, st.tx_offset, &h3_data, false);
                            st.tx_offset += h3_data.len() as u64;
                            tx_frames.push(sf);
                        }
                    }
                }
                _ => {}
            }
        }

        if st.rx.is_complete() && st.buf.is_empty() && !st.finished {
            st.finished = true;
            if !st.headers_sent {
                st.headers_sent = true;
                let resp_hdrs = [0x01u8, 0x03, 0x00, 0x00, 0xd9];
                let mut sf = Vec::new();
                encode_stream_frame(&mut sf, sid, st.tx_offset, &resp_hdrs, false);
                st.tx_offset += resp_hdrs.len() as u64;
                tx_frames.push(sf);
            }
            let tail = match st.route.unwrap_or(H3Route::Echo) {
                H3Route::Sink => encode_h3_data_frame(st.uploaded_data_bytes.to_string().as_bytes()),
                H3Route::Echo => Vec::new(),
            };
            let mut sf = Vec::new();
            encode_stream_frame(&mut sf, sid, st.tx_offset, &tail, true);
            st.tx_offset += tail.len() as u64;
            tx_frames.push(sf);
        }
    }

    if tx_frames.is_empty() {
        if ack_eliciting {
            let mut ack = Vec::new();
            if conn.app_space.encode_ack(&mut ack)
                && let Some(pkt_out) = conn.seal_short(ack)
            {
                out.push(pkt_out);
            }
        }
    } else {
        let mut first_with_ack = true;
        for frame in tx_frames {
            let mut plain_out = Vec::with_capacity(frame.len() + 32);
            if first_with_ack {
                let _ = conn.app_space.encode_ack(&mut plain_out);
                first_with_ack = false;
            }
            plain_out.extend_from_slice(&frame);
            if let Some(pkt_out) = conn.seal_short(plain_out) {
                out.push(pkt_out);
            }
        }
    }
}

fn skip_ack_frame(buf: &[u8], pos: &mut usize, has_ecn: bool) -> Option<()> {
    let _ = read_varint(buf, pos)?;
    let _ = read_varint(buf, pos)?;
    let count = read_varint(buf, pos)?;
    let _ = read_varint(buf, pos)?;
    for _ in 0..count {
        let _ = read_varint(buf, pos)?;
        let _ = read_varint(buf, pos)?;
    }
    if has_ecn {
        let _ = read_varint(buf, pos)?;
        let _ = read_varint(buf, pos)?;
        let _ = read_varint(buf, pos)?;
    }
    Some(())
}

fn build_h3_engine(ca_pem: &str, quic_port: u16, client_quic_options: &str) -> Engine {
    let mut params = EngineParams::new();
    params
        .set_enable_quic(true)
        .set_enable_http2(true)
        .add_quic_hint(&QuicHint::with("quic.example", quic_port, quic_port));
    params
        .set_host_resolver_rules("MAP quic.example 127.0.0.1")
        .unwrap()
        .set_quic_options("", client_quic_options, 16 * 1024 * 1024, 32 * 1024 * 1024)
        .unwrap();
    Engine::builder()
        .tls_config(&tls::Config {
            root_certificates_pem: Some(ca_pem.to_owned()),
            ..tls::Config::default()
        })
        .unwrap()
        .start(&params)
        .unwrap()
}

async fn run_h3_sink_upload(
    engine: &Engine,
    port: u16,
    total_bytes: usize,
    rate_bps: Option<u64>,
) -> (u64, f64, Duration) {
    let mut conn = BidirectionalConn::new(
        engine,
        ConnOptions {
            read_wait_headers: true,
            write_wait_headers: false,
        },
    );
    let url = format!("https://quic.example:{port}/sink");
    conn.start("POST", &url, &[("-force-quic", "on")], StreamPriority::Medium, false)
        .unwrap();
    let headers = tokio::time::timeout(Duration::from_secs(10), conn.headers())
        .await
        .expect("H3 headers timeout")
        .expect("H3 headers succeed");
    assert_eq!(headers.status(), Some(200));
    assert_eq!(headers.negotiated_protocol, "quic/1+spdy/3");

    let conn_id = conn.connection_id();
    assert_ne!(conn_id, 0);
    assert_ne!(conn_id & QUIC_SESSION_ID_BIT, 0);

    if let Some(bps) = rate_bps {
        engine.set_quic_send_rate(conn_id, bps);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let chunk = vec![0x5au8; 32 * 1024];
    let started = Instant::now();
    let mut remaining = total_bytes;
    while remaining > 0 {
        let n = remaining.min(chunk.len());
        conn.write_all(&chunk[..n]).await.unwrap();
        remaining -= n;
    }
    conn.flush().await.unwrap();
    conn.shutdown().await.unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), conn.read_to_end(&mut resp))
        .await
        .expect("H3 sink response timeout")
        .unwrap();
    let elapsed = started.elapsed();
    let reported: usize = std::str::from_utf8(&resp).unwrap().trim().parse().unwrap();
    assert_eq!(reported, total_bytes);
    let measured_bps = (total_bytes as f64) / elapsed.as_secs_f64();
    (conn_id, measured_bps, elapsed)
}

#[tokio::test(flavor = "multi_thread")]
async fn h3_streams_report_high_bit_session_id_and_tcp_ids_remain_unchanged() {
    if !common::library() {
        return;
    }
    let (ca_pem, h3_cfg, h2_cfg) = generate_certs(&["quic.example", "h2.example", "127.0.0.1"]);
    let quic_srv = start_quic_h3_server(h3_cfg).await;
    let port = quic_srv.addr.port();
    let engine = build_h3_engine(&ca_pem, port, "");

    // 1. Open primary HTTP/3 stream and keep it open so concurrent streams pool onto the same QUIC session.
    let mut first = BidirectionalConn::new(
        &engine,
        ConnOptions {
            read_wait_headers: true,
            write_wait_headers: false,
        },
    );
    let echo_url = format!("https://quic.example:{port}/echo");
    first
        .start(
            "POST",
            &echo_url,
            &[("-force-quic", "on")],
            StreamPriority::Medium,
            false,
        )
        .unwrap();
    let first_hdrs = tokio::time::timeout(Duration::from_secs(10), first.headers())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_hdrs.status(), Some(200));
    assert_eq!(first_hdrs.negotiated_protocol, "quic/1+spdy/3");
    let session_id_1 = first.connection_id();
    assert_ne!(session_id_1, 0);
    assert_ne!(
        session_id_1 & QUIC_SESSION_ID_BIT,
        0,
        "QUIC session connection_id must have bit 63 set: {session_id_1:#x}"
    );

    let mut tasks = Vec::new();
    for idx in 1..4usize {
        let engine = engine.clone();
        let url = echo_url.clone();
        tasks.push(tokio::spawn(async move {
            let mut c = BidirectionalConn::new(
                &engine,
                ConnOptions {
                    read_wait_headers: true,
                    write_wait_headers: false,
                },
            );
            c.start("POST", &url, NO_HEADERS, StreamPriority::Medium, false)
                .unwrap();
            let msg = format!("h3-multiplex-payload-{idx}").into_bytes();
            c.write_all(&msg).await.unwrap();
            c.shutdown().await.unwrap();
            let hdrs = c.headers().await.unwrap();
            assert_eq!(hdrs.status(), Some(200));
            assert_eq!(hdrs.negotiated_protocol, "quic/1+spdy/3");
            let id = c.connection_id();
            let mut echoed = Vec::new();
            c.read_to_end(&mut echoed).await.unwrap();
            assert_eq!(echoed, msg);
            id
        }));
    }

    first.write_all(b"h3-primary").await.unwrap();
    first.shutdown().await.unwrap();
    let mut first_echo = Vec::new();
    first.read_to_end(&mut first_echo).await.unwrap();
    assert_eq!(first_echo, b"h3-primary");

    for task in tasks {
        assert_eq!(task.await.unwrap(), session_id_1);
    }

    // 2. Closing all connections establishes a new QUIC session with a new high-bit ID.
    engine.close_all_connections();
    let (session_id_2, _, _) = run_h3_sink_upload(&engine, port, 64 * 1024, None).await;
    assert_ne!(session_id_2 & QUIC_SESSION_ID_BIT, 0);
    assert_ne!(session_id_2, session_id_1);

    // Calling set_quic_send_rate with 0, closed, or unknown IDs from any thread is a safe no-op.
    let engine_bg = engine.clone();
    std::thread::spawn(move || {
        engine_bg.set_quic_send_rate(0, 1_000_000);
        engine_bg.set_quic_send_rate(session_id_1, 1_000_000);
        engine_bg.set_quic_send_rate(QUIC_SESSION_ID_BIT | 0x00ff_ffff, 1_000_000);
    })
    .join()
    .unwrap();

    // 3. Verify TCP connection_id invariants remain unchanged:
    //    - OS-socket TCP HTTP/2 stream returns 0;
    //    - StreamDialer TCP HTTP/2 stream returns non-zero with bit 63 == 0.
    let h2_acceptor = TlsAcceptor::from(Arc::new(h2_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = listener.local_addr().unwrap();
    let acceptor_os = h2_acceptor.clone();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await
            && let Ok(tls_io) = acceptor_os.accept(tcp).await
            && let Ok(mut h2_conn) = h2::server::handshake(tls_io).await
        {
            while let Some(Ok((_req, mut respond))) = h2_conn.accept().await {
                tokio::spawn(async move {
                    if let Ok(mut send) = respond.send_response(http::Response::new(()), false) {
                        let _ = send.send_data(Bytes::from_static(b"ok"), true);
                    }
                });
            }
        }
    });

    let mut os_params = EngineParams::new();
    os_params.set_enable_quic(false).set_enable_http2(true);
    let os_engine = Engine::builder()
        .tls_config(&tls::Config {
            root_certificates_pem: Some(ca_pem.clone()),
            ..tls::Config::default()
        })
        .unwrap()
        .start(&os_params)
        .unwrap();
    let os_conn = BidirectionalConn::new(&os_engine, ConnOptions::default());
    os_conn
        .start(
            "GET",
            &format!("https://{tcp_addr}/"),
            NO_HEADERS,
            StreamPriority::Medium,
            true,
        )
        .unwrap();
    let os_hdrs = os_conn.headers().await.unwrap();
    assert_eq!(os_hdrs.negotiated_protocol, "h2");
    assert_eq!(
        os_conn.connection_id(),
        0,
        "default OS-socket TCP stream must still report connection_id == 0"
    );

    let recorded_target: Arc<Mutex<Option<Target>>> = Arc::new(Mutex::new(None));
    let recorded_clone = recorded_target.clone();
    let sd_engine = Engine::builder()
        .tls_config(&tls::Config {
            root_certificates_pem: Some(ca_pem),
            ..tls::Config::default()
        })
        .unwrap()
        .endpoint(
            "h2.example",
            Endpoint {
                alpn: vec!["h2".into()],
                ..Endpoint::default()
            },
        )
        .stream_dialer(move |target| -> io::Result<Box<dyn Lower>> {
            *recorded_clone.lock().unwrap() = Some(target);
            let (client_io, server_io) = tokio::io::duplex(32 * 1024);
            let acc = h2_acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls_io) = acc.accept(server_io).await
                    && let Ok(mut h2_conn) = h2::server::handshake(tls_io).await
                {
                    while let Some(Ok((_req, mut respond))) = h2_conn.accept().await {
                        tokio::spawn(async move {
                            if let Ok(mut send) = respond.send_response(http::Response::new(()), false) {
                                let _ = send.send_data(Bytes::from_static(b"sd"), true);
                            }
                        });
                    }
                }
            });
            Ok(Box::new(client_io))
        })
        .start(&os_params)
        .unwrap();
    let sd_conn = BidirectionalConn::new(&sd_engine, ConnOptions::default());
    sd_conn
        .start("GET", "https://h2.example/", NO_HEADERS, StreamPriority::Medium, true)
        .unwrap();
    assert_eq!(sd_conn.headers().await.unwrap().negotiated_protocol, "h2");
    let tcp_id = sd_conn.connection_id();
    let dialed_id = recorded_target.lock().unwrap().as_ref().unwrap().connection_id;
    assert_ne!(tcp_id, 0);
    assert_eq!(tcp_id, dialed_id);
    assert_eq!(
        tcp_id & QUIC_SESSION_ID_BIT,
        0,
        "StreamDialer TCP connection_id must keep high bit 0: {tcp_id:#x}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn brutal_unset_and_zero_rate_preserve_unthrottled_h3_transfer() {
    if !common::library() {
        return;
    }
    let (ca_pem, h3_cfg, _) = generate_certs(&["quic.example"]);
    let quic_srv = start_quic_h3_server(h3_cfg).await;
    let port = quic_srv.addr.port();
    let engine = build_h3_engine(&ca_pem, port, "BRTL");

    // 1. With `BRTL` enabled and no rate configured, BBR fallback runs unthrottled on loopback.
    let (conn_id, unset_bps, unset_elapsed) = run_h3_sink_upload(&engine, port, 3 * 1024 * 1024, None).await;
    assert!(
        unset_bps > 6_000_000.0,
        "unset BRTL rate should run unthrottled on loopback, got {unset_bps:.0} B/s ({unset_elapsed:?})"
    );

    // 2. Enabling a rate and resetting back to 0 restores unthrottled BBR behavior.
    engine.set_quic_send_rate(conn_id, 1_500_000);
    tokio::time::sleep(Duration::from_millis(20)).await;
    engine.set_quic_send_rate(conn_id, 0);
    tokio::time::sleep(Duration::from_millis(20)).await;

    let (conn_id_after, reset_bps, reset_elapsed) = run_h3_sink_upload(&engine, port, 3 * 1024 * 1024, None).await;
    assert_eq!(conn_id_after, conn_id);
    assert!(
        reset_bps > 6_000_000.0,
        "resetting BRTL rate to 0 should restore unthrottled BBR, got {reset_bps:.0} B/s ({reset_elapsed:?})"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn brutal_set_quic_send_rate_shapes_throughput_close_to_target_and_compensates_loss() {
    if !common::library() {
        return;
    }
    let (ca_pem, h3_cfg, _) = generate_certs(&["quic.example"]);
    let quic_srv = start_quic_h3_server(h3_cfg).await;
    let port = quic_srv.addr.port();
    let engine = build_h3_engine(&ca_pem, port, "BRTL");

    // 1. Target 1.5 MB/s: upload 2.25 MB (~1.5s) and verify throughput tracks target.
    let target_low = 1_500_000u64;
    let (conn_id_1, low_bps, low_elapsed) = run_h3_sink_upload(&engine, port, 2_250_000, Some(target_low)).await;
    eprintln!(
        "[quic_brutal] target={} B/s, measured={:.0} B/s, elapsed={:?}",
        target_low, low_bps, low_elapsed
    );
    assert!(
        (1_050_000.0..=2_100_000.0).contains(&low_bps),
        "expected throughput near {target_low} B/s, got {low_bps:.0} B/s ({low_elapsed:?})"
    );

    // 2. Dynamically raise rate on the same live QUIC session to 4.0 MB/s: upload 4.0 MB (~1.0s).
    let target_high = 4_000_000u64;
    let (conn_id_2, high_bps, high_elapsed) = run_h3_sink_upload(&engine, port, 4_000_000, Some(target_high)).await;
    assert_eq!(conn_id_2, conn_id_1);
    eprintln!(
        "[quic_brutal] target={} B/s, measured={:.0} B/s, elapsed={:?}",
        target_high, high_bps, high_elapsed
    );
    assert!(
        (2_800_000.0..=5_600_000.0).contains(&high_bps),
        "expected throughput near {target_high} B/s, got {high_bps:.0} B/s ({high_elapsed:?})"
    );
    assert!(
        high_bps > low_bps * 1.8,
        "raising rate from 1.5 MB/s to 4.0 MB/s must scale throughput ({low_bps:.0} vs {high_bps:.0})"
    );

    // 3. Inject 4% packet loss (drop 1 in 25 1-RTT packets) at 3.0 MB/s target:
    //    Brutal loss compensation keeps goodput near target without collapsing.
    quic_srv.control.drop_every_n.store(25, Ordering::Relaxed);
    let target_loss = 3_000_000u64;
    let (_, loss_bps, loss_elapsed) = run_h3_sink_upload(&engine, port, 3_000_000, Some(target_loss)).await;
    quic_srv.control.drop_every_n.store(0, Ordering::Relaxed);
    eprintln!(
        "[quic_brutal] 4% loss target={} B/s, measured={:.0} B/s, elapsed={:?}",
        target_loss, loss_bps, loss_elapsed
    );
    assert!(
        (1_900_000.0..=4_500_000.0).contains(&loss_bps),
        "expected Brutal goodput under 4% loss near {target_loss} B/s, got {loss_bps:.0} B/s ({loss_elapsed:?})"
    );
}
