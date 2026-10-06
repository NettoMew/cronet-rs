//! The engine and the value objects, against the real library.

mod common;

use std::time::{Duration, SystemTime};

use cronet::{DateTime, EngineParams, Error, ErrorCode, NetError, QuicHint};

#[test]
fn date_time_round_trips() {
    if !common::library() {
        return;
    }
    let now = SystemTime::UNIX_EPOCH + Duration::from_millis(1_759_000_000_123);
    assert_eq!(DateTime::from(now).value(), now);
    let before = SystemTime::UNIX_EPOCH - Duration::from_millis(5);
    assert_eq!(DateTime::from(before).value(), before);
}

#[test]
fn engine_reports_version_and_user_agent() {
    if !common::library() {
        return;
    }
    let engine = common::engine();
    // The library matches the headers the bindings were generated from.
    assert_eq!(engine.version(), cronet::sys::CHROMIUM_VERSION);
    assert!(!engine.default_user_agent().is_empty());
}

#[test]
fn engine_params_keep_what_is_set() {
    if !common::library() {
        return;
    }
    let mut params = EngineParams::new();
    params
        .set_user_agent("agent")
        .set_enable_quic(false)
        .set_network_thread_priority(Some(1.5))
        .add_quic_hint(&QuicHint::with("example.com", 443, 8443));
    params
        .set_async_dns(true)
        .unwrap()
        .set_host_resolver_rules("MAP x 1.2.3.4")
        .unwrap();
    assert_eq!(params.user_agent(), "agent");
    assert!(!params.enable_quic());
    assert_eq!(params.network_thread_priority(), Some(1.5));
    assert_eq!(
        params
            .quic_hints()
            .map(|hint| hint.alternate_port())
            .collect::<Vec<_>>(),
        [8443]
    );
    let options: serde_json::Value = serde_json::from_str(&params.experimental_options()).unwrap();
    assert_eq!(options["AsyncDNS"]["enable"], true);
    assert_eq!(options["HostResolverRules"]["host_resolver_rules"], "MAP x 1.2.3.4");
    params.set_async_dns(false).unwrap();
    let options: serde_json::Value = serde_json::from_str(&params.experimental_options()).unwrap();
    assert!(options.get("AsyncDNS").is_none());
}

#[test]
fn errors_copy_and_convert() {
    if !common::library() {
        return;
    }
    let mut error = Error::new();
    error
        .set_error_code(ErrorCode::ConnectionRefused)
        .set_message("refused")
        .set_internal_error_code(NetError::CONNECTION_REFUSED);
    let copy = error.clone();
    assert_eq!(copy.to_string(), "refused");
    assert_eq!(copy.internal_error_code(), NetError::CONNECTION_REFUSED);
    assert_eq!(std::io::Error::from(copy).kind(), std::io::ErrorKind::ConnectionRefused);
}
