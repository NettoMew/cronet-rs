// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_CRONET_NATIVE_INCLUDE_CRONET_C_H_
#define COMPONENTS_CRONET_NATIVE_INCLUDE_CRONET_C_H_

#include <stddef.h>
#include <stdint.h>

#include "cronet_export.h"

// Cronet public C API is generated from cronet.idl
#include "cronet.idl_c.h"

#ifdef __cplusplus
extern "C" {
#endif

// Stream Engine used by Bidirectional Stream C API for GRPC.
typedef struct stream_engine stream_engine;
typedef struct bidirectional_stream bidirectional_stream;

// Additional Cronet C API not generated from cronet.idl.

// Sets net::CertVerifier* raw_mock_cert_verifier for testing of Cronet_Engine.
// Must be called before Cronet_Engine_InitWithParams().
CRONET_EXPORT void Cronet_Engine_SetMockCertVerifierForTesting(
    Cronet_EnginePtr engine,
    /* net::CertVerifier* */ void* raw_mock_cert_verifier);

// Returns "stream_engine" interface for bidirectionsl stream support for GRPC.
// Returned stream engine is owned by Cronet Engine and is only valid until
// Cronet_Engine_Shutdown().
CRONET_EXPORT stream_engine* Cronet_Engine_GetStreamEngine(
    Cronet_EnginePtr engine);

// Creates a CertVerifier that uses custom root certificates for validation.
// pem_root_certs: PEM-formatted root certificates (can contain multiple certs).
// Returns a pointer to the created net::CertVerifier.
// The caller is responsible for passing it to
// Cronet_Engine_SetMockCertVerifierForTesting() which takes ownership.
// Returns nullptr if the PEM data is invalid or no valid certificates found.
CRONET_EXPORT void* Cronet_CreateCertVerifierWithRootCerts(
    const char* pem_root_certs);

// Dialer callback type for custom TCP connection establishment.
// context: User-provided context pointer passed to Cronet_Engine_SetDialer.
// address: IP address string (e.g. "1.2.3.4" or "::1").
// port: Port number.
// Returns: connected socket fd on success, negative net error code on failure.
// Common error codes:
//   -102: ERR_CONNECTION_REFUSED
//   -104: ERR_CONNECTION_FAILED
//   -109: ERR_ADDRESS_UNREACHABLE
//   -118: ERR_CONNECTION_TIMED_OUT
typedef intptr_t (*Cronet_DialerFunc)(void* context,
                                      const char* address,
                                      uint16_t port);

// Sets a custom dialer for TCP connections.
// When set, the engine will use this callback to establish TCP connections
// instead of the default system socket API.
// Must be called before Cronet_Engine_StartWithParams().
// dialer: The callback function to use for TCP connections, or nullptr to
//         disable custom dialing.
// context: User-provided context pointer that will be passed to the dialer.
CRONET_EXPORT void Cronet_Engine_SetDialer(Cronet_EnginePtr engine,
                                           Cronet_DialerFunc dialer,
                                           void* context);

// UDP Dialer callback type for custom UDP socket creation.
// context: User-provided context pointer passed to Cronet_Engine_SetUdpDialer.
// address: IP address string (e.g. "1.2.3.4" or "::1").
// port: Port number.
// out_local_address: Output buffer for local IP address (caller provides
// buffer,
//                    should be at least 46 bytes for INET6_ADDRSTRLEN).
// out_local_port: Output pointer for local port number.
// out_socket_id: Opaque identifier passed to on_close; zero skips notification.
// Returns: socket fd on success, negative net error code on failure.
// The returned socket can be:
//   - AF_INET/AF_INET6 SOCK_DGRAM: Standard UDP socket
//   - AF_UNIX SOCK_DGRAM: Unix domain datagram socket (Unix/macOS/Linux)
//   - AF_UNIX SOCK_STREAM: Unix domain stream socket (Windows, with framing)
typedef intptr_t (*Cronet_UdpDialerFunc)(void* context,
                                         const char* address,
                                         uint16_t port,
                                         char* out_local_address,
                                         uint16_t* out_local_port,
                                         uint64_t* out_socket_id);

typedef void (*Cronet_UdpSocketCloseFunc)(uint64_t socket_id);

// Sets a custom dialer for UDP sockets.
// When set, the engine will use this callback to create UDP sockets
// instead of the default system socket API.
// Must be called before Cronet_Engine_StartWithParams().
// dialer: The callback function to use for UDP sockets, or nullptr to
//         disable custom UDP dialing.
// context: User-provided context pointer that will be passed to the dialer.
CRONET_EXPORT void Cronet_Engine_SetUdpDialer(
    Cronet_EnginePtr engine,
    Cronet_UdpDialerFunc dialer,
    void* context,
    Cronet_UdpSocketCloseFunc on_close);

// Closes all connections managed by the engine's network session.
// This includes socket pools, HTTP stream pool, SPDY session pool,
// and QUIC session pool. Useful for releasing connection-related memory
// or speeding up engine shutdown.
// Must be called after Cronet_Engine_StartWithParams().
// Calls from Cronet's network thread schedule the close asynchronously.
CRONET_EXPORT void Cronet_Engine_CloseAllConnections(Cronet_EnginePtr engine);

// Readiness flags for Cronet_LowerStreamHandle_Notify.
typedef enum Cronet_LowerReady {
  Cronet_LowerReady_READABLE = 1,
  Cronet_LowerReady_WRITABLE = 2,
} Cronet_LowerReady;

// Thread-safe handle used by an embedder to wake a pending read or write on a
// Cronet_LowerStream from any thread.
typedef struct Cronet_LowerStreamHandle Cronet_LowerStreamHandle;

// Non-blocking byte stream owned by the embedder.
// `read` returns bytes read (> 0), 0 on clean EOF, -1 (ERR_IO_PENDING) when no
// data is ready yet, or another negative Chromium net error code.
// `write` returns bytes written (> 0), -1 (ERR_IO_PENDING) when congested, or
// another negative Chromium net error code.
typedef struct Cronet_LowerStream {
  void* context;
  intptr_t (*read)(void* context, uint8_t* buffer, size_t capacity);
  intptr_t (*write)(void* context, const uint8_t* data, size_t length);
  void (*close)(void* context);
} Cronet_LowerStream;

// Callback invoked on the network thread to open a byte stream to `host:port`.
// On success (return 0), the callback takes ownership of `handle` (freeing it
// with Cronet_LowerStreamHandle_Destroy after `close` runs) and populates
// `out_stream`. On failure (return a negative net error code), Cronet frees
// `handle`.
typedef int (*Cronet_StreamDialerFunc)(void* context,
                                       const char* host,
                                       uint16_t port,
                                       uint64_t connection_id,
                                       Cronet_LowerStreamHandle* handle,
                                       Cronet_LowerStream* out_stream);

// Sets a custom stream dialer on `engine` before StartWithParams. When set,
// TCP connections run over embedder-provided Cronet_LowerStream instances
// rather than OS file descriptors.
CRONET_EXPORT void Cronet_Engine_SetStreamDialer(
    Cronet_EnginePtr engine,
    Cronet_StreamDialerFunc dialer,
    void* context);

// Signals that a Cronet_LowerStream may now make progress on READABLE and/or
// WRITABLE operations. Safe to call from any thread.
CRONET_EXPORT void Cronet_LowerStreamHandle_Notify(
    Cronet_LowerStreamHandle* handle,
    uint32_t flags);

// Releases a Cronet_LowerStreamHandle previously handed to a stream dialer or
// TLS connection.
CRONET_EXPORT void Cronet_LowerStreamHandle_Destroy(
    Cronet_LowerStreamHandle* handle);

// Returns the `connection_id` of the transport connection carrying `stream`:
// - for TCP connections opened via a custom stream dialer, the non-zero ID
//   passed to `Cronet_StreamDialerFunc` (high bit 0);
// - for QUIC sessions, `(1ULL << 63) | n` (high bit 1), shared by all HTTP/3
//   streams multiplexed onto the same QUIC session;
// - 0 for default OS-socket TCP connections or streams not yet bound.
CRONET_EXPORT uint64_t Cronet_BidirectionalStream_GetConnectionId(
    bidirectional_stream* stream);

// Registers or updates synthetic endpoint metadata (ECHConfigList, comma-
// separated ALPNs such as "h2" or "h3,h2", and strict ECH enforcement) for
// `host` on `engine`. May be called both before and after StartWithParams().
// Enabling any endpoint installs an in-memory HostResolver that never queries
// system or network DNS.
CRONET_EXPORT void Cronet_Engine_SetEndpoint(
    Cronet_EnginePtr engine,
    const char* host,
    const uint8_t* ech_config_list,
    size_t ech_config_list_len,
    const char* alpns_comma_separated,
    bool strict_ech);

// Clears all registered endpoint metadata entries on `engine` while enabling
// (or keeping active) the in-memory endpoint resolver.
CRONET_EXPORT void Cronet_Engine_ClearEndpoints(Cronet_EnginePtr engine);

// Unified TLS verification, client-auth, ALPN, and ECH configuration shared by
// Cronet_Engine_ConfigureTls and Cronet_TlsClient_Create.
typedef struct Cronet_TlsConfig {
  bool insecure;
  const char* pem_root_certs;
  const char* verify_name;
  const uint8_t* cert_pins_sha256;
  size_t cert_pins_count;
  const uint8_t* key_pins_sha256;
  size_t key_pins_count;
  const uint8_t* client_cert_pem;
  size_t client_cert_pem_len;
  const uint8_t* client_key_data;
  size_t client_key_data_len;
  const char* alpns_comma_separated;
  const uint8_t* ech_config_list;
  size_t ech_config_list_len;
  bool strict_ech;
  int64_t time_offset_ms;
} Cronet_TlsConfig;

// Configures `engine` with the unified certificate verifier and optional client
// certificate before StartWithParams(). Returns true on success, or false with
// a NUL-terminated reason written to `err_buf`.
CRONET_EXPORT bool Cronet_Engine_ConfigureTls(Cronet_EnginePtr engine,
                                              const Cronet_TlsConfig* config,
                                              char* err_buf,
                                              size_t err_len);

typedef struct Cronet_TlsClient Cronet_TlsClient;
typedef struct Cronet_TlsConn Cronet_TlsConn;

typedef struct Cronet_TlsConnCallbacks {
  void (*on_handshake)(void* context,
                       int net_error,
                       const char* negotiated_alpn,
                       bool ech_accepted,
                       const uint8_t* ech_retry_configs,
                       size_t ech_retry_configs_len);
  void (*on_read_completed)(void* context,
                            const uint8_t* data,
                            int bytes_read_or_error);
  void (*on_write_completed)(void* context, int bytes_written_or_error);
  void (*on_closed)(void* context);
} Cronet_TlsConnCallbacks;

CRONET_EXPORT Cronet_TlsClient* Cronet_TlsClient_Create(
    Cronet_EnginePtr engine,
    const Cronet_TlsConfig* config,
    char* err_buf,
    size_t err_len);

CRONET_EXPORT void Cronet_TlsClient_SetTimeOffset(Cronet_TlsClient* client,
                                                  int64_t offset_ms);

CRONET_EXPORT void Cronet_TlsClient_Destroy(Cronet_TlsClient* client);

CRONET_EXPORT Cronet_TlsConn* Cronet_TlsConn_Create(
    Cronet_TlsClient* client,
    const char* host,
    uint16_t port,
    const uint8_t* ech_config_list,
    size_t ech_config_list_len,
    const Cronet_TlsConnCallbacks* callbacks,
    void* callback_context,
    Cronet_LowerStreamHandle** out_lower_handle);

CRONET_EXPORT void Cronet_TlsConn_Start(
    Cronet_TlsConn* conn,
    const Cronet_LowerStream* lower_stream);

CRONET_EXPORT void Cronet_TlsConn_Read(Cronet_TlsConn* conn, size_t max_bytes);

CRONET_EXPORT void Cronet_TlsConn_Write(Cronet_TlsConn* conn,
                                        const uint8_t* data,
                                        size_t length);

CRONET_EXPORT void Cronet_TlsConn_Destroy(Cronet_TlsConn* conn);

// Sets or updates the QUIC Brutal send rate (in bytes per second) for the
// live QUIC session identified by `connection_id` (`(1ULL << 63) | n` from
// Cronet_BidirectionalStream_GetConnectionId) when the engine negotiated the
// `BRTL` client connection option. Passing `0` disables fixed-rate sending
// and falls back to BBR. Safe to call from any thread; unknown or closed
// `connection_id` values are ignored.
CRONET_EXPORT void Cronet_Engine_SetQuicSendRate(Cronet_EnginePtr engine,
                                                 uint64_t connection_id,
                                                 uint64_t bytes_per_second);

#ifdef __cplusplus
}
#endif

#endif  // COMPONENTS_CRONET_NATIVE_INCLUDE_CRONET_C_H_
