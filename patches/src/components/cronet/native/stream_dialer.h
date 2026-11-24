// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_CRONET_NATIVE_STREAM_DIALER_H_
#define COMPONENTS_CRONET_NATIVE_STREAM_DIALER_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <optional>
#include <string>

#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/address_list.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/transport_client_socket.h"

struct Cronet_LowerStream;
struct Cronet_LowerStreamHandle;

namespace cronet {

using RawStreamDialerFunc = int (*)(void* context,
                                    const char* host,
                                    uint16_t port,
                                    uint64_t connection_id,
                                    Cronet_LowerStreamHandle* handle,
                                    Cronet_LowerStream* out_stream);

using HostLookupCallback =
    base::RepeatingCallback<std::optional<std::string>(const net::IPAddress&)>;

class LowerStreamSocket;

// Thread-safe handle allowing an embedder to signal readiness of a
// Cronet_LowerStream from any thread onto the engine's network thread.
class LowerStreamBridge final
    : public base::RefCountedThreadSafe<LowerStreamBridge> {
 public:
  explicit LowerStreamBridge(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  LowerStreamBridge(const LowerStreamBridge&) = delete;
  LowerStreamBridge& operator=(const LowerStreamBridge&) = delete;

  void AttachSocket(base::WeakPtr<LowerStreamSocket> socket);
  void NotifyReady(uint32_t flags);

 private:
  friend class base::RefCountedThreadSafe<LowerStreamBridge>;
  ~LowerStreamBridge();

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  base::WeakPtr<LowerStreamSocket> socket_;
};

// Adapts an embedder-owned Cronet_LowerStream into a Chromium
// net::TransportClientSocket (and net::StreamSocket). Chromium never owns or
// touches an OS file descriptor on this path.
class LowerStreamSocket final : public net::TransportClientSocket {
 public:
  struct LowerStreamVtable {
    raw_ptr<void> context = nullptr;
    intptr_t (*read)(void* context, uint8_t* buffer, size_t capacity) = nullptr;
    intptr_t (*write)(void* context,
                      const uint8_t* data,
                      size_t length) = nullptr;
    void (*close)(void* context) = nullptr;
  };

  LowerStreamSocket(const Cronet_LowerStream& stream,
                    uint64_t connection_id,
                    const net::IPEndPoint& peer_address,
                    net::NetLog* net_log,
                    const net::NetLogSource& source);

  LowerStreamSocket(const LowerStreamSocket&) = delete;
  LowerStreamSocket& operator=(const LowerStreamSocket&) = delete;

  ~LowerStreamSocket() override;

  uint64_t connection_id() const { return connection_id_; }
  void RegisterSslSocketLogId(uint32_t ssl_socket_log_id);
  bool write_pending() const { return !write_callback_.is_null(); }
  void WhenWriteDrained(base::OnceCallback<void(int)> callback);
  base::WeakPtr<LowerStreamSocket> GetWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

  // Invoked on the network thread when the embedder reports new readability or
  // writability on the underlying stream.
  void Retry(uint32_t flags);

  // net::TransportClientSocket:
  int Bind(const net::IPEndPoint& local_addr) override;
  bool SetNoDelay(bool no_delay) override;
  bool SetKeepAlive(bool enable, int delay_secs) override;

  // net::StreamSocket:
  int Connect(net::CompletionOnceCallback callback) override;
  void Disconnect() override;
  bool IsConnected() const override;
  bool IsConnectedAndIdle() const override;
  int GetPeerAddress(net::IPEndPoint* address) const override;
  int GetLocalAddress(net::IPEndPoint* address) const override;
  const net::NetLogWithSource& NetLog() const override;
  bool WasEverUsed() const override;
  net::NextProto GetNegotiatedProtocol() const override;
  bool GetSSLInfo(net::SSLInfo* ssl_info) override;
  int64_t GetTotalReceivedBytes() const override;
  void ApplySocketTag(const net::SocketTag& tag) override;

  // net::Socket:
  int Read(net::IOBuffer* buf,
           int buf_len,
           net::CompletionOnceCallback callback) override;
  int ReadIfReady(net::IOBuffer* buf,
                  int buf_len,
                  net::CompletionOnceCallback callback) override;
  int CancelReadIfReady() override;
  int Write(net::IOBuffer* buf,
            int buf_len,
            net::CompletionOnceCallback callback,
            const net::NetworkTrafficAnnotationTag& traffic_annotation) override;
  int SetReceiveBufferSize(int32_t size) override;
  int SetSendBufferSize(int32_t size) override;

 private:
  void CloseStream();

  LowerStreamVtable stream_;
  bool stream_closed_ = false;
  const uint64_t connection_id_;
  uint32_t ssl_socket_log_id_ = 0;
  net::IPEndPoint peer_address_;
  net::NetLogWithSource net_log_;
  bool connected_ = true;
  bool ever_used_ = false;
  int64_t received_bytes_ = 0;

  scoped_refptr<net::IOBuffer> read_buf_;
  int read_len_ = 0;
  net::CompletionOnceCallback read_callback_;

  scoped_refptr<net::IOBuffer> write_buf_;
  size_t write_len_ = 0;
  net::CompletionOnceCallback write_callback_;
  base::OnceCallback<void(int)> write_drained_callback_;

  base::WeakPtrFactory<LowerStreamSocket> weak_factory_{this};
};

// Allocates a monotonically increasing non-zero connection identifier.
uint64_t NextStreamConnectionId();

// Wraps `bridge` in a heap-allocated C handle released via
// Cronet_LowerStreamHandle_Destroy.
Cronet_LowerStreamHandle* CreateLowerStreamHandle(
    scoped_refptr<LowerStreamBridge> bridge);

// Maps NetLog socket IDs to embedder connection IDs for active connections.
void RegisterSocketLogConnectionId(uint32_t socket_log_id,
                                   uint64_t connection_id);
void UnregisterSocketLogConnectionId(uint32_t socket_log_id);
uint64_t LookupConnectionIdBySocketLogId(uint32_t socket_log_id);

// ClientSocketFactory that establishes TCP streams via Cronet_StreamDialerFunc
// while delegating datagram sockets (or fallback TCP sockets when no stream
// dialer is configured) to `fallback_factory` or the default factory.
class StreamClientSocketFactory final : public net::ClientSocketFactory {
 public:
  StreamClientSocketFactory(
      RawStreamDialerFunc stream_dialer,
      void* stream_dialer_context,
      HostLookupCallback host_lookup,
      std::unique_ptr<net::ClientSocketFactory> fallback_factory);

  StreamClientSocketFactory(const StreamClientSocketFactory&) = delete;
  StreamClientSocketFactory& operator=(const StreamClientSocketFactory&) =
      delete;

  ~StreamClientSocketFactory() override;

  std::unique_ptr<net::DatagramClientSocket> CreateDatagramClientSocket(
      net::DatagramSocket::BindType bind_type,
      net::handles::NetworkHandle target_network,
      net::NetLog* net_log,
      const net::NetLogSource& source) override;

  std::unique_ptr<net::TransportClientSocket> CreateTransportClientSocket(
      const net::AddressList& addresses,
      net::handles::NetworkHandle target_network,
      std::unique_ptr<net::SocketPerformanceWatcher> socket_performance_watcher,
      net::NetworkQualityEstimator* network_quality_estimator,
      net::NetLog* net_log,
      const net::NetLogSource& source) override;

  std::unique_ptr<net::SSLClientSocket> CreateSSLClientSocket(
      net::SSLClientContext* context,
      std::unique_ptr<net::StreamSocket> stream_socket,
      const net::HostPortPair& host_and_port,
      const net::SSLConfig& ssl_config) override;

 private:
  RawStreamDialerFunc stream_dialer_;
  raw_ptr<void> stream_dialer_context_;
  HostLookupCallback host_lookup_;
  std::unique_ptr<net::ClientSocketFactory> fallback_factory_;
};

}  // namespace cronet

#endif  // COMPONENTS_CRONET_NATIVE_STREAM_DIALER_H_
