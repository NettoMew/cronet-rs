// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/cronet/native/stream_dialer.h"

#include <atomic>
#include <unordered_map>
#include <utility>

#include "base/functional/bind.h"
#include "base/no_destructor.h"
#include "base/synchronization/lock.h"
#include "components/cronet/native/include/cronet_c.h"
#include "components/grpc_support/include/bidirectional_stream_c.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/socket/datagram_client_socket.h"
#include "net/socket/ssl_client_socket.h"

struct Cronet_LowerStreamHandle {
  scoped_refptr<cronet::LowerStreamBridge> bridge;
};

namespace cronet {

namespace {

int NormalizeLowerResult(intptr_t r) {
  return static_cast<int>(r);
}

class FailingStreamTransportSocket final : public net::TransportClientSocket {
 public:
  FailingStreamTransportSocket(int error_code,
                               net::NetLog* net_log,
                               const net::NetLogSource&)
      : error_code_(error_code),
        net_log_(net::NetLogWithSource::Make(
            net_log, net::NetLogSourceType::SOCKET)) {}

  ~FailingStreamTransportSocket() override = default;

  int Bind(const net::IPEndPoint&) override { return net::ERR_FAILED; }
  bool SetNoDelay(bool) override { return false; }
  bool SetKeepAlive(bool, int) override { return false; }
  int Connect(net::CompletionOnceCallback) override { return error_code_; }
  void Disconnect() override {}
  bool IsConnected() const override { return false; }
  bool IsConnectedAndIdle() const override { return false; }
  int GetPeerAddress(net::IPEndPoint*) const override {
    return net::ERR_SOCKET_NOT_CONNECTED;
  }
  int GetLocalAddress(net::IPEndPoint*) const override {
    return net::ERR_SOCKET_NOT_CONNECTED;
  }
  const net::NetLogWithSource& NetLog() const override { return net_log_; }
  bool WasEverUsed() const override { return false; }
  net::NextProto GetNegotiatedProtocol() const override {
    return net::NextProto::kProtoUnknown;
  }
  bool GetSSLInfo(net::SSLInfo*) override { return false; }
  int64_t GetTotalReceivedBytes() const override { return 0; }
  void ApplySocketTag(const net::SocketTag&) override {}
  int Read(net::IOBuffer*, int, net::CompletionOnceCallback) override {
    return error_code_;
  }
  int Write(net::IOBuffer*,
            int,
            net::CompletionOnceCallback,
            const net::NetworkTrafficAnnotationTag&) override {
    return error_code_;
  }
  int SetReceiveBufferSize(int32_t) override { return net::ERR_FAILED; }
  int SetSendBufferSize(int32_t) override { return net::ERR_FAILED; }

 private:
  const int error_code_;
  net::NetLogWithSource net_log_;
};

struct ConnectionIdRegistry {
  base::Lock lock;
  std::unordered_map<uint32_t, uint64_t> by_socket_log_id;
};

ConnectionIdRegistry& GetConnectionIdRegistry() {
  static base::NoDestructor<ConnectionIdRegistry> registry;
  return *registry;
}

}  // namespace

uint64_t NextStreamConnectionId() {
  static std::atomic<uint64_t> next_id{1};
  return next_id.fetch_add(1, std::memory_order_relaxed);
}

Cronet_LowerStreamHandle* CreateLowerStreamHandle(
    scoped_refptr<LowerStreamBridge> bridge) {
  return new Cronet_LowerStreamHandle{std::move(bridge)};
}

void RegisterSocketLogConnectionId(uint32_t socket_log_id,
                                   uint64_t connection_id) {
  if (socket_log_id == 0 || connection_id == 0) {
    return;
  }
  auto& reg = GetConnectionIdRegistry();
  base::AutoLock guard(reg.lock);
  reg.by_socket_log_id[socket_log_id] = connection_id;
}

void UnregisterSocketLogConnectionId(uint32_t socket_log_id) {
  if (socket_log_id == 0) {
    return;
  }
  auto& reg = GetConnectionIdRegistry();
  base::AutoLock guard(reg.lock);
  reg.by_socket_log_id.erase(socket_log_id);
}

uint64_t LookupConnectionIdBySocketLogId(uint32_t socket_log_id) {
  if (socket_log_id == 0) {
    return 0;
  }
  auto& reg = GetConnectionIdRegistry();
  base::AutoLock guard(reg.lock);
  auto it = reg.by_socket_log_id.find(socket_log_id);
  return it != reg.by_socket_log_id.end() ? it->second : 0;
}

LowerStreamBridge::LowerStreamBridge(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : task_runner_(std::move(task_runner)) {}

LowerStreamBridge::~LowerStreamBridge() = default;

void LowerStreamBridge::AttachSocket(base::WeakPtr<LowerStreamSocket> socket) {
  socket_ = std::move(socket);
}

void LowerStreamBridge::NotifyReady(uint32_t flags) {
  if (!task_runner_) {
    return;
  }
  if (task_runner_->BelongsToCurrentThread()) {
    if (socket_) {
      socket_->Retry(flags);
    }
    return;
  }
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<LowerStreamBridge> self, uint32_t ready_flags) {
            if (self->socket_) {
              self->socket_->Retry(ready_flags);
            }
          },
          scoped_refptr<LowerStreamBridge>(this), flags));
}

LowerStreamSocket::LowerStreamSocket(const Cronet_LowerStream& stream,
                                     uint64_t connection_id,
                                     const net::IPEndPoint& peer_address,
                                     net::NetLog* net_log,
                                     const net::NetLogSource&)
    : stream_{stream.context, stream.read, stream.write, stream.close},
      connection_id_(connection_id),
      peer_address_(peer_address),
      net_log_(net::NetLogWithSource::Make(
          net_log, net::NetLogSourceType::SOCKET)) {
  RegisterSocketLogConnectionId(net_log_.source().id, connection_id_);
}

LowerStreamSocket::~LowerStreamSocket() {
  UnregisterSocketLogConnectionId(net_log_.source().id);
  UnregisterSocketLogConnectionId(ssl_socket_log_id_);
  CloseStream();
}

void LowerStreamSocket::RegisterSslSocketLogId(uint32_t ssl_socket_log_id) {
  if (ssl_socket_log_id_ != 0 && ssl_socket_log_id_ != ssl_socket_log_id) {
    UnregisterSocketLogConnectionId(ssl_socket_log_id_);
  }
  ssl_socket_log_id_ = ssl_socket_log_id;
  RegisterSocketLogConnectionId(ssl_socket_log_id_, connection_id_);
}

void LowerStreamSocket::WhenWriteDrained(
    base::OnceCallback<void(int)> callback) {
  if (!write_pending()) {
    std::move(callback).Run(net::OK);
    return;
  }
  write_drained_callback_ = std::move(callback);
}

void LowerStreamSocket::CloseStream() {
  connected_ = false;
  if (!stream_closed_) {
    stream_closed_ = true;
    if (stream_.close) {
      stream_.close(stream_.context);
    }
  }
}

void LowerStreamSocket::Retry(uint32_t flags) {
  auto guard = weak_factory_.GetWeakPtr();
  if ((flags & Cronet_LowerReady_WRITABLE) && write_callback_) {
    intptr_t r = stream_.write(
        stream_.context, reinterpret_cast<const uint8_t*>(write_buf_->data()),
        write_len_);
    if (r != net::ERR_IO_PENDING) {
      if (r > 0) {
        ever_used_ = true;
      }
      int status = NormalizeLowerResult(r);
      write_buf_ = nullptr;
      write_len_ = 0;
      std::move(write_callback_).Run(status);
      if (!guard) {
        return;
      }
      if (!write_pending() && write_drained_callback_) {
        std::move(write_drained_callback_).Run(status < 0 ? status : net::OK);
        if (!guard) {
          return;
        }
      }
    }
  }
  if ((flags & Cronet_LowerReady_READABLE) && read_callback_) {
    if (read_buf_) {
      intptr_t r = stream_.read(
          stream_.context, reinterpret_cast<uint8_t*>(read_buf_->data()),
          static_cast<size_t>(read_len_));
      if (r == net::ERR_IO_PENDING) {
        return;
      }
      if (r > 0) {
        ever_used_ = true;
        received_bytes_ += r;
      }
      read_buf_ = nullptr;
      read_len_ = 0;
      std::move(read_callback_).Run(NormalizeLowerResult(r));
    } else {
      // ReadIfReady contract: notify caller with OK so SocketBIOAdapter issues
      // a fresh ReadIfReady with its own buffer.
      std::move(read_callback_).Run(net::OK);
    }
  }
}

int LowerStreamSocket::Bind(const net::IPEndPoint&) {
  return net::OK;
}

bool LowerStreamSocket::SetNoDelay(bool) {
  return true;
}

bool LowerStreamSocket::SetKeepAlive(bool, int) {
  return true;
}

int LowerStreamSocket::Connect(net::CompletionOnceCallback) {
  return connected_ ? net::OK : net::ERR_CONNECTION_CLOSED;
}

void LowerStreamSocket::Disconnect() {
  read_buf_ = nullptr;
  read_len_ = 0;
  read_callback_.Reset();
  write_buf_ = nullptr;
  write_len_ = 0;
  write_callback_.Reset();
  write_drained_callback_.Reset();
  CloseStream();
}

bool LowerStreamSocket::IsConnected() const {
  return connected_;
}

bool LowerStreamSocket::IsConnectedAndIdle() const {
  return connected_ && read_callback_.is_null() && write_callback_.is_null();
}

int LowerStreamSocket::GetPeerAddress(net::IPEndPoint* address) const {
  if (!connected_) {
    return net::ERR_SOCKET_NOT_CONNECTED;
  }
  *address = peer_address_;
  return net::OK;
}

int LowerStreamSocket::GetLocalAddress(net::IPEndPoint* address) const {
  if (!connected_) {
    return net::ERR_SOCKET_NOT_CONNECTED;
  }
  *address = net::IPEndPoint(net::IPAddress::IPv4Localhost(), 0);
  return net::OK;
}

const net::NetLogWithSource& LowerStreamSocket::NetLog() const {
  return net_log_;
}

bool LowerStreamSocket::WasEverUsed() const {
  return ever_used_;
}

net::NextProto LowerStreamSocket::GetNegotiatedProtocol() const {
  return net::NextProto::kProtoUnknown;
}

bool LowerStreamSocket::GetSSLInfo(net::SSLInfo*) {
  return false;
}

int64_t LowerStreamSocket::GetTotalReceivedBytes() const {
  return received_bytes_;
}

void LowerStreamSocket::ApplySocketTag(const net::SocketTag&) {}

int LowerStreamSocket::Read(net::IOBuffer* buf,
                            int buf_len,
                            net::CompletionOnceCallback callback) {
  int rv = ReadIfReady(buf, buf_len, std::move(callback));
  if (rv == net::ERR_IO_PENDING) {
    read_buf_ = buf;
    read_len_ = buf_len;
  }
  return rv;
}

int LowerStreamSocket::ReadIfReady(net::IOBuffer* buf,
                                   int buf_len,
                                   net::CompletionOnceCallback callback) {
  if (!connected_) {
    return net::ERR_SOCKET_NOT_CONNECTED;
  }
  intptr_t r = stream_.read(stream_.context,
                            reinterpret_cast<uint8_t*>(buf->data()),
                            static_cast<size_t>(buf_len));
  if (r == net::ERR_IO_PENDING) {
    read_callback_ = std::move(callback);
    return net::ERR_IO_PENDING;
  }
  if (r > 0) {
    ever_used_ = true;
    received_bytes_ += r;
  }
  return NormalizeLowerResult(r);
}

int LowerStreamSocket::CancelReadIfReady() {
  read_buf_ = nullptr;
  read_len_ = 0;
  read_callback_.Reset();
  return net::OK;
}

int LowerStreamSocket::Write(
    net::IOBuffer* buf,
    int buf_len,
    net::CompletionOnceCallback callback,
    const net::NetworkTrafficAnnotationTag&) {
  if (!connected_) {
    return net::ERR_SOCKET_NOT_CONNECTED;
  }
  intptr_t r = stream_.write(stream_.context,
                             reinterpret_cast<const uint8_t*>(buf->data()),
                             static_cast<size_t>(buf_len));
  if (r == net::ERR_IO_PENDING) {
    write_buf_ = buf;
    write_len_ = static_cast<size_t>(buf_len);
    write_callback_ = std::move(callback);
    return net::ERR_IO_PENDING;
  }
  if (r > 0) {
    ever_used_ = true;
  }
  return NormalizeLowerResult(r);
}

int LowerStreamSocket::SetReceiveBufferSize(int32_t) {
  return net::OK;
}

int LowerStreamSocket::SetSendBufferSize(int32_t) {
  return net::OK;
}

StreamClientSocketFactory::StreamClientSocketFactory(
    RawStreamDialerFunc stream_dialer,
    void* stream_dialer_context,
    HostLookupCallback host_lookup,
    std::unique_ptr<net::ClientSocketFactory> fallback_factory)
    : stream_dialer_(stream_dialer),
      stream_dialer_context_(stream_dialer_context),
      host_lookup_(std::move(host_lookup)),
      fallback_factory_(std::move(fallback_factory)) {}

StreamClientSocketFactory::~StreamClientSocketFactory() = default;

std::unique_ptr<net::DatagramClientSocket>
StreamClientSocketFactory::CreateDatagramClientSocket(
    net::DatagramSocket::BindType bind_type,
    net::handles::NetworkHandle target_network,
    net::NetLog* net_log,
    const net::NetLogSource& source) {
  net::ClientSocketFactory* inner =
      fallback_factory_ ? fallback_factory_.get()
                        : net::ClientSocketFactory::GetDefaultFactory();
  return inner->CreateDatagramClientSocket(bind_type, target_network, net_log,
                                           source);
}

std::unique_ptr<net::TransportClientSocket>
StreamClientSocketFactory::CreateTransportClientSocket(
    const net::AddressList& addresses,
    net::handles::NetworkHandle target_network,
    std::unique_ptr<net::SocketPerformanceWatcher> socket_performance_watcher,
    net::NetworkQualityEstimator* network_quality_estimator,
    net::NetLog* net_log,
    const net::NetLogSource& source) {
  if (!stream_dialer_) {
    net::ClientSocketFactory* inner =
        fallback_factory_ ? fallback_factory_.get()
                          : net::ClientSocketFactory::GetDefaultFactory();
    return inner->CreateTransportClientSocket(
        addresses, target_network, std::move(socket_performance_watcher),
        network_quality_estimator, net_log, source);
  }

  auto task_runner = base::SingleThreadTaskRunner::GetCurrentDefault();
  int last_error = net::ERR_NAME_NOT_RESOLVED;
  for (const auto& endpoint : addresses) {
    std::string host;
    if (host_lookup_) {
      if (auto mapped = host_lookup_.Run(endpoint.address())) {
        host = std::move(*mapped);
      }
    }
    if (host.empty()) {
      if (!addresses.dns_aliases().empty()) {
        host = *addresses.dns_aliases().begin();
      } else {
        host = endpoint.ToStringWithoutPort();
      }
    }

    uint64_t connection_id = NextStreamConnectionId();
    auto bridge = base::MakeRefCounted<LowerStreamBridge>(task_runner);
    auto* raw_handle = new Cronet_LowerStreamHandle{bridge};
    Cronet_LowerStream lower{};
    int rv = stream_dialer_(stream_dialer_context_, host.c_str(),
                            endpoint.port(), connection_id, raw_handle, &lower);
    if (rv == net::OK) {
      auto socket = std::make_unique<LowerStreamSocket>(
          lower, connection_id, endpoint, net_log, source);
      bridge->AttachSocket(socket->GetWeakPtr());
      return socket;
    }
    delete raw_handle;
    last_error = rv;
  }

  return std::make_unique<FailingStreamTransportSocket>(last_error, net_log,
                                                        source);
}

std::unique_ptr<net::SSLClientSocket>
StreamClientSocketFactory::CreateSSLClientSocket(
    net::SSLClientContext* context,
    std::unique_ptr<net::StreamSocket> stream_socket,
    const net::HostPortPair& host_and_port,
    const net::SSLConfig& ssl_config) {
  uint64_t lower_conn_id = LookupConnectionIdBySocketLogId(
      stream_socket->NetLog().source().id);
  LowerStreamSocket* lower_ptr =
      lower_conn_id != 0 ? static_cast<LowerStreamSocket*>(stream_socket.get())
                         : nullptr;
  auto ssl_socket =
      net::ClientSocketFactory::GetDefaultFactory()->CreateSSLClientSocket(
          context, std::move(stream_socket), host_and_port, ssl_config);
  if (lower_ptr && ssl_socket) {
    lower_ptr->RegisterSslSocketLogId(ssl_socket->NetLog().source().id);
  }
  return ssl_socket;
}

}  // namespace cronet

CRONET_EXPORT void Cronet_LowerStreamHandle_Notify(
    Cronet_LowerStreamHandle* handle,
    uint32_t flags) {
  if (handle && handle->bridge) {
    handle->bridge->NotifyReady(flags);
  }
}

CRONET_EXPORT void Cronet_LowerStreamHandle_Destroy(
    Cronet_LowerStreamHandle* handle) {
  delete handle;
}

CRONET_EXPORT uint64_t Cronet_BidirectionalStream_GetConnectionId(
    bidirectional_stream* stream) {
  if (!stream) {
    return 0;
  }
  uint32_t socket_log_id = bidirectional_stream_get_socket_log_id(stream);
  return cronet::LookupConnectionIdBySocketLogId(socket_log_id);
}
