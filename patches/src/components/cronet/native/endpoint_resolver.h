// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_CRONET_NATIVE_ENDPOINT_RESOLVER_H_
#define COMPONENTS_CRONET_NATIVE_ENDPOINT_RESOLVER_H_

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/memory/ref_counted.h"
#include "base/memory/scoped_refptr.h"
#include "base/synchronization/lock.h"
#include "net/base/address_list.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/ech_mode.h"
#include "net/base/ip_address.h"
#include "net/dns/host_resolver.h"
#include "net/socket/next_proto.h"
#include "net/socket/ssl_client_socket.h"
#include "net/ssl/ssl_config.h"
#include "net/ssl/ssl_config_service_defaults.h"

namespace cronet {

struct EndpointMetadataEntry {
  std::vector<uint8_t> ech_config_list;
  std::vector<std::string> alpns;
  bool strict_ech = false;
};

// Thread-safe per-engine registry mapping hostnames to synthetic placeholder
// IPv4 addresses and optional HTTPS/SVCB metadata (ECHConfigList, ALPNs, and
// strict ECH policy).
class EndpointRegistry final
    : public base::RefCountedThreadSafe<EndpointRegistry> {
 public:
  EndpointRegistry();

  EndpointRegistry(const EndpointRegistry&) = delete;
  EndpointRegistry& operator=(const EndpointRegistry&) = delete;

  void SetEnabled(bool enabled);
  bool IsEnabled() const;

  void SetEndpoint(std::string host,
                   std::vector<uint8_t> ech_config_list,
                   std::vector<std::string> alpns,
                   bool strict_ech);
  void ClearEndpoints();

  struct ResolvedHost {
    net::IPAddress ip;
    net::ConnectionEndpointMetadata metadata;
  };

  ResolvedHost Resolve(std::string_view host);
  std::optional<std::string> LookupHostByIp(const net::IPAddress& ip) const;
  net::EchMode GetEchMode(std::string_view hostname) const;

 private:
  friend class base::RefCountedThreadSafe<EndpointRegistry>;
  ~EndpointRegistry();

  static std::string NormalizeHost(std::string_view host);

  mutable base::Lock lock_;
  bool enabled_ = false;
  uint32_t next_synthetic_id_ = 1;
  std::map<std::string, EndpointMetadataEntry> entries_;
  std::map<std::string, net::IPAddress> host_to_ip_;
  std::map<net::IPAddress, std::string> ip_to_host_;
};

// HostResolver that resolves every name in-memory without touching DNS,
// attaching any registered ConnectionEndpointMetadata (ECHConfigList + ALPNs).
class EndpointHostResolver final : public net::HostResolver {
 public:
  explicit EndpointHostResolver(scoped_refptr<EndpointRegistry> registry);

  EndpointHostResolver(const EndpointHostResolver&) = delete;
  EndpointHostResolver& operator=(const EndpointHostResolver&) = delete;

  ~EndpointHostResolver() override;

  void OnShutdown() override;

  bool IsHappyEyeballsV3Enabled() const override;

  void SetRequestContext(net::URLRequestContext* request_context) override;

  std::unique_ptr<ProbeRequest> CreateDohProbeRequest() override;

  std::unique_ptr<ResolveHostRequest> CreateRequest(
      url::SchemeHostPort host,
      net::NetworkAnonymizationKey network_anonymization_key,
      net::handles::NetworkHandle target_network,
      net::NetLogWithSource net_log,
      std::optional<ResolveHostParameters> optional_parameters) override;

  std::unique_ptr<ResolveHostRequest> CreateRequest(
      const net::HostPortPair& host,
      const net::NetworkAnonymizationKey& network_anonymization_key,
      net::handles::NetworkHandle target_network,
      const net::NetLogWithSource& net_log,
      const std::optional<ResolveHostParameters>& optional_parameters) override;

  std::unique_ptr<ServiceEndpointRequest> CreateServiceEndpointRequest(
      Host host,
      net::NetworkAnonymizationKey network_anonymization_key,
      net::handles::NetworkHandle target_network,
      net::NetLogWithSource net_log,
      ResolveHostParameters parameters) override;

 private:
  scoped_refptr<EndpointRegistry> registry_;
};

// Shared SSLConfigService used by both Cronet_Engine and Cronet_TlsClient so
// both paths advertise identical Chrome Trust Anchor IDs, server padding, and
// per-host strict/opportunistic ECH mode.
class EndpointSSLConfigService final : public net::SSLConfigServiceDefaults {
 public:
  EndpointSSLConfigService(scoped_refptr<EndpointRegistry> registry,
                           bool default_strict_ech);

  ~EndpointSSLConfigService() override;

  net::EchMode GetEchMode(std::string_view hostname) const override;
  net::SSLContextConfig GetSSLContextConfig() override;

 private:
  scoped_refptr<EndpointRegistry> registry_;
  bool default_strict_ech_ = false;
};

// Builds a net::SSLConfig matching Chrome's HttpStreamPool::AttemptManager +
// TlsStreamAttempt so Cronet_TlsClient and Cronet_Engine emit byte-identical
// TLS ClientHellos under identical parameters.
net::SSLConfig BuildChromeSslConfig(
    net::SSLClientContext* context,
    const std::vector<net::NextProto>& alpns,
    std::vector<uint8_t> ech_config_list);

std::vector<std::string> SplitCommaSeparatedAlpns(const char* csv);
std::vector<net::NextProto> ParseNextProtos(
    const std::vector<std::string>& alpns);

}  // namespace cronet

#endif  // COMPONENTS_CRONET_NATIVE_ENDPOINT_RESOLVER_H_
