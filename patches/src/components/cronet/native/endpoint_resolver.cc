// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/cronet/native/endpoint_resolver.h"

#include <set>
#include <utility>

#include "base/containers/extend.h"
#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "build/build_config.h"
#include "net/base/features.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/cert/x509_util.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/public/resolve_error_info.h"

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
#include "net/cert/internal/trust_store_chrome.h"
#endif

namespace cronet {

namespace {

// Synthetic IPv4 block 198.18.0.0/15 (RFC 2544 benchmarking) gives 131,070
// distinct addresses without colliding with 127.0.0.0/8 or RFC 1918 networks.
net::IPAddress SyntheticIpForIndex(uint32_t id) {
  uint8_t b1 = static_cast<uint8_t>(18 + ((id >> 16) & 0x01));
  uint8_t b2 = static_cast<uint8_t>((id >> 8) & 0xff);
  uint8_t b3 = static_cast<uint8_t>(id & 0xff);
  if (b2 == 0 && b3 == 0) {
    b3 = 1;
  }
  return net::IPAddress(198, b1, b2, b3);
}

class ImmediateResolveHostRequest final
    : public net::HostResolver::ResolveHostRequest {
 public:
  ImmediateResolveHostRequest(const EndpointRegistry::ResolvedHost& resolved,
                              std::string canonical_host,
                              uint16_t port) {
    net::IPEndPoint ip_endpoint(resolved.ip, port);
    aliases_.insert(canonical_host);
    address_list_ = net::AddressList(ip_endpoint, {canonical_host});

    net::HostResolverEndpointResult ep;
    ep.ip_endpoints.push_back(ip_endpoint);
    ep.metadata = resolved.metadata;
    endpoints_.push_back(std::move(ep));

    // When `resolved.metadata` is an HTTPS/SVCB alternative endpoint without
    // ECH, RFC 9460 also exposes the authority A/AAAA fallback endpoint; when
    // ECH is present, AllAlternativeEndpointsHaveEch() requires every endpoint
    // to carry ECH so no unencrypted fallback is offered.
    if (resolved.metadata.IsAlternative() &&
        resolved.metadata.ech_config_list.empty()) {
      net::HostResolverEndpointResult plain;
      plain.ip_endpoints.push_back(ip_endpoint);
      endpoints_.push_back(std::move(plain));
    }
  }

  ~ImmediateResolveHostRequest() override = default;

  int Start(net::CompletionOnceCallback) override { return net::OK; }

  const net::AddressList& GetAddressResults() const override {
    return address_list_;
  }

  base::span<const net::HostResolverEndpointResult> GetEndpointResults()
      const override {
    return endpoints_;
  }

  base::span<const std::string> GetTextResults() const override { return {}; }

  base::span<const net::HostPortPair> GetHostnameResults() const override {
    return {};
  }

  const std::set<std::string>& GetDnsAliasResults() const override {
    return aliases_;
  }

  net::ResolveErrorInfo GetResolveErrorInfo() const override {
    return net::ResolveErrorInfo(net::OK);
  }

  const std::optional<net::HostCache::EntryStaleness>& GetStaleInfo()
      const override {
    return staleness_;
  }

  std::optional<net::ResolutionDetails> GetResolutionDetails() const override {
    return std::nullopt;
  }

 private:
  net::AddressList address_list_;
  std::vector<net::HostResolverEndpointResult> endpoints_;
  std::set<std::string> aliases_;
  std::optional<net::HostCache::EntryStaleness> staleness_;
};

class ImmediateServiceEndpointRequest final
    : public net::HostResolver::ServiceEndpointRequest {
 public:
  ImmediateServiceEndpointRequest(
      const EndpointRegistry::ResolvedHost& resolved,
      std::string canonical_host,
      uint16_t port) {
    net::IPEndPoint ip_endpoint(resolved.ip, port);
    aliases_.insert(std::move(canonical_host));

    net::ServiceEndpoint ep;
    if (resolved.ip.IsIPv4()) {
      ep.ipv4_endpoints.push_back(ip_endpoint);
    } else {
      ep.ipv6_endpoints.push_back(ip_endpoint);
    }
    ep.metadata = resolved.metadata;
    endpoints_.push_back(std::move(ep));
  }

  ~ImmediateServiceEndpointRequest() override = default;

  int Start(Delegate*) override { return net::OK; }

  base::span<const net::ServiceEndpoint> GetEndpointResults() override {
    return endpoints_;
  }

  const std::set<std::string>& GetDnsAliasResults() override {
    return aliases_;
  }

  bool EndpointsCryptoReady() override { return true; }

  net::ResolveErrorInfo GetResolveErrorInfo() override {
    return net::ResolveErrorInfo(net::OK);
  }

  const net::HostCache::EntryStaleness* GetStaleInfo() const override {
    return nullptr;
  }

  bool IsStaleWhileRefreshing() const override { return false; }

  void ChangeRequestPriority(net::RequestPriority) override {}

  std::optional<net::ResolutionDetails> GetResolutionDetails() const override {
    return std::nullopt;
  }

 private:
  std::vector<net::ServiceEndpoint> endpoints_;
  std::set<std::string> aliases_;
};

}  // namespace

EndpointRegistry::EndpointRegistry() = default;
EndpointRegistry::~EndpointRegistry() = default;

std::string EndpointRegistry::NormalizeHost(std::string_view host) {
  if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
    host.remove_prefix(1);
    host.remove_suffix(1);
  }
  return base::ToLowerASCII(host);
}

void EndpointRegistry::SetEnabled(bool enabled) {
  base::AutoLock guard(lock_);
  enabled_ = enabled;
}

bool EndpointRegistry::IsEnabled() const {
  base::AutoLock guard(lock_);
  return enabled_ || !entries_.empty();
}

void EndpointRegistry::SetEndpoint(std::string host,
                                   std::vector<uint8_t> ech_config_list,
                                   std::vector<std::string> alpns,
                                   bool strict_ech) {
  std::string key = NormalizeHost(host);
  base::AutoLock guard(lock_);
  enabled_ = true;
  if (key.empty()) {
    return;
  }
  if (!ech_config_list.empty() && alpns.empty()) {
    alpns = {"h2", "http/1.1"};
  }
  EndpointMetadataEntry entry;
  entry.ech_config_list = std::move(ech_config_list);
  entry.alpns = std::move(alpns);
  entry.strict_ech = strict_ech;
  entries_[key] = std::move(entry);
}

void EndpointRegistry::ClearEndpoints() {
  base::AutoLock guard(lock_);
  enabled_ = true;
  entries_.clear();
}

EndpointRegistry::ResolvedHost EndpointRegistry::Resolve(
    std::string_view raw_host) {
  std::string key = NormalizeHost(raw_host);
  base::AutoLock guard(lock_);

  net::IPAddress ip;
  if (!ip.AssignFromIPLiteral(key)) {
    auto it = host_to_ip_.find(key);
    if (it != host_to_ip_.end()) {
      ip = it->second;
    } else {
      uint32_t id = next_synthetic_id_++;
      if (next_synthetic_id_ > 0x1fffe) {
        next_synthetic_id_ = 1;
      }
      ip = SyntheticIpForIndex(id);
      host_to_ip_[key] = ip;
      ip_to_host_[ip] = key;
    }
  }

  net::ConnectionEndpointMetadata metadata;
  auto entry_it = entries_.find(key);
  if (entry_it != entries_.end()) {
    metadata.ech_config_list = entry_it->second.ech_config_list;
    metadata.supported_protocol_alpns = entry_it->second.alpns;
    metadata.target_name = key;
  }
  return ResolvedHost{ip, std::move(metadata)};
}

std::optional<std::string> EndpointRegistry::LookupHostByIp(
    const net::IPAddress& ip) const {
  base::AutoLock guard(lock_);
  auto it = ip_to_host_.find(ip);
  if (it == ip_to_host_.end()) {
    return std::nullopt;
  }
  return it->second;
}

net::EchMode EndpointRegistry::GetEchMode(std::string_view hostname) const {
  std::string key = NormalizeHost(hostname);
  base::AutoLock guard(lock_);
  auto it = entries_.find(key);
  if (it != entries_.end() && it->second.strict_ech) {
    return net::EchMode::kStrict;
  }
  return net::EchMode::kOpportunistic;
}

EndpointHostResolver::EndpointHostResolver(
    scoped_refptr<EndpointRegistry> registry)
    : registry_(std::move(registry)) {}

EndpointHostResolver::~EndpointHostResolver() = default;

void EndpointHostResolver::OnShutdown() {}

bool EndpointHostResolver::IsHappyEyeballsV3Enabled() const {
  return base::FeatureList::IsEnabled(net::features::kHappyEyeballsV3);
}

void EndpointHostResolver::SetRequestContext(net::URLRequestContext*) {}

std::unique_ptr<net::HostResolver::ProbeRequest>
EndpointHostResolver::CreateDohProbeRequest() {
  return net::HostResolver::CreateFailingProbeRequest(net::ERR_NOT_IMPLEMENTED);
}

std::unique_ptr<net::HostResolver::ResolveHostRequest>
EndpointHostResolver::CreateRequest(
    url::SchemeHostPort host,
    net::NetworkAnonymizationKey,
    net::handles::NetworkHandle,
    net::NetLogWithSource,
    std::optional<ResolveHostParameters>) {
  std::string name(host.host());
  auto resolved = registry_->Resolve(name);
  return std::make_unique<ImmediateResolveHostRequest>(
      resolved, std::move(name), host.port());
}

std::unique_ptr<net::HostResolver::ResolveHostRequest>
EndpointHostResolver::CreateRequest(
    const net::HostPortPair& host,
    const net::NetworkAnonymizationKey&,
    net::handles::NetworkHandle,
    const net::NetLogWithSource&,
    const std::optional<ResolveHostParameters>&) {
  std::string name = host.host();
  auto resolved = registry_->Resolve(name);
  return std::make_unique<ImmediateResolveHostRequest>(
      resolved, std::move(name), host.port());
}

std::unique_ptr<net::HostResolver::ServiceEndpointRequest>
EndpointHostResolver::CreateServiceEndpointRequest(
    Host host,
    net::NetworkAnonymizationKey,
    net::handles::NetworkHandle,
    net::NetLogWithSource,
    ResolveHostParameters) {
  std::string name(host.GetHostnameWithoutBrackets());
  auto resolved = registry_->Resolve(name);
  return std::make_unique<ImmediateServiceEndpointRequest>(
      resolved, std::move(name), host.GetPort());
}

EndpointSSLConfigService::EndpointSSLConfigService(
    scoped_refptr<EndpointRegistry> registry,
    bool default_strict_ech)
    : registry_(std::move(registry)),
      default_strict_ech_(default_strict_ech) {}

EndpointSSLConfigService::~EndpointSSLConfigService() = default;

net::EchMode EndpointSSLConfigService::GetEchMode(
    std::string_view hostname) const {
  if (default_strict_ech_) {
    return net::EchMode::kStrict;
  }
  if (registry_) {
    net::EchMode mode = registry_->GetEchMode(hostname);
    if (mode == net::EchMode::kStrict) {
      return net::EchMode::kStrict;
    }
  }
  return net::SSLConfigServiceDefaults::GetEchMode(hostname);
}

net::SSLContextConfig EndpointSSLConfigService::GetSSLContextConfig() {
  net::SSLContextConfig config =
      net::SSLConfigServiceDefaults::GetSSLContextConfig();
#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
  if (base::FeatureList::IsEnabled(net::features::kTLSTrustAnchorIDs)) {
    std::vector<std::vector<uint8_t>> ids;
    if (base::FeatureList::IsEnabled(net::features::kNonMtcTrustAnchorIDs)) {
      base::Extend(
          ids, net::TrustStoreChrome::GetTrustAnchorIDsFromCompiledInRootStore());
    }
    if (base::FeatureList::IsEnabled(net::features::kVerifyMTCs)) {
      base::Extend(
          ids, net::TrustStoreChrome::GetTrustedMtcCaIDsFromCompiledInRootStore());
    }
    config.trust_anchor_ids =
        net::x509_util::EncodeTlsRequestedTrustAnchorIDList(std::move(ids));
  }
#endif
  return config;
}

net::SSLConfig BuildChromeSslConfig(
    net::SSLClientContext* context,
    const std::vector<net::NextProto>& alpns,
    std::vector<uint8_t> ech_config_list) {
  net::SSLConfig config;
  if (alpns.empty()) {
    config.alpn_protos = {net::NextProto::kProtoHTTP2,
                          net::NextProto::kProtoHTTP11};
  } else {
    config.alpn_protos = alpns;
  }
  bool offers_h2 = false;
  for (net::NextProto proto : config.alpn_protos) {
    if (proto == net::NextProto::kProtoHTTP2) {
      offers_h2 = true;
      break;
    }
  }
  if (offers_h2 && base::FeatureList::IsEnabled(net::features::kAlpsForHttp2)) {
    config.application_settings[net::NextProto::kProtoHTTP2] = {};
  }
  config.renego_allowed_default = true;
  config.renego_allowed_for_protos = {net::NextProto::kProtoHTTP11};
  config.early_data_enabled =
      base::FeatureList::IsEnabled(net::features::kEnableTLS13EarlyData);
  const net::SSLContextConfig& context_config = context->config();
  if (context_config.ShouldAdvertiseTrustAnchorIDs()) {
    config.trust_anchor_ids = context_config.SelectAllTrustAnchorIDs();
  }
  config.server_padding_to_request = context_config.RequestServerPadding();
  config.ech_config_list = std::move(ech_config_list);
  return config;
}

std::vector<std::string> SplitCommaSeparatedAlpns(const char* csv) {
  if (!csv || *csv == '\0') {
    return {};
  }
  return base::SplitString(csv, ",", base::TRIM_WHITESPACE,
                           base::SPLIT_WANT_NONEMPTY);
}

std::vector<net::NextProto> ParseNextProtos(
    const std::vector<std::string>& alpns) {
  std::vector<net::NextProto> out;
  for (const auto& name : alpns) {
    net::NextProto proto = net::NextProtoFromString(name);
    if (proto != net::NextProto::kProtoUnknown) {
      out.push_back(proto);
    }
  }
  return out;
}

}  // namespace cronet
