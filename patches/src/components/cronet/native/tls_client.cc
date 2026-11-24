// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/cronet/native/tls_client.h"

#include <limits.h>

#include <algorithm>
#include <map>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "components/cronet/native/endpoint_resolver.h"
#include "components/cronet/native/engine.h"
#include "components/cronet/native/include/cronet_c.h"
#include "components/cronet/native/stream_dialer.h"
#include "components/network_time/time_tracker/time_tracker.h"
#include "crypto/sha2.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/cert/asn1_util.h"
#include "net/cert/caching_cert_verifier.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/cert_verify_proc_builtin.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/coalescing_cert_verifier.h"
#include "net/cert/crl_set.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cert/internal/system_trust_store.h"
#include "net/cert/multi_threaded_cert_verifier.h"
#include "net/cert/x509_util.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/ssl_client_socket.h"
#include "net/ssl/openssl_private_key.h"
#include "net/ssl/ssl_client_session_cache.h"
#include "net/ssl/ssl_info.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "third_party/boringssl/src/include/openssl/bio.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/pem.h"
#include "third_party/boringssl/src/pki/cert_errors.h"
#include "third_party/boringssl/src/pki/parse_certificate.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"
#include "third_party/boringssl/src/pki/trust_store_collection.h"
#include "third_party/boringssl/src/pki/trust_store_in_memory.h"

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
#include "net/cert/internal/trust_store_chrome.h"
#endif

namespace cronet {

constexpr net::NetworkTrafficAnnotationTag kTlsClientTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("cronet_tls_client", R"(
      semantics {
        sender: "Cronet TLS Client"
        description: "TLS client connection over an embedder-provided stream."
        trigger: "Application initiates Cronet_TlsConn_Start."
        data: "Application payload."
        destination: OTHER
      }
      policy {
        cookies_allowed: NO
        setting: "Application configuration."
        policy_exception_justification: "Embedded library API."
      })");

namespace {

void WriteErrorBuffer(char* err_buf, size_t err_len, const std::string& msg) {
  if (!err_buf || err_len == 0) {
    return;
  }
  size_t n = std::min(msg.size(), err_len - 1);
  UNSAFE_TODO(memcpy(err_buf, msg.data(), n));
  UNSAFE_TODO(err_buf[n]) = '\0';
}

std::vector<net::SHA256HashValue> UnpackSha256Pins(const uint8_t* packed,
                                                   size_t count) {
  if (!packed || count == 0) {
    return {};
  }
  std::vector<net::SHA256HashValue> out(count);
  for (size_t i = 0; i < count; ++i) {
    base::span(out[i]).copy_from(
        UNSAFE_TODO(base::span(packed + i * 32, 32u)));
  }
  return out;
}

bool ParseClientIdentity(const uint8_t* cert_pem,
                         size_t cert_pem_len,
                         const uint8_t* key_data,
                         size_t key_data_len,
                         scoped_refptr<net::X509Certificate>* out_cert,
                         scoped_refptr<net::SSLPrivateKey>* out_key,
                         std::string* error) {
  net::CertificateList certs =
      net::X509Certificate::CreateCertificateListFromBytes(
          UNSAFE_TODO(base::span(cert_pem, cert_pem_len)),
          net::X509Certificate::FORMAT_AUTO);
  if (certs.empty()) {
    if (error) {
      *error = "client certificate failed to parse";
    }
    return false;
  }
  std::vector<std::string_view> der_chain;
  for (const auto& c : certs) {
    der_chain.push_back(
        net::x509_util::CryptoBufferAsStringPiece(c->cert_buffer()));
  }
  scoped_refptr<net::X509Certificate> chain =
      net::X509Certificate::CreateFromDERCertChain(der_chain);
  if (!chain) {
    if (error) {
      *error = "client certificate chain invalid";
    }
    return false;
  }

  bssl::UniquePtr<EVP_PKEY> pkey;
  CBS cbs;
  CBS_init(&cbs, key_data, key_data_len);
  pkey.reset(EVP_parse_private_key(&cbs));
  if (!pkey) {
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(key_data, key_data_len));
    if (bio) {
      pkey.reset(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    }
  }
  if (!pkey) {
    if (error) {
      *error = "client private key failed to parse";
    }
    return false;
  }

  *out_cert = std::move(chain);
  *out_key = net::WrapOpenSSLPrivateKey(std::move(pkey));
  return true;
}

class AcceptAnyCertVerifier final : public net::CertVerifier {
 public:
  int Verify(const RequestParams& params,
             net::CertVerifyResult* result,
             net::CompletionOnceCallback,
             std::unique_ptr<Request>*,
             const net::NetLogWithSource&) override {
    result->Reset();
    result->verified_cert = params.certificate();
    return net::OK;
  }

  void Verify2QwacBinding(
      const std::string&,
      const std::string&,
      const scoped_refptr<net::X509Certificate>&,
      base::OnceCallback<void(const scoped_refptr<net::X509Certificate>&)>
          callback,
      const net::NetLogWithSource&) override {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(std::move(callback), nullptr));
  }

  void SetConfig(const Config&) override {}
  void AddObserver(Observer*) override {}
  void RemoveObserver(Observer*) override {}
};

// Exclusive custom-root SystemTrustStore: trusts ONLY the anchors supplied by
// the caller, never platform/OS roots or the compiled-in Chrome Root Store.
// IsKnownRoot() returns false while IsLocallyTrustedRoot() returns true for
// custom anchors so private CAs are not subjected to WebPKI 398-day leaf
// validity or Certificate Transparency constraints.
class ExclusiveRootSystemTrustStore final : public net::SystemTrustStore {
 public:
  explicit ExclusiveRootSystemTrustStore(
      std::unique_ptr<bssl::TrustStoreInMemory> trust_store)
      : trust_store_(std::move(trust_store)) {}

  bssl::TrustStore* GetTrustStore() override { return trust_store_.get(); }

  bool IsKnownRoot(const bssl::ParsedCertificate*) const override {
    return false;
  }

  bool IsKnownMtcAnchor(const bssl::MTCAnchor*) const override { return false; }

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
  net::PlatformTrustStore* GetPlatformTrustStore() override { return nullptr; }

  bool IsLocallyTrustedRoot(
      const bssl::ParsedCertificate* trust_anchor) override {
    return trust_store_->Contains(trust_anchor);
  }

  int64_t chrome_root_store_version() const override { return 0; }

  std::optional<base::Time> signer_set_timestamp() const override {
    return std::nullopt;
  }

  std::optional<base::Time> mtc_metadata_update_time() const override {
    return std::nullopt;
  }

  base::span<const net::ChromeRootCertConstraints> GetChromeRootConstraints(
      const bssl::CertPathBuilderResultPath*) const override {
    return {};
  }

  const net::TrustStoreChrome::MtcAnchorExtraData* GetMTCAnchorData(
      base::span<const uint8_t>) const override {
    return nullptr;
  }

  std::optional<bssl::VerifyCertificateChainDelegate::MTCCosigner>
  GetMtcMirrorKey(base::span<const uint8_t>) const override {
    return std::nullopt;
  }

  bool IsMtcCosignerPolicySatisfied(
      const bssl::ParsedCertificate&,
      base::Time,
      const bssl::MTCAnchor*,
      base::span<const std::vector<uint8_t>>,
      const net::NetLogWithSource&) const override {
    return false;
  }

  std::optional<int32_t> GetCrsRootIdForCert(
      const bssl::CertPathBuilderResultPath*) const override {
    return std::nullopt;
  }

  bssl::TrustStore* eutl_trust_store() override {
    return &empty_eutl_trust_store_;
  }
#endif

 private:
  std::unique_ptr<bssl::TrustStoreInMemory> trust_store_;
#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
  bssl::TrustStoreCollection empty_eutl_trust_store_;
#endif
};

class ExclusiveRootProcFactory final : public net::CertVerifyProcFactory {
 public:
  explicit ExclusiveRootProcFactory(
      std::vector<std::shared_ptr<const bssl::ParsedCertificate>> anchors)
      : anchors_(std::move(anchors)) {}

  scoped_refptr<net::CertVerifyProc> CreateCertVerifyProc(
      scoped_refptr<net::CertNetFetcher> fetcher,
      const net::CertVerifyProc::ImplParams& impl,
      const net::CertVerifyProc::InstanceParams& instance) override {
    auto store = std::make_unique<bssl::TrustStoreInMemory>();
    for (const auto& anchor : anchors_) {
      store->AddTrustAnchorWithConstraints(anchor);
    }
    return net::CreateCertVerifyProcBuiltin(
        std::move(fetcher),
        impl.crl_set ? impl.crl_set : net::CRLSet::BuiltinCRLSet(),
        std::make_unique<net::DoNothingCTVerifier>(),
        base::MakeRefCounted<net::DefaultCTPolicyEnforcer>(),
        std::make_unique<ExclusiveRootSystemTrustStore>(std::move(store)),
        instance, impl.time_tracker);
  }

 private:
  ~ExclusiveRootProcFactory() override = default;
  std::vector<std::shared_ptr<const bssl::ParsedCertificate>> anchors_;
};

std::vector<std::shared_ptr<const bssl::ParsedCertificate>> ParseRootAnchors(
    std::string_view pem) {
  net::CertificateList certs =
      net::X509Certificate::CreateCertificateListFromBytes(
          base::as_byte_span(pem), net::X509Certificate::FORMAT_AUTO);
  std::vector<std::shared_ptr<const bssl::ParsedCertificate>> anchors;
  for (const auto& cert : certs) {
    bssl::CertErrors errors;
    auto parsed = bssl::ParsedCertificate::Create(
        bssl::UpRef(cert->cert_buffer()),
        net::x509_util::DefaultParseCertificateOptions(), &errors);
    if (parsed) {
      anchors.push_back(std::move(parsed));
    }
  }
  return anchors;
}

std::unique_ptr<net::MultiThreadedCertVerifier> CreateExclusiveRootVerifier(
    const std::vector<CRYPTO_BUFFER*>& buffers,
    const net::CertVerifyProc::ImplParams& impl) {
  std::vector<std::shared_ptr<const bssl::ParsedCertificate>> anchors;
  for (CRYPTO_BUFFER* buffer : buffers) {
    bssl::CertErrors errors;
    auto parsed = bssl::ParsedCertificate::Create(
        bssl::UpRef(buffer), net::x509_util::DefaultParseCertificateOptions(),
        &errors);
    if (parsed) {
      anchors.push_back(std::move(parsed));
    }
  }
  if (anchors.empty()) {
    return nullptr;
  }
  auto factory =
      base::MakeRefCounted<ExclusiveRootProcFactory>(std::move(anchors));
  net::CertVerifyProc::InstanceParams instance;
  auto proc = factory->CreateCertVerifyProc(nullptr, impl, instance);
  return std::make_unique<net::MultiThreadedCertVerifier>(std::move(proc),
                                                          std::move(factory));
}

class PinAndNameCertVerifier final : public net::CertVerifierWithUpdatableProc {
 public:
  PinAndNameCertVerifier(std::unique_ptr<net::CertVerifier> base,
                         net::CertVerifierWithUpdatableProc* base_proc,
                         std::string origin_host,
                         std::string verify_name,
                         std::vector<net::SHA256HashValue> cert_pins,
                         std::vector<net::SHA256HashValue> key_pins)
      : base_(std::move(base)),
        base_proc_(base_proc),
        origin_host_(std::move(origin_host)),
        verify_name_(std::move(verify_name)),
        cert_pins_(std::move(cert_pins)),
        key_pins_(std::move(key_pins)) {}

  int Verify(const RequestParams& params,
             net::CertVerifyResult* result,
             net::CompletionOnceCallback callback,
             std::unique_ptr<Request>* out_req,
             const net::NetLogWithSource& net_log) override {
    std::string_view target_name = params.hostname();
    if (!verify_name_.empty() &&
        (origin_host_.empty() || target_name == origin_host_)) {
      target_name = verify_name_;
    }
    RequestParams named(params.certificate(), target_name, params.flags(),
                        params.ocsp_response(), params.sct_list());
    if (base_) {
      return base_->Verify(named, result, std::move(callback), out_req,
                           net_log);
    }

    const net::X509Certificate& cert = *params.certificate();
    if (Contains(cert_pins_, net::X509Certificate::CalculateFingerprint256(
                                 cert.cert_buffer())) ||
        LeafSpkiMatches(cert)) {
      result->Reset();
      result->verified_cert = params.certificate();
      return net::OK;
    }

    for (const auto& buffer : cert.intermediate_buffers()) {
      net::SHA256HashValue digest =
          net::X509Certificate::CalculateFingerprint256(buffer.get());
      if (Contains(cert_pins_, digest)) {
        auto& rooted = rooted_[digest];
        if (!rooted) {
          rooted = CreateExclusiveRootVerifier({buffer.get()}, impl_);
        }
        if (rooted) {
          return rooted->Verify(named, result, std::move(callback), out_req,
                                net_log);
        }
      }
    }

    result->Reset();
    result->verified_cert = params.certificate();
    result->cert_status = net::CERT_STATUS_AUTHORITY_INVALID;
    return net::ERR_CERT_AUTHORITY_INVALID;
  }

  void Verify2QwacBinding(
      const std::string& binding,
      const std::string& hostname,
      const scoped_refptr<net::X509Certificate>& cert,
      base::OnceCallback<void(const scoped_refptr<net::X509Certificate>&)>
          callback,
      const net::NetLogWithSource& net_log) override {
    if (base_) {
      base_->Verify2QwacBinding(binding, hostname, cert, std::move(callback),
                                net_log);
      return;
    }
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(std::move(callback), nullptr));
  }

  void SetConfig(const Config& config) override {
    if (base_) {
      base_->SetConfig(config);
    }
  }

  void AddObserver(Observer* observer) override {
    if (base_) {
      base_->AddObserver(observer);
    }
  }

  void RemoveObserver(Observer* observer) override {
    if (base_) {
      base_->RemoveObserver(observer);
    }
  }

  void UpdateVerifyProcData(
      scoped_refptr<net::CertNetFetcher> fetcher,
      const net::CertVerifyProc::ImplParams& impl,
      const net::CertVerifyProc::InstanceParams& instance) override {
    impl_ = impl;
    if (base_proc_) {
      base_proc_->UpdateVerifyProcData(fetcher, impl, instance);
    }
    net::CertVerifyProc::InstanceParams empty_instance;
    for (auto& [digest, verifier] : rooted_) {
      if (verifier) {
        verifier->UpdateVerifyProcData(fetcher, impl, empty_instance);
      }
    }
  }

 private:
  static bool Contains(const std::vector<net::SHA256HashValue>& pins,
                       const net::SHA256HashValue& digest) {
    return std::find(pins.begin(), pins.end(), digest) != pins.end();
  }

  bool LeafSpkiMatches(const net::X509Certificate& cert) const {
    std::string_view spki;
    return !key_pins_.empty() &&
           net::asn1::ExtractSPKIFromDERCert(
               net::x509_util::CryptoBufferAsStringPiece(cert.cert_buffer()),
               &spki) &&
           Contains(key_pins_, crypto::SHA256Hash(base::as_byte_span(spki)));
  }

  std::unique_ptr<net::CertVerifier> base_;
  raw_ptr<net::CertVerifierWithUpdatableProc> base_proc_;
  const std::string origin_host_;
  const std::string verify_name_;
  const std::vector<net::SHA256HashValue> cert_pins_;
  const std::vector<net::SHA256HashValue> key_pins_;
  std::map<net::SHA256HashValue, std::unique_ptr<net::MultiThreadedCertVerifier>>
      rooted_;
  net::CertVerifyProc::ImplParams impl_;
};

void ApplyTimeOffset(net::CertVerifierWithUpdatableProc* updatable,
                     int64_t offset_ms) {
  if (!updatable) {
    return;
  }
  net::CertVerifyProc::ImplParams impl;
  if (offset_ms != 0) {
    base::Time now = base::Time::Now();
    impl.time_tracker.emplace(now, base::TimeTicks::Now(),
                              now + base::Milliseconds(offset_ms),
                              base::TimeDelta());
  }
  net::CertVerifyProc::InstanceParams instance;
  updatable->UpdateVerifyProcData(nullptr, impl, instance);
}

}  // namespace

OwnedTlsConfig::OwnedTlsConfig() = default;
OwnedTlsConfig::~OwnedTlsConfig() = default;
OwnedTlsConfig::OwnedTlsConfig(OwnedTlsConfig&&) = default;
OwnedTlsConfig& OwnedTlsConfig::operator=(OwnedTlsConfig&&) = default;

bool ParseAndValidateTlsConfig(const Cronet_TlsConfig& config,
                               OwnedTlsConfig* out,
                               std::string* error) {
  OwnedTlsConfig parsed;
  parsed.insecure = config.insecure;
  if (config.pem_root_certs && *config.pem_root_certs) {
    parsed.pem_root_certs = config.pem_root_certs;
    if (ParseRootAnchors(parsed.pem_root_certs).empty()) {
      if (error) {
        *error = "no valid root certificates in pem_root_certs";
      }
      return false;
    }
  }
  if (config.verify_name) {
    parsed.verify_name = config.verify_name;
  }
  if ((config.cert_pins_count > 0 && !config.cert_pins_sha256) ||
      (config.key_pins_count > 0 && !config.key_pins_sha256)) {
    if (error) {
      *error = "pin array pointer must be non-null when pin count is non-zero";
    }
    return false;
  }
  parsed.cert_pins =
      UnpackSha256Pins(config.cert_pins_sha256, config.cert_pins_count);
  parsed.key_pins =
      UnpackSha256Pins(config.key_pins_sha256, config.key_pins_count);

  if (config.client_cert_pem && config.client_cert_pem_len > 0) {
    if (!config.client_key_data || config.client_key_data_len == 0) {
      if (error) {
        *error = "client certificate requires private key";
      }
      return false;
    }
    if (!ParseClientIdentity(
            config.client_cert_pem, config.client_cert_pem_len,
            config.client_key_data, config.client_key_data_len,
            &parsed.client_cert, &parsed.client_key, error)) {
      return false;
    }
  }
  if (config.alpns_comma_separated) {
    parsed.alpns_comma_separated = config.alpns_comma_separated;
  }
  if (config.ech_config_list && config.ech_config_list_len > 0) {
    parsed.ech_config_list.assign(
        config.ech_config_list,
        UNSAFE_TODO(config.ech_config_list + config.ech_config_list_len));
  }
  parsed.strict_ech = config.strict_ech;
  parsed.time_offset_ms = config.time_offset_ms;
  *out = std::move(parsed);
  return true;
}

bool BuildConfiguredCertVerifier(const OwnedTlsConfig& config,
                                 const std::string& default_host,
                                 ConfiguredVerifier* out,
                                 std::string* error) {
  bool pinned = !config.cert_pins.empty() || !config.key_pins.empty();
  std::unique_ptr<net::CertVerifier> verifier;
  net::CertVerifierWithUpdatableProc* updatable = nullptr;

  if (config.insecure && !pinned) {
    verifier = std::make_unique<AcceptAnyCertVerifier>();
  } else if (!pinned && !config.pem_root_certs.empty()) {
    auto anchors = ParseRootAnchors(config.pem_root_certs);
    if (anchors.empty()) {
      if (error) {
        *error = "no valid root certificates in pem_root_certs";
      }
      return false;
    }
    auto factory =
        base::MakeRefCounted<ExclusiveRootProcFactory>(std::move(anchors));
    net::CertVerifyProc::ImplParams impl;
    net::CertVerifyProc::InstanceParams instance;
    auto proc = factory->CreateCertVerifyProc(nullptr, impl, instance);
    auto exclusive = std::make_unique<net::MultiThreadedCertVerifier>(
        std::move(proc), std::move(factory));
    updatable = exclusive.get();
    verifier = std::move(exclusive);
  } else if (!pinned) {
    auto inner = net::CertVerifier::CreateDefaultWithoutCaching(nullptr);
    updatable = inner.get();
    verifier = std::make_unique<net::CachingCertVerifier>(
        std::make_unique<net::CoalescingCertVerifier>(std::move(inner)));
  }

  if (!(config.insecure && !pinned) &&
      (pinned || !config.verify_name.empty())) {
    auto wrapper = std::make_unique<PinAndNameCertVerifier>(
        std::move(verifier), updatable, default_host, config.verify_name,
        config.cert_pins, config.key_pins);
    updatable = wrapper.get();
    verifier = std::move(wrapper);
  }

  if (!verifier) {
    if (error) {
      *error = "failed to construct certificate verifier";
    }
    return false;
  }

  if (config.time_offset_ms != 0 && updatable) {
    ApplyTimeOffset(updatable, config.time_offset_ms);
  }

  out->verifier = std::move(verifier);
  out->updatable = updatable;
  return true;
}

}  // namespace cronet

struct Cronet_TlsClient {
  scoped_refptr<base::SingleThreadTaskRunner> network_task_runner;
  cronet::EndpointSSLConfigService ssl_config_service;
  cronet::ConfiguredVerifier verifier;
  net::TransportSecurityState transport_security;
  net::SSLClientSessionCache session_cache{
      net::SSLClientSessionCache::Config()};
  std::unique_ptr<net::SSLClientContext> ssl_context;
  std::vector<net::NextProto> alpns;
  std::vector<uint8_t> default_ech_config_list;
  bool strict_ech = false;

  Cronet_TlsClient(scoped_refptr<base::SingleThreadTaskRunner> runner,
                   bool strict)
      : network_task_runner(std::move(runner)),
        ssl_config_service(nullptr, strict),
        strict_ech(strict) {}
};

struct Cronet_TlsConn {
  raw_ptr<Cronet_TlsClient> client;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner;
  std::string host;
  uint16_t port;
  std::vector<uint8_t> ech_config_list;
  scoped_refptr<cronet::LowerStreamBridge> bridge;
  Cronet_TlsConnCallbacks callbacks;
  raw_ptr<void> callback_ctx;

  Cronet_LowerStream lower_stream{};
  bool lower_attached = false;
  raw_ptr<cronet::LowerStreamSocket> lower_socket = nullptr;
  std::unique_ptr<net::SSLClientSocket> ssl;
  bool connected = false;
  bool destroyed = false;

  scoped_refptr<net::GrowableIOBuffer> read_buf;
  bool read_in_flight = false;

  scoped_refptr<net::IOBufferWithSize> write_buf;
  bool write_in_flight = false;

  base::WeakPtrFactory<Cronet_TlsConn> weak_factory{this};

  void StartOnNetworkThread(Cronet_LowerStream stream) {
    DCHECK(task_runner->BelongsToCurrentThread());
    if (destroyed) {
      if (stream.close) {
        stream.close(stream.context);
      }
      return;
    }
    lower_stream = stream;
    lower_attached = true;

    net::IPEndPoint peer(net::IPAddress::IPv4Localhost(), port);
    auto socket = std::make_unique<cronet::LowerStreamSocket>(
        lower_stream, cronet::NextStreamConnectionId(), peer, nullptr,
        net::NetLogSource());
    lower_socket = socket.get();
    bridge->AttachSocket(socket->GetWeakPtr());

    const std::vector<uint8_t>& ech =
        !ech_config_list.empty() ? ech_config_list
                                 : client->default_ech_config_list;
    ssl = client->ssl_context->CreateSSLClientSocket(
        std::move(socket), net::HostPortPair(host, port),
        cronet::BuildChromeSslConfig(client->ssl_context.get(), client->alpns,
                                     ech));
    int rv = ssl->Connect(base::BindOnce(&Cronet_TlsConn::OnHandshakeDone,
                                         weak_factory.GetWeakPtr()));
    if (rv != net::ERR_IO_PENDING) {
      task_runner->PostTask(FROM_HERE,
                            base::BindOnce(&Cronet_TlsConn::OnHandshakeDone,
                                           weak_factory.GetWeakPtr(), rv));
    }
  }

  void OnHandshakeDone(int rv) {
    DCHECK(task_runner->BelongsToCurrentThread());
    if (destroyed) {
      return;
    }
    connected = (rv == net::OK);
    std::string alpn;
    bool ech_accepted = false;
    std::vector<uint8_t> retry_configs;

    if (connected) {
      net::NextProto proto = ssl->GetNegotiatedProtocol();
      if (proto != net::NextProto::kProtoUnknown) {
        alpn = std::string(net::NextProtoToString(proto));
      }
      net::SSLInfo info;
      if (ssl->GetSSLInfo(&info)) {
        ech_accepted = info.encrypted_client_hello;
      }
    } else if (rv == net::ERR_ECH_NOT_NEGOTIATED && !client->strict_ech) {
      retry_configs = ssl->GetECHRetryConfigs();
    }

    if (callbacks.on_handshake) {
      callbacks.on_handshake(
          callback_ctx, rv, alpn.c_str(), ech_accepted,
          retry_configs.empty() ? nullptr : retry_configs.data(),
          retry_configs.size());
    }
  }

  void ReadOnNetworkThread(size_t max_bytes) {
    DCHECK(task_runner->BelongsToCurrentThread());
    if (destroyed || !connected || read_in_flight || !ssl) {
      return;
    }
    if (lower_socket) {
      lower_socket->Retry(Cronet_LowerReady_READABLE);
    }
    int cap = static_cast<int>(std::min<size_t>(max_bytes, 64 * 1024));
    if (!read_buf) {
      read_buf = base::MakeRefCounted<net::GrowableIOBuffer>();
    }
    if (read_buf->capacity() < cap) {
      read_buf->SetCapacity(cap);
    }
    read_buf->set_offset(0);
    read_in_flight = true;

    int rv = ssl->Read(read_buf.get(), cap,
                       base::BindOnce(&Cronet_TlsConn::OnReadCompleted,
                                      weak_factory.GetWeakPtr()));
    if (rv != net::ERR_IO_PENDING) {
      OnReadCompleted(rv);
    }
  }

  void OnReadCompleted(int rv) {
    DCHECK(task_runner->BelongsToCurrentThread());
    if (destroyed) {
      return;
    }
    read_in_flight = false;
    if (rv == net::ERR_CONNECTION_CLOSED) {
      rv = 0;
    }
    const uint8_t* data = (rv > 0 && read_buf) ? read_buf->bytes() : nullptr;
    if (callbacks.on_read_completed) {
      callbacks.on_read_completed(callback_ctx, data, rv);
    }
  }

  void WriteOnNetworkThread(scoped_refptr<net::IOBufferWithSize> buf) {
    DCHECK(task_runner->BelongsToCurrentThread());
    if (destroyed || !connected || !ssl) {
      return;
    }
    if (lower_socket) {
      lower_socket->Retry(Cronet_LowerReady_WRITABLE);
    }
    if (write_in_flight) {
      if (callbacks.on_write_completed) {
        callbacks.on_write_completed(callback_ctx, net::ERR_INVALID_ARGUMENT);
      }
      return;
    }
    int len = buf->size();
    write_buf = std::move(buf);
    write_in_flight = true;
    int rv = ssl->Write(write_buf.get(), len,
                        base::BindOnce(&Cronet_TlsConn::OnWriteCompleted,
                                       weak_factory.GetWeakPtr()),
                        cronet::kTlsClientTrafficAnnotation);
    if (rv != net::ERR_IO_PENDING) {
      OnWriteCompleted(rv);
    }
  }

  void OnWriteCompleted(int rv) {
    DCHECK(task_runner->BelongsToCurrentThread());
    if (destroyed) {
      return;
    }
    if (rv > 0 && lower_socket && lower_socket->write_pending()) {
      lower_socket->WhenWriteDrained(
          base::BindOnce(&Cronet_TlsConn::OnLowerWriteDrained,
                         weak_factory.GetWeakPtr(), rv));
      return;
    }
    FinishWrite(rv);
  }

  void OnLowerWriteDrained(int plaintext_bytes, int lower_status) {
    DCHECK(task_runner->BelongsToCurrentThread());
    if (destroyed) {
      return;
    }
    FinishWrite(lower_status < 0 ? lower_status : plaintext_bytes);
  }

  void FinishWrite(int rv) {
    write_in_flight = false;
    write_buf = nullptr;
    if (callbacks.on_write_completed) {
      callbacks.on_write_completed(callback_ctx, rv);
    }
  }

  void DestroyOnNetworkThread() {
    DCHECK(task_runner->BelongsToCurrentThread());
    destroyed = true;
    weak_factory.InvalidateWeakPtrs();
    read_buf = nullptr;
    write_buf = nullptr;
    bool closed_via_socket = (lower_socket != nullptr);
    lower_socket = nullptr;
    ssl.reset();
    if (lower_attached && !closed_via_socket && lower_stream.close) {
      lower_stream.close(lower_stream.context);
    }
    if (callbacks.on_closed) {
      callbacks.on_closed(callback_ctx);
    }
    delete this;
  }
};

CRONET_EXPORT Cronet_TlsClient* Cronet_TlsClient_Create(
    Cronet_EnginePtr engine,
    const Cronet_TlsConfig* config,
    char* err_buf,
    size_t err_len) {
  if (!engine || !config) {
    cronet::WriteErrorBuffer(err_buf, err_len,
                             "engine and config must be non-null");
    return nullptr;
  }
  auto* engine_impl = static_cast<cronet::Cronet_EngineImpl*>(engine);
  auto runner = engine_impl->GetNetworkTaskRunner();
  if (!runner) {
    cronet::WriteErrorBuffer(err_buf, err_len,
                             "engine must be started before creating TlsClient");
    return nullptr;
  }

  cronet::OwnedTlsConfig owned;
  std::string error;
  if (!cronet::ParseAndValidateTlsConfig(*config, &owned, &error)) {
    cronet::WriteErrorBuffer(err_buf, err_len, error);
    return nullptr;
  }

  auto client = std::make_unique<Cronet_TlsClient>(runner, owned.strict_ech);
  client->alpns = cronet::ParseNextProtos(
      cronet::SplitCommaSeparatedAlpns(owned.alpns_comma_separated.c_str()));
  client->default_ech_config_list = std::move(owned.ech_config_list);

  bool ok = false;
  auto init_on_network_thread = [](Cronet_TlsClient* raw,
                                   cronet::OwnedTlsConfig* cfg,
                                   bool* out_ok,
                                   std::string* out_err) {
    if (!cronet::BuildConfiguredCertVerifier(*cfg, "", &raw->verifier,
                                             out_err)) {
      *out_ok = false;
      return;
    }
    raw->ssl_context = std::make_unique<net::SSLClientContext>(
        &raw->ssl_config_service, raw->verifier.verifier.get(),
        &raw->transport_security, &raw->session_cache, nullptr);
    if (cfg->client_cert && cfg->client_key) {
      raw->ssl_context->SetDefaultClientCertificate(
          std::move(cfg->client_cert), std::move(cfg->client_key));
    }
    *out_ok = true;
  };

  if (runner->BelongsToCurrentThread()) {
    init_on_network_thread(client.get(), &owned, &ok, &error);
  } else {
    base::WaitableEvent done;
    runner->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](Cronet_TlsClient* raw, cronet::OwnedTlsConfig* cfg,
               void (*init)(Cronet_TlsClient*, cronet::OwnedTlsConfig*, bool*,
                            std::string*),
               bool* out_ok, std::string* out_err, base::WaitableEvent* event) {
              init(raw, cfg, out_ok, out_err);
              event->Signal();
            },
            client.get(), &owned, init_on_network_thread, &ok, &error, &done));
    done.Wait();
  }
  if (!ok) {
    cronet::WriteErrorBuffer(err_buf, err_len, error);
    return nullptr;
  }

  return client.release();
}

CRONET_EXPORT void Cronet_TlsClient_SetTimeOffset(Cronet_TlsClient* client,
                                                  int64_t offset_ms) {
  if (!client || !client->verifier.updatable) {
    return;
  }
  auto* updatable = client->verifier.updatable.get();
  auto runner = client->network_task_runner;
  auto apply = [](net::CertVerifierWithUpdatableProc* proc, int64_t ms) {
    cronet::ApplyTimeOffset(proc, ms);
  };
  if (runner->BelongsToCurrentThread()) {
    apply(updatable, offset_ms);
  } else {
    runner->PostTask(FROM_HERE, base::BindOnce(apply, updatable, offset_ms));
  }
}

CRONET_EXPORT void Cronet_TlsClient_Destroy(Cronet_TlsClient* client) {
  if (!client) {
    return;
  }
  auto runner = client->network_task_runner;
  if (runner->BelongsToCurrentThread()) {
    delete client;
  } else {
    runner->DeleteSoon(FROM_HERE, client);
  }
}

CRONET_EXPORT Cronet_TlsConn* Cronet_TlsConn_Create(
    Cronet_TlsClient* client,
    const char* host,
    uint16_t port,
    const uint8_t* ech_config_list,
    size_t ech_config_list_len,
    const Cronet_TlsConnCallbacks* callbacks,
    void* callback_context,
    Cronet_LowerStreamHandle** out_lower_handle) {
  if (!client || !host || !callbacks) {
    return nullptr;
  }
  auto bridge = base::MakeRefCounted<cronet::LowerStreamBridge>(
      client->network_task_runner);
  if (out_lower_handle) {
    *out_lower_handle = cronet::CreateLowerStreamHandle(bridge);
  }
  auto* conn = new Cronet_TlsConn{
      client,
      client->network_task_runner,
      std::string(host),
      port ? port : static_cast<uint16_t>(443),
      ech_config_list && ech_config_list_len > 0
          ? std::vector<uint8_t>(
                ech_config_list,
                UNSAFE_TODO(ech_config_list + ech_config_list_len))
          : std::vector<uint8_t>(),
      std::move(bridge),
      *callbacks,
      callback_context};
  return conn;
}

CRONET_EXPORT void Cronet_TlsConn_Start(
    Cronet_TlsConn* conn,
    const Cronet_LowerStream* lower_stream) {
  if (!conn || !lower_stream) {
    return;
  }
  conn->task_runner->PostTask(
      FROM_HERE, base::BindOnce(&Cronet_TlsConn::StartOnNetworkThread,
                                base::Unretained(conn), *lower_stream));
}

CRONET_EXPORT void Cronet_TlsConn_Read(Cronet_TlsConn* conn, size_t max_bytes) {
  if (!conn || max_bytes == 0) {
    return;
  }
  conn->task_runner->PostTask(
      FROM_HERE, base::BindOnce(&Cronet_TlsConn::ReadOnNetworkThread,
                                base::Unretained(conn), max_bytes));
}

CRONET_EXPORT void Cronet_TlsConn_Write(Cronet_TlsConn* conn,
                                        const uint8_t* data,
                                        size_t length) {
  if (!conn) {
    return;
  }
  size_t clamped = std::min<size_t>(length, INT_MAX);
  auto buf = base::MakeRefCounted<net::IOBufferWithSize>(clamped);
  if (clamped > 0 && data) {
    buf->span().copy_from(UNSAFE_TODO(base::span(data, clamped)));
  }
  conn->task_runner->PostTask(
      FROM_HERE, base::BindOnce(&Cronet_TlsConn::WriteOnNetworkThread,
                                base::Unretained(conn), std::move(buf)));
}

CRONET_EXPORT void Cronet_TlsConn_Destroy(Cronet_TlsConn* conn) {
  if (!conn) {
    return;
  }
  conn->task_runner->PostTask(
      FROM_HERE, base::BindOnce(&Cronet_TlsConn::DestroyOnNetworkThread,
                                base::Unretained(conn)));
}
