// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_CRONET_NATIVE_TLS_CLIENT_H_
#define COMPONENTS_CRONET_NATIVE_TLS_CLIENT_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "net/base/hash_value.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/x509_certificate.h"
#include "net/ssl/ssl_private_key.h"

struct Cronet_TlsConfig;

namespace cronet {

struct ConfiguredVerifier {
  std::unique_ptr<net::CertVerifier> verifier;
  raw_ptr<net::CertVerifierWithUpdatableProc> updatable = nullptr;
};

// Owned copy of a validated Cronet_TlsConfig so an engine can validate inputs
// synchronously before StartWithParams() while constructing the CertVerifier on
// the network thread (where SequencedTaskRunner::GetCurrentDefault() exists).
struct OwnedTlsConfig {
  OwnedTlsConfig();
  ~OwnedTlsConfig();
  OwnedTlsConfig(OwnedTlsConfig&&);
  OwnedTlsConfig& operator=(OwnedTlsConfig&&);

  bool insecure = false;
  std::string pem_root_certs;
  std::string verify_name;
  std::vector<net::SHA256HashValue> cert_pins;
  std::vector<net::SHA256HashValue> key_pins;
  scoped_refptr<net::X509Certificate> client_cert;
  scoped_refptr<net::SSLPrivateKey> client_key;
  std::string alpns_comma_separated;
  std::vector<uint8_t> ech_config_list;
  bool strict_ech = false;
  int64_t time_offset_ms = 0;
};

// Synchronously validates PEM root certificates, client identity, and pin
// arguments from `config`, populating `out` on success or `error` on failure.
bool ParseAndValidateTlsConfig(const Cronet_TlsConfig& config,
                               OwnedTlsConfig* out,
                               std::string* error);

// Builds a unified certificate verifier on a SequencedTaskRunner thread,
// supporting exclusive custom PEM roots, insecure bypass, verify_name override,
// SHA-256 certificate/SPKI pins, and network-time offset updates. Shared
// between Cronet_Engine and Cronet_TlsClient.
bool BuildConfiguredCertVerifier(const OwnedTlsConfig& config,
                                 const std::string& default_host,
                                 ConfiguredVerifier* out,
                                 std::string* error);

}  // namespace cronet

#endif  // COMPONENTS_CRONET_NATIVE_TLS_CLIENT_H_
