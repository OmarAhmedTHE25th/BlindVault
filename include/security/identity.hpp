#pragma once
// A node's own identity: a private key plus a self-signed certificate made from it.
// Nobody vouches for the certificate. Other peers recognize it by its FINGERPRINT,
// which they get from you through a channel they trust and then write in their trust list.

#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <openssl/bio.h>
#include <openssl/x509.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "OpenSSL 3.0 or newer is required"
#endif

namespace identity {

inline constexpr const char* CERT_FILE  = "identity.crt";
inline constexpr const char* KEY_FILE   = "identity.key";
inline constexpr const char* TRUST_FILE = "trusted_peers.txt";

namespace detail {
using FilePtr = std::unique_ptr<FILE, int (*)(FILE*)>;
using BioPtr  = std::unique_ptr<BIO, int (*)(BIO*)>;

FILE* open_private_file(const std::filesystem::path& path);
std::string read_file(const std::filesystem::path& path);
void write_private_file(const std::filesystem::path& path, const std::string& bytes);
std::string bio_contents(BIO* bio);
} // namespace detail

// SHA-256 of the certificate (its DER encoding), as 64 lowercase hex characters
std::string fingerprint_of(const X509* cert);
std::string fingerprint_of_file(const std::filesystem::path& cert_path);

// Can this key file be opened with this passphrase? (empty passphrase = unencrypted key)
bool private_key_loads(const std::filesystem::path& key_path, const std::string& passphrase);

// Creates a new identity: an EC P-256 key and a certificate for it, valid for ten years.
void generate(const std::filesystem::path& cert_path, const std::filesystem::path& key_path,
              const std::string& common_name, const std::string& passphrase = "",
              bool overwrite = false);

} // namespace identity
