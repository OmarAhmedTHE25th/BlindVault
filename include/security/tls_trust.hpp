#pragma once
// Makes the TLS handshake check WHO the other side is, by fingerprint, on both ends.

#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <boost/asio/ssl.hpp>

#include "trust_store.hpp"

namespace tls_trust {

enum class PeerVerdict {
    Trusted,
    UnknownPeer,        // a well-formed identity, but not on our trust list
    BadCertificate      // expired, not valid yet, or not a single self-signed certificate
};

PeerVerdict judge_peer(int depth, int openssl_error, const std::string& fingerprint,
                       const trust::TrustStore& store);

std::function<bool(bool, boost::asio::ssl::verify_context&)>
make_verifier(const std::shared_ptr<trust::TrustStore>& store,
              const std::string& log_prefix,
              const std::string& peer_word);

void load_identity(boost::asio::ssl::context& context);

void load_identity(boost::asio::ssl::context& context,
                   const std::filesystem::path& cert_file,
                   const std::filesystem::path& key_file,
                   const std::string& passphrase = "");

void configure_server(boost::asio::ssl::context& context,
                      const std::shared_ptr<trust::TrustStore>& store);

void configure_server(boost::asio::ssl::context& context,
                      const std::shared_ptr<trust::TrustStore>& store,
                      const std::filesystem::path& cert_file,
                      const std::filesystem::path& key_file,
                      const std::string& passphrase);

void configure_client(boost::asio::ssl::context& context,
                      const std::shared_ptr<trust::TrustStore>& store);

void configure_client(boost::asio::ssl::context& context,
                      const std::shared_ptr<trust::TrustStore>& store,
                      const std::filesystem::path& cert_file,
                      const std::filesystem::path& key_file,
                      const std::string& passphrase);

} // namespace tls_trust
