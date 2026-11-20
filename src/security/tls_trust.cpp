#include "tls_trust.hpp"

#include <iostream>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "cli_identity.hpp"
#include "identity.hpp"

namespace tls_trust {

PeerVerdict judge_peer(int depth, int openssl_error, const std::string& fingerprint,
                       const trust::TrustStore& store) {
    if (depth != 0) return PeerVerdict::BadCertificate;
    if (openssl_error != X509_V_OK && openssl_error != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
        return PeerVerdict::BadCertificate;
    }
    return store.is_trusted(fingerprint) ? PeerVerdict::Trusted : PeerVerdict::UnknownPeer;
}

std::function<bool(bool, boost::asio::ssl::verify_context&)>
make_verifier(const std::shared_ptr<trust::TrustStore>& store,
              const std::string& log_prefix,
              const std::string& peer_word) {
    return [store, log_prefix, peer_word](bool /*openssl's own verdict, replaced by ours*/,
                                          boost::asio::ssl::verify_context& context) -> bool {
        try {
            X509_STORE_CTX* state = context.native_handle();
            const X509* cert = X509_STORE_CTX_get_current_cert(state);
            if (!cert) return false;
            const int depth = X509_STORE_CTX_get_error_depth(state);
            const int error = X509_STORE_CTX_get_error(state);
            const std::string fingerprint = identity::fingerprint_of(cert);

            switch (judge_peer(depth, error, fingerprint, *store)) {
                case PeerVerdict::Trusted:
                    return true;
                case PeerVerdict::UnknownPeer:
                    std::cerr << log_prefix << " Refused the " << peer_word
                              << ": its fingerprint is not in your trust list.\n"
                              << log_prefix << " Fingerprint: " << trust::display_fingerprint(fingerprint) << '\n'
                              << log_prefix << " If you have checked with its owner (a call, or a message you know "
                                               "is really theirs) that this is their fingerprint, trust it with:\n"
                              << log_prefix << "   BlindVault trust add "
                              << trust::display_fingerprint(fingerprint) << " <name>\n";
                    return false;
                case PeerVerdict::BadCertificate:
                    std::cerr << log_prefix << " Refused the " << peer_word << ": its certificate cannot be used ("
                              << X509_verify_cert_error_string(error) << ", depth " << depth << ").\n";
                    return false;
            }
        } catch (...) {
            // never let an exception escape into OpenSSL; when in doubt, refuse
        }
        return false;
    };
}

void load_identity(boost::asio::ssl::context& context) {
    context.set_password_callback([](std::size_t /*max_length*/, boost::asio::ssl::context_base::password_purpose /*purpose*/) -> std::string {
        return cli::detail::read_password("Enter passphrase to unlock identity.key: ");
    });

    context.use_certificate_chain_file(identity::CERT_FILE);
    context.use_private_key_file(identity::KEY_FILE, boost::asio::ssl::context::pem);
}

void load_identity(boost::asio::ssl::context& context,
                   const std::filesystem::path& cert_file,
                   const std::filesystem::path& key_file,
                   const std::string& passphrase) {
    context.set_password_callback([passphrase](std::size_t, boost::asio::ssl::context_base::password_purpose) {
        return passphrase;
    });
    const std::string cert_pem = identity::detail::read_file(cert_file);
    const std::string key_pem  = identity::detail::read_file(key_file);
    context.use_certificate_chain(boost::asio::buffer(cert_pem));
    context.use_private_key(boost::asio::buffer(key_pem), boost::asio::ssl::context::pem);
}

void configure_server(boost::asio::ssl::context& context, const std::shared_ptr<trust::TrustStore>& store) {
    context.set_options(boost::asio::ssl::context::default_workarounds |
                        boost::asio::ssl::context::no_sslv2 |
                        boost::asio::ssl::context::no_sslv3 |
                        boost::asio::ssl::context::single_dh_use);
    load_identity(context);
    context.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert);
    context.set_verify_callback(make_verifier(store, "[SERVER]", "sender"));
}

void configure_server(boost::asio::ssl::context& context,
                      const std::shared_ptr<trust::TrustStore>& store,
                      const std::filesystem::path& cert_file,
                      const std::filesystem::path& key_file,
                      const std::string& passphrase) {
    context.set_options(boost::asio::ssl::context::default_workarounds |
                        boost::asio::ssl::context::no_sslv2 |
                        boost::asio::ssl::context::no_sslv3 |
                        boost::asio::ssl::context::single_dh_use);
    load_identity(context, cert_file, key_file, passphrase);
    context.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert);
    context.set_verify_callback(make_verifier(store, "[SERVER]", "sender"));
}

void configure_client(boost::asio::ssl::context& context, const std::shared_ptr<trust::TrustStore>& store) {
    context.set_options(boost::asio::ssl::context::default_workarounds |
                        boost::asio::ssl::context::no_sslv2 |
                        boost::asio::ssl::context::no_sslv3);
    load_identity(context);
    context.set_verify_mode(boost::asio::ssl::verify_peer);
    context.set_verify_callback(make_verifier(store, "[CLIENT]", "receiver"));
}

void configure_client(boost::asio::ssl::context& context,
                      const std::shared_ptr<trust::TrustStore>& store,
                      const std::filesystem::path& cert_file,
                      const std::filesystem::path& key_file,
                      const std::string& passphrase) {
    context.set_options(boost::asio::ssl::context::default_workarounds |
                        boost::asio::ssl::context::no_sslv2 |
                        boost::asio::ssl::context::no_sslv3);
    load_identity(context, cert_file, key_file, passphrase);
    context.set_verify_mode(boost::asio::ssl::verify_peer);
    context.set_verify_callback(make_verifier(store, "[CLIENT]", "receiver"));
}

} // namespace tls_trust
