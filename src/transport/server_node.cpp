#include "server_node.hpp"

#include <iostream>
#include <openssl/x509.h>

#include "identity.hpp"

namespace net = boost::asio;
namespace fs = std::filesystem;

ServerNode::ServerNode(net::io_context& io_ctx,
                       net::ssl::context& ssl_ctx,
                       uint16_t port,
                       fs::path save_dir,
                       std::shared_ptr<trust::TrustStore> trust_store,
                       TransferEvents events)
    : io_ctx_(io_ctx),
      ssl_ctx_(ssl_ctx),
      acceptor_(io_ctx, net::ip::tcp::endpoint(net::ip::tcp::v4(), port)),
      save_dir_(std::move(save_dir)),
      trust_store_(trust_store ? std::move(trust_store)
                               : std::make_shared<trust::TrustStore>(identity::TRUST_FILE)),
      events_(std::move(events)) {}

uint16_t ServerNode::port() const {
    return acceptor_.local_endpoint().port();
}

void ServerNode::start() {
    std::cout << "[SERVER] Listening on port " << acceptor_.local_endpoint().port()
              << ", saving files to: " << save_dir_.string() << '\n';
    accept_next();
}

void ServerNode::accept_next() {
    auto socket = std::make_shared<SSLStream>(io_ctx_, ssl_ctx_);
    acceptor_.async_accept(socket->lowest_layer(),
        [self = shared_from_this(), socket](const boost::system::error_code& ec) {
            if (ec == net::error::operation_aborted) return;
            if (ec) {
                std::cerr << "[SERVER ERROR] Accept failed: " << ec.message() << '\n';
            } else if (self->active_connections_->load() >= MAX_CONNECTIONS) {
                std::cerr << "[SERVER] Too many connections (" << MAX_CONNECTIONS
                          << "), dropping a new peer\n";
            } else {
                self->handshake(socket);
            }
            self->accept_next();
        });
}

void ServerNode::handshake(const std::shared_ptr<SSLStream>& socket) {
    auto slot = std::make_shared<ConnectionSlot>(active_connections_);

    auto timer = std::make_shared<net::steady_timer>(io_ctx_);
    timer->expires_after(HANDSHAKE_TIMEOUT);
    timer->async_wait([socket](const boost::system::error_code& ec) {
        if (ec) return;
        std::cerr << "[SERVER] TLS handshake timed out, dropping peer\n";
        boost::system::error_code ignored_ec;
        socket->lowest_layer().close(ignored_ec);
    });

    socket->async_handshake(net::ssl::stream_base::server,
        [self = shared_from_this(), socket, timer, slot](const boost::system::error_code& ec) {
            timer->cancel();
            if (ec) {
                if (ec != net::error::operation_aborted) {
                    std::cerr << "[SERVER ERROR] Handshake failed: " << ec.message() << '\n';
                }
                return;
            }

            X509* cert = SSL_get_peer_certificate(socket->native_handle());
            if (cert) {
                try {
                    const std::string fp = identity::fingerprint_of(cert);
                    const std::string shown_fp = trust::display_fingerprint(fp);
                    if (auto name = self->trust_store_->find_name(fp)) {
                        std::cout << "[SERVER] Authenticated peer '" << *name
                                  << "' (fingerprint: " << shown_fp << ")\n";
                    } else {
                        std::cout << "[SERVER] Authenticated peer (fingerprint: " << shown_fp << ")\n";
                    }
                } catch (...) {}
                X509_free(cert);
            }

            std::cout << "[SERVER] TLS handshake OK. Channel is secure.\n";
            std::make_shared<ServerSession>(socket, self->save_dir_, slot, self->disk_budget_, self->events_)->start();
        });
}
