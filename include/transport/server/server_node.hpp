#ifndef P2P_SECURE_FILE_SHARING_SERVER_NODE_HPP
#define P2P_SECURE_FILE_SHARING_SERVER_NODE_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "disk_budget.hpp"
#include "events.hpp"
#include "server_session.hpp"
#include "trust_store.hpp"

class ConnectionSlot {
public:
    explicit ConnectionSlot(std::shared_ptr<std::atomic<std::size_t>> counter)
        : counter_(std::move(counter)) { ++*counter_; }
    ConnectionSlot(const ConnectionSlot&) = delete;
    ConnectionSlot& operator=(const ConnectionSlot&) = delete;
    ~ConnectionSlot() { --*counter_; }
private:
    std::shared_ptr<std::atomic<std::size_t>> counter_;
};

class ServerNode : public std::enable_shared_from_this<ServerNode> {
public:
    using SSLStream = ServerSession::SSLStream;

    static constexpr std::size_t MAX_CONNECTIONS = 64;
    static constexpr std::chrono::seconds HANDSHAKE_TIMEOUT{10};

    ServerNode(boost::asio::io_context& io_ctx,
               boost::asio::ssl::context& ssl_ctx,
               uint16_t port,
               std::filesystem::path save_dir,
               std::shared_ptr<trust::TrustStore> trust_store = nullptr,
               TransferEvents events = {});

    [[nodiscard]] uint16_t port() const;
    void start();

private:
    void accept_next();
    void handshake(const std::shared_ptr<SSLStream>& socket);

    boost::asio::io_context& io_ctx_;
    boost::asio::ssl::context& ssl_ctx_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::filesystem::path save_dir_;
    std::shared_ptr<trust::TrustStore> trust_store_;
    std::shared_ptr<std::atomic<std::size_t>> active_connections_ =
        std::make_shared<std::atomic<std::size_t>>(0);
    std::shared_ptr<DiskBudget> disk_budget_ = std::make_shared<DiskBudget>();
    TransferEvents events_;
};

#endif // P2P_SECURE_FILE_SHARING_SERVER_NODE_HPP
