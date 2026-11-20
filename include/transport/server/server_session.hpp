#ifndef P2P_SECURE_FILE_SHARING_SERVER_SESSION_HPP
#define P2P_SECURE_FILE_SHARING_SERVER_SESSION_HPP

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/evp.h>

#include "disk_budget.hpp"
#include "events.hpp"
#include "file_streaming.hpp"
#include "protocol.hpp"

class ServerSession : public std::enable_shared_from_this<ServerSession> {
public:
    using SSLStream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;

    ServerSession(std::shared_ptr<SSLStream> socket,
                  std::filesystem::path save_dir,
                  std::shared_ptr<void> connection_slot,
                  std::shared_ptr<DiskBudget> disk_budget,
                  TransferEvents events = {});

    ~ServerSession();

    void start();

private:
    void start_timeout();
    void reset_timeout();
    void read_header();
    void handle_header();
    void read_filename();
    void prepare_receive();
    void read_next_chunk();
    void handle_chunk(std::size_t n);
    void read_eof_header();
    void finish_transfer();
    void reject(AckStatus status, const std::string& reason);
    void shutdown_tls();
    void send_ack(AckStatus status, std::function<void()> on_sent = nullptr);
    void report_done(bool ok, const std::string& msg);

    std::shared_ptr<SSLStream> socket_;
    boost::asio::steady_timer timer_;
    std::filesystem::path final_path_;
    std::filesystem::path temp_path_;
    std::ofstream part_file_;
    std::vector<char> buffer_;
    uint64_t bytes_received_ = 0;
    bool finished_ = false;
    FileStreamer::EVP_MD_CTX_ptr hash_ctx_{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
    PacketHeader eof_header_{};
    PacketHeader ack_header_{};
    uint8_t ack_status_ = 0;
    std::filesystem::path save_dir_;
    PacketHeader header_{};
    std::string raw_name_;
    std::string safe_name_;
    uint64_t file_size_ = 0;
    std::shared_ptr<void> connection_slot_;
    std::shared_ptr<DiskBudget> disk_budget_;
    DiskBudget::Reservation reservation_;
    TransferEvents events_;
    int last_pct_ = -1;
    bool reported_ = false;
};

#endif // P2P_SECURE_FILE_SHARING_SERVER_SESSION_HPP
