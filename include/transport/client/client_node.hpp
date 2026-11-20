#pragma once

#include <cstdint>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "events.hpp"
#include "protocol.hpp"
#include "trust_store.hpp"

class ClientNode : public std::enable_shared_from_this<ClientNode> {
public:
    using SSLStream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;

    ClientNode(boost::asio::io_context& io_ctx,
               boost::asio::ssl::context& ssl_ctx,
               TransferEvents events = {},
               std::shared_ptr<trust::TrustStore> store = nullptr);

    void send_file(const std::string& port, const std::string& host, const std::string& file_path);
    [[nodiscard]] bool succeeded() const noexcept { return succeeded_; }

private:
    void log(const std::string& msg, bool error = false);
    void finish(const std::string& reason = "");
    bool handle_unknown_ca(const boost::system::error_code& ec);
    void arm_timeout();
    void start_timeout() { arm_timeout(); }
    void reset_timeout() { arm_timeout(); }

    void connect(const boost::asio::ip::tcp::resolver::results_type& endpoints);
    void handshake();
    void prepare_and_send_header();
    void send_filename_payload();
    void read_reply(std::function<void(AckStatus)> handler);

    void open_file_and_stream();
    void report_progress();
    void stream_next_chunk();
    void send_end_of_file_signal();

    boost::asio::steady_timer timer_;
    boost::asio::ip::tcp::resolver resolver_;
    SSLStream ssl_socket_;
    TransferEvents events_;
    std::shared_ptr<trust::TrustStore> store_;

    std::string file_name_;
    std::string file_path_;
    PacketHeader header_{};
    PacketHeader eof_header_{};
    PacketHeader ack_header_{};
    uint8_t ack_status_ = 0;
    std::ifstream file_stream_;
    std::vector<char> buffer_;
    uint64_t total_size_ = 0;
    uint64_t bytes_sent_ = 0;
    int last_progress_ = -1;
    bool succeeded_ = false;
    bool done_ = false;
};
