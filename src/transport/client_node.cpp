#include "client_node.hpp"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <boost/endian/conversion.hpp>

#include "file_streaming.hpp"
#include "identity.hpp"

namespace net = boost::asio;
using tcp = net::ip::tcp;

ClientNode::ClientNode(net::io_context& io_ctx,
                       net::ssl::context& ssl_ctx,
                       TransferEvents events,
                       std::shared_ptr<trust::TrustStore> store)
    : timer_(io_ctx),
      resolver_(io_ctx),
      ssl_socket_(io_ctx, ssl_ctx),
      events_(std::move(events)),
      store_(std::move(store)) {}

void ClientNode::send_file(const std::string& port, const std::string& host, const std::string& file_path) {
    succeeded_ = false;
    file_path_ = file_path;
    start_timeout();
    resolver_.async_resolve(host, port,
        [self = shared_from_this()](const boost::system::error_code& ec, const tcp::resolver::results_type& endpoints) {
            if (!ec) {
                self->reset_timeout();
                self->connect(endpoints);
            } else {
                self->log("Resolve failed: " + ec.message(), true);
                self->finish("Could not find the host: " + ec.message());
            }
        });
}

void ClientNode::log(const std::string& msg, bool error) {
    (error ? std::cerr : std::cout) << "[CLIENT] " << msg << '\n';
    if (events_.on_log) events_.on_log("[CLIENT] " + msg);
}

void ClientNode::finish(const std::string& reason) {
    if (done_) return;
    done_ = true;
    timer_.cancel();
    boost::system::error_code ignored_ec;
    ssl_socket_.lowest_layer().close(ignored_ec);
    if (events_.on_finished) {
        events_.on_finished(succeeded_,
            succeeded_ ? std::string("File verified and saved by the receiver")
                       : (reason.empty() ? std::string("Transfer did not complete") : reason));
    }
}

bool ClientNode::handle_unknown_ca(const boost::system::error_code& ec) {
    if (ec && ec != net::error::operation_aborted &&
        ec.message().find("unknown ca") != std::string::npos) {
        log("The receiver may not trust you yet.", true);
        finish("The receiver doesn't trust your fingerprint yet. "
               "Send them your fingerprint so they can add you.");
        return true;
    }
    return false;
}

void ClientNode::arm_timeout() {
    timer_.expires_after(std::chrono::seconds(30));
    timer_.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
        if (!ec) {
            self->log("Operation timed out", true);
            self->finish("Operation timed out");
        }
    });
}

void ClientNode::connect(const tcp::resolver::results_type& endpoints) {
    net::async_connect(ssl_socket_.lowest_layer(), endpoints,
        [self = shared_from_this()](const boost::system::error_code& ec, const tcp::endpoint&) {
            if (ec) {
                if (ec != net::error::operation_aborted)
                    self->log("TCP connect failed: " + ec.message(), true);
                self->finish("Could not connect: " + ec.message());
                return;
            }
            self->reset_timeout();
            self->log("TCP connected. Performing TLS 1.3 handshake...");
            self->handshake();
        });
}

void ClientNode::handshake() {
    ssl_socket_.async_handshake(net::ssl::stream_base::client,
        [self = shared_from_this()](const boost::system::error_code& ec) {
            if (ec) {
                const std::string reason = ec.message();
                if (ec != net::error::operation_aborted)
                    self->log("TLS handshake failed: " + reason, true);
                std::string friendly = "TLS handshake failed: " + reason;
                if (reason.find("certificate verify failed") != std::string::npos) {
                    friendly = "You don't trust this receiver's fingerprint yet. "
                               "Verify it with its owner, then add it in Trusted Peers.";
                }
                self->finish(friendly);
                return;
            }
            self->reset_timeout();

            X509* cert = SSL_get_peer_certificate(self->ssl_socket_.native_handle());
            if (cert) {
                try {
                    const std::string fp = identity::fingerprint_of(cert);
                    const auto name = self->store_
                        ? self->store_->find_name(fp)
                        : trust::TrustStore(identity::TRUST_FILE).find_name(fp);
                    const std::string shown_fp = trust::display_fingerprint(fp);
                    if (name) self->log("Connected to '" + *name + "' (fingerprint: " + shown_fp + ")");
                    else      self->log("Connected (fingerprint: " + shown_fp + ")");
                    if (self->events_.on_peer) self->events_.on_peer(name ? *name : std::string(), fp);
                } catch (...) {}
                X509_free(cert);
            }
            self->log("TLS handshake SUCCESS");
            self->prepare_and_send_header();
        });
}

void ClientNode::prepare_and_send_header() {
    try {
        total_size_ = FileStreamer::get_file_size(file_path_);
        auto file_hash = FileStreamer::compute_sha256(file_path_);
        file_name_ = std::filesystem::path(file_path_).filename().string();

        header_.msg_type = static_cast<uint8_t>(MessageType::METADATA);
        header_.payload_len = boost::endian::native_to_big(static_cast<uint32_t>(file_name_.length()));
        header_.total_file_size = boost::endian::native_to_big(total_size_);
        header_.filename_len = boost::endian::native_to_big(static_cast<uint16_t>(file_name_.length()));
        std::memcpy(header_.file_hash, file_hash.data(), 32);
        log("Sending 47-byte PacketHeader...");

        net::async_write(ssl_socket_, net::buffer(&header_, sizeof(PacketHeader)),
            [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    if (ec == net::error::operation_aborted) {
                        self->finish("Failed to send header: " + ec.message());
                        return;
                    }
                    if (self->handle_unknown_ca(ec)) {
                        return;
                    }
                    net::async_read(self->ssl_socket_, net::buffer(&self->ack_header_, sizeof(PacketHeader)),
                        [self, ec](const boost::system::error_code& read_ec, std::size_t) {
                            if (read_ec && self->handle_unknown_ca(read_ec)) {
                                return;
                            }
                            self->log("Failed to send header: " + ec.message(), true);
                            self->finish("Failed to send header: " + ec.message());
                        });
                    return;
                }
                self->reset_timeout();
                self->send_filename_payload();
            });
    } catch (const std::exception& e) {
        log(std::string("File prep failed: ") + e.what(), true);
        finish(std::string("Could not read the file: ") + e.what());
    }
}

void ClientNode::send_filename_payload() {
    net::async_write(ssl_socket_, net::buffer(file_name_),
        [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
            if (ec) {
                if (ec == net::error::operation_aborted) {
                    self->finish("Failed to send filename: " + ec.message());
                    return;
                }
                if (self->handle_unknown_ca(ec)) {
                    return;
                }
                net::async_read(self->ssl_socket_, net::buffer(&self->ack_header_, sizeof(PacketHeader)),
                    [self, ec](const boost::system::error_code& read_ec, std::size_t) {
                        if (read_ec && self->handle_unknown_ca(read_ec)) {
                            return;
                        }
                        self->log("Failed to send filename: " + ec.message(), true);
                        self->finish("Failed to send filename: " + ec.message());
                    });
                return;
            }
            self->reset_timeout();
            self->log("Metadata sent. Waiting for the receiver to accept...");
            self->read_reply([self](AckStatus status) {
                if (status == AckStatus::READY) {
                    self->log("Receiver accepted. Streaming file...");
                    self->open_file_and_stream();
                } else {
                    self->log(std::string("Receiver refused the transfer: ") + describe(status), true);
                    self->finish(std::string("Receiver refused: ") + describe(status));
                }
            });
        });
}

void ClientNode::read_reply(std::function<void(AckStatus)> handler) {
    net::async_read(ssl_socket_, net::buffer(&ack_header_, sizeof(PacketHeader)),
        [self = shared_from_this(), handler = std::move(handler)](const boost::system::error_code& ec, std::size_t bytes_read) mutable {
            if (ec) {
                if (ec != net::error::operation_aborted) {
                    self->log("No reply from receiver after reading " + std::to_string(bytes_read) +
                              " bytes: " + ec.message(), true);
                }
                if (self->handle_unknown_ca(ec)) {
                    return;
                }
                self->finish("No reply from receiver: " + ec.message());
                return;
            }
            self->reset_timeout();
            if (self->ack_header_.msg_type != static_cast<uint8_t>(MessageType::ACK) ||
                boost::endian::big_to_native(self->ack_header_.payload_len) != 1) {
                self->log("Malformed reply from receiver", true);
                self->finish("Malformed reply from receiver");
                return;
            }

            net::async_read(self->ssl_socket_, net::buffer(&self->ack_status_, 1),
                [self, handler = std::move(handler)](const boost::system::error_code& ec2, std::size_t) {
                    if (ec2) {
                        if (ec2 != net::error::operation_aborted)
                            self->log("Failed to read reply status: " + ec2.message(), true);
                        self->finish("Failed to read reply status: " + ec2.message());
                        return;
                    }
                    self->reset_timeout();
                    handler(static_cast<AckStatus>(self->ack_status_));
                });
        });
}

void ClientNode::open_file_and_stream() {
    file_stream_.open(file_path_, std::ios::binary);
    if (!file_stream_.is_open()) {
        log("Failed to open file for streaming!", true);
        finish("Failed to open the file for sending");
        return;
    }
    buffer_.resize(FileStreamer::CHUNK_SIZE);
    report_progress();
    stream_next_chunk();
}

void ClientNode::report_progress() {
    if (events_.on_progress) events_.on_progress(bytes_sent_, total_size_);
    if (total_size_ > 0) {
        const int progress = static_cast<int>((bytes_sent_ * 100) / total_size_);
        if (progress != last_progress_) {
            std::cout << "\r[CLIENT] Progress: [" << std::string(progress / 2, '=') << std::string(50 - progress / 2, ' ')
                      << "] " << progress << "%" << std::flush;
            if (progress == 100) std::cout << std::endl;
            last_progress_ = progress;
        }
    }
}

void ClientNode::stream_next_chunk() {
    if (!file_stream_.read(buffer_.data(), static_cast<std::streamsize>(buffer_.size())) && file_stream_.gcount() == 0) {
        log("File transfer complete!");
        send_end_of_file_signal();
        return;
    }
    const std::size_t bytes_read = static_cast<std::size_t>(file_stream_.gcount());

    net::async_write(ssl_socket_, net::buffer(buffer_.data(), bytes_read),
        [self = shared_from_this()](const boost::system::error_code& ec, std::size_t bytes_transferred) {
            if (ec) {
                if (ec != net::error::operation_aborted)
                    self->log("Stream write error: " + ec.message(), true);
                self->finish("Connection lost while sending: " + ec.message());
                return;
            }
            self->reset_timeout();
            self->bytes_sent_ += bytes_transferred;
            self->report_progress();
            self->stream_next_chunk();
        });
}

void ClientNode::send_end_of_file_signal() {
    std::memset(&eof_header_, 0, sizeof(PacketHeader));
    eof_header_.msg_type = static_cast<uint8_t>(MessageType::END_OF_FILE);

    net::async_write(ssl_socket_, net::buffer(&eof_header_, sizeof(PacketHeader)),
        [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
            if (ec) {
                if (ec != net::error::operation_aborted)
                    self->log("Failed to send EOF packet: " + ec.message(), true);
                self->finish("Failed to send the end-of-file marker: " + ec.message());
                return;
            }
            self->reset_timeout();
            self->log("EOF packet delivered. Waiting for the receiver's verdict...");
            self->read_reply([self](AckStatus status) {
                if (status == AckStatus::OK) {
                    self->succeeded_ = true;
                    self->log(std::string("Receiver confirmed: ") + describe(status) + "!");
                    self->finish();
                } else {
                    self->log(std::string("Transfer failed: ") + describe(status), true);
                    self->finish(std::string("Receiver says: ") + describe(status));
                }
            });
        });
}
