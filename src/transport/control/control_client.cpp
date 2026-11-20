#include "control_client.hpp"

#define BOOST_JSON_NO_LIB
#include <boost/json/src.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <utility>
#include <variant>
#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace control_plane {

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = net::ssl;
namespace json = boost::json;
using tcp = net::ip::tcp;
using udp = net::ip::udp;

namespace {

constexpr std::array<uint8_t, 4> BVST_MAGIC = {'B', 'V', 'S', 'T'};
constexpr std::size_t RELAY_CHUNK_BYTES = 65536;

std::string bytes_to_lower_hex(const uint8_t* data, std::size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0x0F]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

std::string base64_encode(const uint8_t* data, std::size_t len) {
    static constexpr char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (std::size_t i = 0; i < len; i += 3) {
        const uint32_t b0 = data[i];
        const bool has1 = (i + 1) < len;
        const bool has2 = (i + 2) < len;
        const uint32_t b1 = has1 ? data[i + 1] : 0;
        const uint32_t b2 = has2 ? data[i + 2] : 0;
        const uint32_t triple = (b0 << 16) | (b1 << 8) | b2;
        out.push_back(kTable[(triple >> 18) & 0x3F]);
        out.push_back(kTable[(triple >> 12) & 0x3F]);
        out.push_back(has1 ? kTable[(triple >> 6) & 0x3F] : '=');
        out.push_back(has2 ? kTable[triple & 0x3F] : '=');
    }
    return out;
}

std::vector<uint8_t> base64_decode(std::string_view input) {
    while (!input.empty() && (input.back() == '\r' || input.back() == '\n' || input.back() == ' ')) {
        input.remove_suffix(1);
    }
    if (input.empty() || (input.size() % 4) != 0) {
        throw std::runtime_error("ControlClient: invalid base64 length");
    }
    auto decode_char = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    std::vector<uint8_t> out;
    out.reserve((input.size() / 4) * 3);
    for (std::size_t i = 0; i < input.size(); i += 4) {
        const unsigned char c0 = static_cast<unsigned char>(input[i]);
        const unsigned char c1 = static_cast<unsigned char>(input[i + 1]);
        const unsigned char c2 = static_cast<unsigned char>(input[i + 2]);
        const unsigned char c3 = static_cast<unsigned char>(input[i + 3]);

        const int v0 = decode_char(c0);
        const int v1 = decode_char(c1);
        const bool p2 = (c2 == '=') && (i + 4 == input.size());
        const bool p3 = (c3 == '=') && (i + 4 == input.size());
        if (p2 && !p3) throw std::runtime_error("ControlClient: malformed base64 padding");
        const int v2 = p2 ? 0 : decode_char(c2);
        const int v3 = p3 ? 0 : decode_char(c3);
        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
            throw std::runtime_error("ControlClient: invalid base64 character");
        }
        const uint32_t triple = (static_cast<uint32_t>(v0) << 18) |
                                (static_cast<uint32_t>(v1) << 12) |
                                (static_cast<uint32_t>(v2) << 6) |
                                static_cast<uint32_t>(v3);
        out.push_back(static_cast<uint8_t>((triple >> 16) & 0xFF));
        if (!p2) out.push_back(static_cast<uint8_t>((triple >> 8) & 0xFF));
        if (!p3) out.push_back(static_cast<uint8_t>(triple & 0xFF));
    }
    return out;
}

int pem_passphrase_cb(char* buf, int size, int /*rwflag*/, void* userdata) {
    const auto* pass = static_cast<const std::string*>(userdata);
    if (!pass || size <= 0) return 0;
    const int n = std::min(size, static_cast<int>(pass->size()));
    std::memcpy(buf, pass->data(), static_cast<std::size_t>(n));
    return n;
}

void configure_client_ssl_ctx(ssl::context& ctx, const std::string& ca_file) {
    ctx.set_default_verify_paths();
    if (!ca_file.empty()) {
        ctx.load_verify_file(ca_file);
    }
    ctx.set_verify_mode(ssl::verify_peer);
}

using PlainWsStream = websocket::stream<beast::tcp_stream>;
using TlsWsStream = websocket::stream<beast::ssl_stream<beast::tcp_stream>>;

template <typename WsStream>
std::unique_ptr<WsStream> connect_ws_stream(net::io_context& ioc,
                                            const ControlEndpoint& ep,
                                            const std::string& target,
                                            const std::string& bearer_token,
                                            ssl::context* ssl_ctx) {
    tcp::resolver resolver{ioc};
    const auto results = resolver.resolve(ep.host, ep.port);

    if constexpr (std::is_same_v<WsStream, PlainWsStream>) {
        (void)ssl_ctx;
        auto ws = std::make_unique<PlainWsStream>(ioc);
        beast::get_lowest_layer(*ws).expires_after(std::chrono::seconds(15));
        beast::get_lowest_layer(*ws).connect(results);
        beast::get_lowest_layer(*ws).expires_never();
        if (!bearer_token.empty()) {
            ws->set_option(websocket::stream_base::decorator(
                [bearer_token](websocket::request_type& req) {
                    req.set(http::field::authorization, "Bearer " + bearer_token);
                }));
        }
        ws->handshake(ep.host_header(), target);
        return ws;
    } else {
        auto ws = std::make_unique<TlsWsStream>(ioc, *ssl_ctx);
        if (!SSL_set_tlsext_host_name(ws->next_layer().native_handle(), ep.host.c_str())) {
            throw std::runtime_error("ControlClient: failed setting TLS SNI host");
        }
        beast::get_lowest_layer(*ws).expires_after(std::chrono::seconds(15));
        beast::get_lowest_layer(*ws).connect(results);
        ws->next_layer().handshake(ssl::stream_base::client);
        beast::get_lowest_layer(*ws).expires_never();
        if (!bearer_token.empty()) {
            ws->set_option(websocket::stream_base::decorator(
                [bearer_token](websocket::request_type& req) {
                    req.set(http::field::authorization, "Bearer " + bearer_token);
                }));
        }
        ws->handshake(ep.host_header(), target);
        return ws;
    }
}

template <typename WsStream>
void start_pump_ws_and_tcp(std::shared_ptr<WsStream> ws,
                           std::shared_ptr<tcp::socket> sock) {
    ws->binary(true);
    ws->read_message_max(RELAY_CHUNK_BYTES * 2);

    struct PumpState : std::enable_shared_from_this<PumpState> {
        std::shared_ptr<WsStream> ws;
        std::shared_ptr<tcp::socket> sock;
        std::array<uint8_t, RELAY_CHUNK_BYTES> tcp_buf{};
        beast::flat_buffer ws_buf;
        std::atomic<bool> closing{false};

        void start() {
            read_tcp();
            read_ws();
        }

        void shutdown() {
            if (closing.exchange(true)) return;
            beast::error_code ec;
            sock->shutdown(tcp::socket::shutdown_both, ec);
            sock->close(ec);
            beast::get_lowest_layer(*ws).cancel();
            auto self = this->shared_from_this();
            ws->async_close(websocket::close_code::normal, [self](const beast::error_code&) {});
        }

        void read_tcp() {
            if (closing.load()) return;
            auto self = this->shared_from_this();
            sock->async_read_some(
                net::buffer(tcp_buf),
                [self](const beast::error_code& ec, std::size_t n) {
                    if (ec || n == 0 || self->closing.load()) {
                        self->shutdown();
                        return;
                    }
                    self->ws->binary(true);
                    self->ws->async_write(
                        net::buffer(self->tcp_buf.data(), n),
                        [self](const beast::error_code& wec, std::size_t) {
                            if (wec || self->closing.load()) {
                                self->shutdown();
                                return;
                            }
                            self->read_tcp();
                        });
                });
        }

        void read_ws() {
            if (closing.load()) return;
            auto self = this->shared_from_this();
            ws->async_read(
                ws_buf,
                [self](const beast::error_code& ec, std::size_t) {
                    if (ec || self->closing.load() || !self->ws->got_binary()) {
                        self->shutdown();
                        return;
                    }
                    net::async_write(
                        *self->sock,
                        self->ws_buf.data(),
                        [self](const beast::error_code& wec, std::size_t) {
                            self->ws_buf.consume(self->ws_buf.size());
                            if (wec || self->closing.load()) {
                                self->shutdown();
                                return;
                            }
                            self->read_ws();
                        });
                });
        }
    };

    auto st = std::make_shared<PumpState>();
    st->ws = std::move(ws);
    st->sock = std::move(sock);
    st->start();
}

template <typename WsStream>
void pump_ws_and_tcp(std::shared_ptr<WsStream> ws,
                     std::shared_ptr<tcp::socket> sock,
                     net::io_context& ioc) {
    start_pump_ws_and_tcp(std::move(ws), std::move(sock));
    ioc.run();
}

json::array endpoints_to_json(const std::vector<EndpointHint>& endpoints) {
    json::array arr;
    for (const auto& ep : endpoints) {
        arr.push_back(json::object{
            {"host", ep.host},
            {"port", ep.port},
            {"proto", ep.proto.empty() ? "tcp" : ep.proto}
        });
    }
    return arr;
}

std::vector<EndpointHint> json_to_endpoints(const json::value& val) {
    std::vector<EndpointHint> out;
    if (!val.is_array()) return out;
    for (const auto& item : val.as_array()) {
        if (!item.is_object()) continue;
        const auto& obj = item.as_object();
        EndpointHint ep;
        if (const auto* h = obj.if_contains("host"); h && h->is_string()) {
            ep.host = std::string(h->as_string());
        }
        if (const auto* p = obj.if_contains("port")) {
            if (p->is_int64()) ep.port = static_cast<std::uint16_t>(p->as_int64());
            else if (p->is_uint64()) ep.port = static_cast<std::uint16_t>(p->as_uint64());
        }
        if (const auto* pr = obj.if_contains("proto"); pr && pr->is_string()) {
            ep.proto = std::string(pr->as_string());
        }
        if (!ep.host.empty() && ep.port != 0) {
            out.push_back(std::move(ep));
        }
    }
    return out;
}

PeerMatch parse_peer_matched(const json::object& obj) {
    PeerMatch match;
    if (const auto* fp = obj.if_contains("peer_fingerprint"); fp && fp->is_string()) {
        match.peer_fingerprint = std::string(fp->as_string());
    }
    if (const auto* role = obj.if_contains("role"); role && role->is_string()) {
        match.role = std::string(role->as_string());
    }
    if (const auto* eps = obj.if_contains("endpoints")) {
        match.endpoints = json_to_endpoints(*eps);
    }
    return match;
}

} // namespace

std::string ControlEndpoint::host_header() const {
    const bool is_default =
        (!use_tls && port == "80") || (use_tls && port == "443") || port.empty();
    return is_default ? host : (host + ":" + port);
}

ControlEndpoint parse_control_url(std::string_view url) {
    ControlEndpoint ep;
    std::string_view rest = url;
    if (rest.rfind("https://", 0) == 0 || rest.rfind("wss://", 0) == 0) {
        ep.use_tls = true;
        ep.port = "443";
        rest.remove_prefix(rest.rfind("https://", 0) == 0 ? 8 : 6);
    } else if (rest.rfind("http://", 0) == 0 || rest.rfind("ws://", 0) == 0) {
        ep.use_tls = false;
        ep.port = "80";
        rest.remove_prefix(rest.rfind("http://", 0) == 0 ? 7 : 5);
    } else {
        throw std::runtime_error("ControlClient: URL must use http://, https://, ws://, or wss://");
    }

    if (const std::size_t slash = rest.find('/'); slash != std::string_view::npos) {
        rest = rest.substr(0, slash);
    }

    if (!rest.empty() && rest.front() == '[') {
        const std::size_t close = rest.find(']');
        if (close == std::string_view::npos) {
            throw std::runtime_error("ControlClient: malformed IPv6 control URL");
        }
        ep.host = std::string(rest.substr(1, close - 1));
        if (close + 1 < rest.size() && rest[close + 1] == ':') {
            ep.port = std::string(rest.substr(close + 2));
        }
    } else if (const std::size_t colon = rest.rfind(':'); colon != std::string_view::npos) {
        ep.host = std::string(rest.substr(0, colon));
        ep.port = std::string(rest.substr(colon + 1));
    } else {
        ep.host = std::string(rest);
    }

    if (ep.host.empty() || ep.port.empty()) {
        throw std::runtime_error("ControlClient: missing host or port in control URL");
    }
    return ep;
}

struct ControlClient::Impl {
    using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

    ControlEndpoint endpoint;
    std::string ca_file;
    PkeyPtr priv_key{nullptr, &EVP_PKEY_free};
    std::string public_key_pem;
    std::string fingerprint_hex;
    int heartbeat_sec = 20;

    net::io_context ioc;
    std::unique_ptr<ssl::context> ssl_ctx;
    std::variant<std::monostate,
                 std::unique_ptr<PlainWsStream>,
                 std::unique_ptr<TlsWsStream>> ws_conn;

    void load_identity_key(const std::filesystem::path& key_path, std::string passphrase) {
        std::ifstream in(key_path, std::ios::binary);
        if (!in) {
            throw std::runtime_error("ControlClient: cannot open private key " + key_path.string());
        }
        std::string pem((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
        BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
        EVP_PKEY* raw = PEM_read_bio_PrivateKey(
            bio.get(), nullptr, passphrase.empty() ? nullptr : &pem_passphrase_cb,
            passphrase.empty() ? nullptr : &passphrase);
        OPENSSL_cleanse(pem.data(), pem.size());
        OPENSSL_cleanse(passphrase.data(), passphrase.size());
        if (!raw) {
            throw std::runtime_error("ControlClient: failed loading private key " + key_path.string());
        }
        priv_key.reset(raw);
        if (EVP_PKEY_base_id(priv_key.get()) != EVP_PKEY_EC) {
            throw std::runtime_error("ControlClient: control-plane identity key must be EC P-256");
        }

        // Export SPKI PEM
        BioPtr pub_bio(BIO_new(BIO_s_mem()), &BIO_free);
        if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), priv_key.get()) != 1) {
            throw std::runtime_error("ControlClient: failed exporting SPKI PEM public key");
        }
        char* pem_data = nullptr;
        const long pem_len = BIO_get_mem_data(pub_bio.get(), &pem_data);
        public_key_pem.assign(pem_data, static_cast<std::size_t>(pem_len));

        // Export SPKI DER & SHA-256 hex (matches blindvault-control compute_peer_fingerprint)
        const int der_len = i2d_PUBKEY(priv_key.get(), nullptr);
        if (der_len <= 0) {
            throw std::runtime_error("ControlClient: failed sizing SPKI DER");
        }
        std::vector<uint8_t> der(static_cast<std::size_t>(der_len));
        uint8_t* p = der.data();
        if (i2d_PUBKEY(priv_key.get(), &p) != der_len) {
            throw std::runtime_error("ControlClient: failed serializing SPKI DER");
        }
        std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
        SHA256(der.data(), der.size(), digest.data());
        fingerprint_hex = bytes_to_lower_hex(digest.data(), digest.size());
    }

    std::string sign_nonce_b64(const std::vector<uint8_t>& nonce) const {
        using MdCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
        MdCtx mctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
        if (!mctx ||
            EVP_DigestSignInit(mctx.get(), nullptr, EVP_sha256(), nullptr, priv_key.get()) <= 0) {
            throw std::runtime_error("ControlClient: EVP_DigestSignInit failed");
        }
        if (EVP_DigestSignUpdate(mctx.get(), nonce.data(), nonce.size()) <= 0) {
            throw std::runtime_error("ControlClient: EVP_DigestSignUpdate failed");
        }
        std::size_t sig_len = 0;
        if (EVP_DigestSignFinal(mctx.get(), nullptr, &sig_len) <= 0 || sig_len == 0) {
            throw std::runtime_error("ControlClient: EVP_DigestSignFinal size failed");
        }
        std::vector<uint8_t> sig(sig_len);
        if (EVP_DigestSignFinal(mctx.get(), sig.data(), &sig_len) <= 0) {
            throw std::runtime_error("ControlClient: EVP_DigestSignFinal failed");
        }
        sig.resize(sig_len);
        return base64_encode(sig.data(), sig.size());
    }

    void send_json(const json::object& obj) {
        const std::string text = json::serialize(obj);
        if (auto* plain = std::get_if<std::unique_ptr<PlainWsStream>>(&ws_conn)) {
            (*plain)->text(true);
            (*plain)->write(net::buffer(text));
        } else if (auto* tls = std::get_if<std::unique_ptr<TlsWsStream>>(&ws_conn)) {
            (*tls)->text(true);
            (*tls)->write(net::buffer(text));
        } else {
            throw std::runtime_error("ControlClient: WebSocket not connected");
        }
    }

    json::object read_json_with_keepalives(std::chrono::milliseconds timeout) {
        if (std::holds_alternative<std::monostate>(ws_conn)) {
            throw std::runtime_error("ControlClient: WebSocket not connected");
        }

        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (true) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                throw std::runtime_error("ControlClient: timed out waiting for control message");
            }
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);

            beast::flat_buffer buffer;
            std::optional<json::object> parsed;
            std::optional<std::string> async_err;

            net::steady_timer deadline_timer{ioc, remaining};
            net::steady_timer hb_timer{ioc};
            std::atomic<bool> finished{false};

            std::function<void()> schedule_hb = [&]() {
                if (finished.load()) return;
                const auto interval = std::chrono::seconds(std::max(1, heartbeat_sec));
                hb_timer.expires_after(interval);
                hb_timer.async_wait([&](const beast::error_code& ec) {
                    if (ec || finished.load()) return;
                    static const std::string kPing = R"({"type":"PING"})";
                    if (auto* plain = std::get_if<std::unique_ptr<PlainWsStream>>(&ws_conn)) {
                        (*plain)->text(true);
                        (*plain)->async_write(net::buffer(kPing), [](const beast::error_code&, std::size_t) {});
                    } else if (auto* tls = std::get_if<std::unique_ptr<TlsWsStream>>(&ws_conn)) {
                        (*tls)->text(true);
                        (*tls)->async_write(net::buffer(kPing), [](const beast::error_code&, std::size_t) {});
                    }
                    schedule_hb();
                });
            };
            schedule_hb();

            deadline_timer.async_wait([&](const beast::error_code& ec) {
                if (ec || finished.load()) return;
                finished.store(true);
                hb_timer.cancel();
                if (auto* plain = std::get_if<std::unique_ptr<PlainWsStream>>(&ws_conn)) {
                    beast::get_lowest_layer(**plain).cancel();
                } else if (auto* tls = std::get_if<std::unique_ptr<TlsWsStream>>(&ws_conn)) {
                    beast::get_lowest_layer(**tls).cancel();
                }
                async_err = "timed out waiting for control message";
            });

            auto on_read = [&](const beast::error_code& ec, std::size_t) {
                if (finished.exchange(true)) return;
                deadline_timer.cancel();
                hb_timer.cancel();
                if (ec) {
                    async_err = ec.message();
                    return;
                }
                try {
                    const std::string text = beast::buffers_to_string(buffer.data());
                    auto jv = json::parse(text);
                    if (!jv.is_object()) {
                        async_err = "ControlClient: non-object JSON message";
                        return;
                    }
                    parsed = std::move(jv.as_object());
                } catch (const std::exception& e) {
                    async_err = e.what();
                }
            };

            if (auto* plain = std::get_if<std::unique_ptr<PlainWsStream>>(&ws_conn)) {
                (*plain)->async_read(buffer, on_read);
            } else if (auto* tls = std::get_if<std::unique_ptr<TlsWsStream>>(&ws_conn)) {
                (*tls)->async_read(buffer, on_read);
            }

            ioc.restart();
            ioc.run();

            if (async_err) {
                throw std::runtime_error("ControlClient: " + *async_err);
            }
            if (!parsed) {
                throw std::runtime_error("ControlClient: empty control read");
            }
            const auto* t = parsed->if_contains("type");
            if (t && t->is_string() && t->as_string() == "PONG") {
                continue;
            }
            if (t && t->is_string() && t->as_string() == "ERROR") {
                std::string code = "ERROR";
                std::string msg = "unknown error";
                if (const auto* c = parsed->if_contains("code"); c && c->is_string()) {
                    code = std::string(c->as_string());
                }
                if (const auto* m = parsed->if_contains("message"); m && m->is_string()) {
                    msg = std::string(m->as_string());
                }
                throw std::runtime_error("ControlClient server error [" + code + "]: " + msg);
            }
            return std::move(*parsed);
        }
    }
};

ControlClient::ControlClient(std::string control_url,
                             const std::filesystem::path& identity_key_path,
                             std::string key_passphrase,
                             std::string ca_file)
    : impl_(std::make_unique<Impl>()) {
    impl_->endpoint = parse_control_url(control_url);
    impl_->ca_file = std::move(ca_file);
    impl_->load_identity_key(identity_key_path, std::move(key_passphrase));
}

ControlClient::~ControlClient() {
    close();
}

const std::string& ControlClient::fingerprint() const noexcept {
    return impl_->fingerprint_hex;
}

int ControlClient::heartbeat_interval_sec() const noexcept {
    return impl_->heartbeat_sec;
}

ServerInfo ControlClient::fetch_server_info() {
    http::request<http::empty_body> req{http::verb::get, "/api/v1/info", 11};
    req.set(http::field::host, impl_->endpoint.host_header());
    req.set(http::field::user_agent, "BlindVault-ControlClient/1.0");

    http::response<http::string_body> res;
    net::io_context ioc;
    tcp::resolver resolver{ioc};
    const auto results = resolver.resolve(impl_->endpoint.host, impl_->endpoint.port);

    if (!impl_->endpoint.use_tls) {
        beast::tcp_stream stream{ioc};
        stream.expires_after(std::chrono::seconds(10));
        stream.connect(results);
        http::write(stream, req);
        beast::flat_buffer buf;
        http::read(stream, buf, res);
        beast::error_code ignored;
        stream.socket().shutdown(tcp::socket::shutdown_both, ignored);
    } else {
        ssl::context ssl_ctx{ssl::context::tls_client};
        configure_client_ssl_ctx(ssl_ctx, impl_->ca_file);
        beast::ssl_stream<beast::tcp_stream> stream{ioc, ssl_ctx};
        if (!SSL_set_tlsext_host_name(stream.native_handle(), impl_->endpoint.host.c_str())) {
            throw std::runtime_error("ControlClient: failed setting TLS SNI host");
        }
        beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(10));
        beast::get_lowest_layer(stream).connect(results);
        stream.handshake(ssl::stream_base::client);
        http::write(stream, req);
        beast::flat_buffer buf;
        http::read(stream, buf, res);
        beast::error_code ignored;
        stream.shutdown(ignored);
    }

    if (res.result_int() < 200 || res.result_int() >= 300) {
        throw std::runtime_error(
            "ControlClient: GET /api/v1/info returned HTTP " + std::to_string(res.result_int()));
    }

    const auto jv = json::parse(res.body());
    if (!jv.is_object()) {
        throw std::runtime_error("ControlClient: malformed /api/v1/info JSON");
    }
    const auto& obj = jv.as_object();

    ServerInfo info;
    if (const auto* v = obj.if_contains("version"); v && v->is_string()) {
        info.version = std::string(v->as_string());
    }
    if (const auto* p = obj.if_contains("udp_reflector_port")) {
        if (p->is_int64()) info.udp_reflector_port = static_cast<std::uint16_t>(p->as_int64());
        else if (p->is_uint64()) info.udp_reflector_port = static_cast<std::uint16_t>(p->as_uint64());
    }
    if (const auto* pk = obj.if_contains("udp_reflector_public_key"); pk && pk->is_string()) {
        info.udp_reflector_public_key_b64 = std::string(pk->as_string());
    }
    if (const auto* alg = obj.if_contains("udp_reflector_signature_alg"); alg && alg->is_string()) {
        info.udp_reflector_signature_alg = std::string(alg->as_string());
    }
    if (const auto* mf = obj.if_contains("max_relay_frame_bytes")) {
        if (mf->is_int64()) info.max_relay_frame_bytes = static_cast<std::size_t>(mf->as_int64());
        else if (mf->is_uint64()) info.max_relay_frame_bytes = static_cast<std::size_t>(mf->as_uint64());
    }
    return info;
}

std::optional<ReflectedEndpoint> ControlClient::verify_udp_reflection_packet(
    const std::vector<uint8_t>& packet,
    std::string_view ed25519_pubkey_b64,
    const std::array<uint8_t, 16>& expected_nonce) {
    // Minimal length (IPv4): 4 + 16 + 1 + 4 + 2 + 8 + 64 = 99 bytes
    if (packet.size() < 99) return std::nullopt;
    if (!std::equal(BVST_MAGIC.begin(), BVST_MAGIC.end(), packet.begin())) return std::nullopt;
    if (CRYPTO_memcmp(packet.data() + 4, expected_nonce.data(), expected_nonce.size()) != 0) {
        return std::nullopt;
    }

    const uint8_t ip_version = packet[20];
    std::size_t ip_len = 0;
    if (ip_version == 4) ip_len = 4;
    else if (ip_version == 6) ip_len = 16;
    else return std::nullopt;

    const std::size_t body_len = 21 + ip_len + 2 + 8;
    const std::size_t total_len = body_len + 64;
    if (packet.size() != total_len) return std::nullopt;

    std::vector<uint8_t> pub_raw;
    try {
        pub_raw = base64_decode(ed25519_pubkey_b64);
    } catch (...) {
        return std::nullopt;
    }
    if (pub_raw.size() != 32) return std::nullopt;

    using Pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using MdCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

    Pkey pkey(EVP_PKEY_new_raw_public_key(
                  EVP_PKEY_ED25519, nullptr, pub_raw.data(), pub_raw.size()),
              &EVP_PKEY_free);
    MdCtx mctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!pkey || !mctx) return std::nullopt;
    if (EVP_DigestVerifyInit(mctx.get(), nullptr, nullptr, nullptr, pkey.get()) <= 0) {
        return std::nullopt;
    }
    if (EVP_DigestVerify(mctx.get(),
                         packet.data() + body_len, 64,
                         packet.data(), body_len) != 1) {
        return std::nullopt;
    }

    std::string ip_str;
    if (ip_version == 4) {
        net::ip::address_v4::bytes_type b4{};
        std::memcpy(b4.data(), packet.data() + 21, 4);
        ip_str = net::ip::address_v4(b4).to_string();
    } else {
        net::ip::address_v6::bytes_type b6{};
        std::memcpy(b6.data(), packet.data() + 21, 16);
        ip_str = net::ip::address_v6(b6).to_string();
    }

    const std::size_t port_off = 21 + ip_len;
    const std::uint16_t port = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(packet[port_off]) << 8) |
        static_cast<std::uint16_t>(packet[port_off + 1]));

    const std::size_t ts_off = port_off + 2;
    std::uint64_t ts = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        ts = (ts << 8) | static_cast<std::uint64_t>(packet[ts_off + i]);
    }

    return ReflectedEndpoint{std::move(ip_str), port, ts};
}

std::optional<ReflectedEndpoint> ControlClient::probe_udp_endpoint(
    const ServerInfo& info,
    std::uint16_t local_port,
    std::size_t timeout_ms) {
    if (info.udp_reflector_port == 0 || info.udp_reflector_public_key_b64.empty()) {
        return std::nullopt;
    }

    try {
        net::io_context ioc;
        udp::resolver resolver{ioc};
        const auto resolved = resolver.resolve(
            impl_->endpoint.host, std::to_string(info.udp_reflector_port));
        if (resolved.empty()) return std::nullopt;

        const udp::endpoint remote_ep = *resolved.begin();
        udp::socket sock{ioc, udp::endpoint(remote_ep.protocol(), local_port)};

        std::array<uint8_t, 16> nonce{};
        if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
            return std::nullopt;
        }

        std::array<uint8_t, 20> probe{};
        std::copy(BVST_MAGIC.begin(), BVST_MAGIC.end(), probe.begin());
        std::copy(nonce.begin(), nonce.end(), probe.begin() + 4);

        sock.send_to(net::buffer(probe), remote_ep);

        std::vector<uint8_t> rx(256);
        udp::endpoint sender_ep;
        std::size_t rx_len = 0;
        bool received = false;

        net::steady_timer timer{ioc, std::chrono::milliseconds(timeout_ms)};
        timer.async_wait([&](const beast::error_code& ec) {
            if (!ec) {
                beast::error_code ignored;
                sock.cancel(ignored);
            }
        });
        sock.async_receive_from(
            net::buffer(rx), sender_ep,
            [&](const beast::error_code& ec, std::size_t n) {
                timer.cancel();
                if (!ec && n > 0) {
                    rx_len = n;
                    received = true;
                }
            });

        ioc.run();
        if (!received) return std::nullopt;
        rx.resize(rx_len);
        return verify_udp_reflection_packet(rx, info.udp_reflector_public_key_b64, nonce);
    } catch (...) {
        return std::nullopt;
    }
}

void ControlClient::connect_and_authenticate(const std::optional<ReflectedEndpoint>& observed) {
    close();
    if (impl_->endpoint.use_tls) {
        impl_->ssl_ctx = std::make_unique<ssl::context>(ssl::context::tls_client);
        configure_client_ssl_ctx(*impl_->ssl_ctx, impl_->ca_file);
        impl_->ws_conn = connect_ws_stream<TlsWsStream>(
            impl_->ioc, impl_->endpoint, "/ws/control", "", impl_->ssl_ctx.get());
    } else {
        impl_->ws_conn = connect_ws_stream<PlainWsStream>(
            impl_->ioc, impl_->endpoint, "/ws/control", "", nullptr);
    }

    json::object hello;
    hello["type"] = "HELLO";
    hello["public_key"] = impl_->public_key_pem;
    if (observed) {
        hello["observed_endpoint"] = observed->ip + ":" + std::to_string(observed->port);
    } else {
        hello["observed_endpoint"] = nullptr;
    }
    impl_->send_json(hello);

    const auto chal = impl_->read_json_with_keepalives(std::chrono::seconds(15));
    const auto* ctype = chal.if_contains("type");
    if (!ctype || !ctype->is_string() || ctype->as_string() != "CHALLENGE") {
        throw std::runtime_error("ControlClient: expected CHALLENGE response");
    }
    const auto* server_fp = chal.if_contains("fingerprint");
    const auto* nonce_b64 = chal.if_contains("nonce");
    if (!server_fp || !server_fp->is_string() || !nonce_b64 || !nonce_b64->is_string()) {
        throw std::runtime_error("ControlClient: malformed CHALLENGE payload");
    }
    if (std::string(server_fp->as_string()) != impl_->fingerprint_hex) {
        throw std::runtime_error("ControlClient: server fingerprint mismatch during challenge");
    }

    const std::vector<uint8_t> nonce = base64_decode(std::string_view(nonce_b64->as_string()));
    const std::string sig_b64 = impl_->sign_nonce_b64(nonce);

    impl_->send_json(json::object{
        {"type", "AUTH"},
        {"signature", sig_b64}
    });

    const auto auth_res = impl_->read_json_with_keepalives(std::chrono::seconds(15));
    const auto* atype = auth_res.if_contains("type");
    if (!atype || !atype->is_string()) {
        throw std::runtime_error("ControlClient: malformed AUTH response");
    }
    if (atype->as_string() == "AUTH_FAILED") {
        std::string reason = "unknown";
        if (const auto* r = auth_res.if_contains("reason"); r && r->is_string()) {
            reason = std::string(r->as_string());
        }
        throw std::runtime_error("ControlClient: AUTH_FAILED: " + reason);
    }
    if (atype->as_string() != "AUTH_OK") {
        throw std::runtime_error("ControlClient: unexpected AUTH response type");
    }
    if (const auto* hb = auth_res.if_contains("heartbeat_interval_sec")) {
        if (hb->is_int64() && hb->as_int64() > 0) {
            impl_->heartbeat_sec = static_cast<int>(hb->as_int64());
        }
    }
}

void ControlClient::send_ping() {
    impl_->send_json(json::object{{"type", "PING"}});
    (void)impl_->read_json_with_keepalives(std::chrono::seconds(10));
}

InviteResult ControlClient::create_invite(const std::vector<EndpointHint>& endpoints) {
    impl_->send_json(json::object{
        {"type", "CREATE_INVITE"},
        {"endpoints", endpoints_to_json(endpoints)}
    });
    const auto resp = impl_->read_json_with_keepalives(std::chrono::seconds(15));
    const auto* t = resp.if_contains("type");
    if (!t || !t->is_string() || t->as_string() != "INVITE_CREATED") {
        throw std::runtime_error("ControlClient: expected INVITE_CREATED response");
    }
    InviteResult out;
    if (const auto* c = resp.if_contains("code"); c && c->is_string()) {
        out.code = std::string(c->as_string());
    }
    if (const auto* ttl = resp.if_contains("ttl"); ttl && ttl->is_int64()) {
        out.ttl = static_cast<int>(ttl->as_int64());
    }
    return out;
}

PeerMatch ControlClient::claim_invite(const std::string& code,
                                      const std::vector<EndpointHint>& endpoints) {
    impl_->send_json(json::object{
        {"type", "CLAIM_INVITE"},
        {"code", code},
        {"endpoints", endpoints_to_json(endpoints)}
    });
    const auto resp = impl_->read_json_with_keepalives(std::chrono::seconds(15));
    const auto* t = resp.if_contains("type");
    if (!t || !t->is_string() || t->as_string() != "PEER_MATCHED") {
        throw std::runtime_error("ControlClient: expected PEER_MATCHED response");
    }
    return parse_peer_matched(resp);
}

PeerMatch ControlClient::wait_for_peer_match(std::chrono::seconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            throw std::runtime_error("ControlClient: timed out waiting for peer to claim invite");
        }
        const auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const auto msg = impl_->read_json_with_keepalives(rem);
        const auto* t = msg.if_contains("type");
        if (t && t->is_string() && t->as_string() == "PEER_MATCHED") {
            return parse_peer_matched(msg);
        }
    }
}

void ControlClient::send_signal_offer(const std::string& target_fingerprint,
                                      const std::string& session_id,
                                      const std::string& host,
                                      std::uint16_t port,
                                      const std::string& proto) {
    impl_->send_json(json::object{
        {"type", "SIGNAL_OFFER"},
        {"target_fingerprint", target_fingerprint},
        {"session_id", session_id},
        {"candidate", json::object{{"host", host}, {"port", port}, {"proto", proto}}}
    });
}

void ControlClient::send_signal_answer(const std::string& target_fingerprint,
                                       const std::string& session_id,
                                       const std::string& host,
                                       std::uint16_t port,
                                       const std::string& proto) {
    impl_->send_json(json::object{
        {"type", "SIGNAL_ANSWER"},
        {"target_fingerprint", target_fingerprint},
        {"session_id", session_id},
        {"candidate", json::object{{"host", host}, {"port", port}, {"proto", proto}}}
    });
}

void ControlClient::send_hole_punch_sync(const std::string& target_fingerprint,
                                         const std::string& stage,
                                         double timestamp_sec) {
    impl_->send_json(json::object{
        {"type", "HOLE_PUNCH_SYNC"},
        {"target_fingerprint", target_fingerprint},
        {"stage", stage},
        {"timestamp", timestamp_sec}
    });
}

RelaySessionInfo ControlClient::create_relay(const std::string& target_fingerprint) {
    impl_->send_json(json::object{
        {"type", "CREATE_RELAY"},
        {"target_fingerprint", target_fingerprint}
    });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            throw std::runtime_error("ControlClient: timed out waiting for RELAY_CREATED");
        }
        const auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const auto msg = impl_->read_json_with_keepalives(rem);
        const auto* t = msg.if_contains("type");
        if (t && t->is_string() && t->as_string() == "RELAY_CREATED") {
            RelaySessionInfo info;
            if (const auto* s = msg.if_contains("session_id"); s && s->is_string()) {
                info.session_id = std::string(s->as_string());
            }
            if (const auto* tok = msg.if_contains("token"); tok && tok->is_string()) {
                info.token = std::string(tok->as_string());
            }
            return info;
        }
    }
}

RelaySessionInfo ControlClient::wait_for_relay_invite(std::chrono::seconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            throw std::runtime_error("ControlClient: timed out waiting for RELAY_INVITE");
        }
        const auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const auto msg = impl_->read_json_with_keepalives(rem);
        const auto* t = msg.if_contains("type");
        if (t && t->is_string() && t->as_string() == "RELAY_INVITE") {
            RelaySessionInfo info;
            if (const auto* s = msg.if_contains("session_id"); s && s->is_string()) {
                info.session_id = std::string(s->as_string());
            }
            if (const auto* tok = msg.if_contains("token"); tok && tok->is_string()) {
                info.token = std::string(tok->as_string());
            }
            if (const auto* fp = msg.if_contains("from_fingerprint"); fp && fp->is_string()) {
                info.from_fingerprint = std::string(fp->as_string());
            }
            return info;
        }
    }
}

bool ControlClient::try_direct_tcp_connect(const std::string& host,
                                           std::uint16_t port,
                                           std::size_t timeout_ms) {
    if (host.empty() || port == 0) return false;
    try {
        net::io_context ioc;
        tcp::resolver resolver{ioc};
        const auto resolved = resolver.resolve(host, std::to_string(port));
        tcp::socket sock{ioc};
        net::steady_timer timer{ioc, std::chrono::milliseconds(timeout_ms)};
        bool connected = false;

        timer.async_wait([&](const beast::error_code& ec) {
            if (!ec) {
                beast::error_code ignored;
                sock.cancel(ignored);
            }
        });
        net::async_connect(
            sock, resolved,
            [&](const beast::error_code& ec, const tcp::endpoint&) {
                timer.cancel();
                if (!ec) {
                    connected = true;
                    beast::error_code ignored;
                    sock.shutdown(tcp::socket::shutdown_both, ignored);
                    sock.close(ignored);
                }
            });

        ioc.run();
        return connected;
    } catch (...) {
        return false;
    }
}

void ControlClient::close() {
    beast::error_code ignored;
    if (auto* plain = std::get_if<std::unique_ptr<PlainWsStream>>(&impl_->ws_conn)) {
        if (*plain && (*plain)->is_open()) {
            (*plain)->close(websocket::close_code::normal, ignored);
        }
    } else if (auto* tls = std::get_if<std::unique_ptr<TlsWsStream>>(&impl_->ws_conn)) {
        if (*tls && (*tls)->is_open()) {
            (*tls)->close(websocket::close_code::normal, ignored);
        }
    }
    impl_->ws_conn = std::monostate{};
}

void RelayTcpBridge::bridge_to_local_server(const std::string& control_url,
                                            const std::string& session_id,
                                            const std::string& token,
                                            std::uint16_t local_server_port,
                                            const std::string& ca_file) {
    const ControlEndpoint ep = parse_control_url(control_url);
    const std::string target = "/ws/relay/" + session_id;

    net::io_context ioc;
    auto sock = std::make_shared<tcp::socket>(ioc);
    sock->connect(tcp::endpoint(net::ip::make_address("127.0.0.1"), local_server_port));

    if (ep.use_tls) {
        ssl::context ssl_ctx{ssl::context::tls_client};
        configure_client_ssl_ctx(ssl_ctx, ca_file);
        std::shared_ptr<TlsWsStream> ws(
            connect_ws_stream<TlsWsStream>(ioc, ep, target, token, &ssl_ctx));
        pump_ws_and_tcp(std::move(ws), std::move(sock), ioc);
    } else {
        std::shared_ptr<PlainWsStream> ws(
            connect_ws_stream<PlainWsStream>(ioc, ep, target, token, nullptr));
        pump_ws_and_tcp(std::move(ws), std::move(sock), ioc);
    }
}

struct RelayTcpBridge::LocalRelayProxy::Impl {
    ControlEndpoint ep;
    std::string target;
    std::string token;
    std::string ca_file;

    net::io_context ioc;
    tcp::acceptor acceptor{ioc};
    std::unique_ptr<ssl::context> ssl_ctx;
    std::shared_ptr<PlainWsStream> plain_ws;
    std::shared_ptr<TlsWsStream> tls_ws;
    std::shared_ptr<tcp::socket> active_sock;
    std::uint16_t bound_port = 0;
    std::thread worker;
    std::atomic<bool> stopped{false};
};

RelayTcpBridge::LocalRelayProxy::LocalRelayProxy(const std::string& control_url,
                                                 const std::string& session_id,
                                                 const std::string& token,
                                                 const std::string& ca_file)
    : impl_(std::make_unique<Impl>()) {
    impl_->ep = parse_control_url(control_url);
    impl_->target = "/ws/relay/" + session_id;
    impl_->token = token;
    impl_->ca_file = ca_file;

    tcp::endpoint bind_ep(net::ip::make_address("127.0.0.1"), 0);
    impl_->acceptor.open(bind_ep.protocol());
    impl_->acceptor.set_option(net::socket_base::reuse_address(true));
    impl_->acceptor.bind(bind_ep);
    impl_->acceptor.listen(1);
    impl_->bound_port = impl_->acceptor.local_endpoint().port();

    if (impl_->ep.use_tls) {
        impl_->ssl_ctx = std::make_unique<ssl::context>(ssl::context::tls_client);
        configure_client_ssl_ctx(*impl_->ssl_ctx, impl_->ca_file);
        impl_->tls_ws.reset(connect_ws_stream<TlsWsStream>(
                                impl_->ioc, impl_->ep, impl_->target, impl_->token, impl_->ssl_ctx.get())
                                .release());
    } else {
        impl_->plain_ws.reset(connect_ws_stream<PlainWsStream>(
                                  impl_->ioc, impl_->ep, impl_->target, impl_->token, nullptr)
                                  .release());
    }

    impl_->ioc.restart();
    auto sock = std::make_shared<tcp::socket>(impl_->ioc);
    impl_->acceptor.async_accept(*sock, [this, sock](const beast::error_code& ec) {
        beast::error_code ignored;
        impl_->acceptor.close(ignored);
        if (ec || impl_->stopped.load()) return;
        impl_->active_sock = sock;
        if (impl_->tls_ws) {
            start_pump_ws_and_tcp(impl_->tls_ws, sock);
        } else if (impl_->plain_ws) {
            start_pump_ws_and_tcp(impl_->plain_ws, sock);
        }
    });

    impl_->worker = std::thread([this]() {
        try {
            impl_->ioc.run();
        } catch (...) {
        }
    });
}

RelayTcpBridge::LocalRelayProxy::~LocalRelayProxy() {
    stop();
    join();
}

std::uint16_t RelayTcpBridge::LocalRelayProxy::local_port() const noexcept {
    return impl_->bound_port;
}

void RelayTcpBridge::LocalRelayProxy::join() {
    if (impl_->worker.joinable()) {
        impl_->worker.join();
    }
}

void RelayTcpBridge::LocalRelayProxy::stop() {
    if (impl_->stopped.exchange(true)) return;
    net::post(impl_->ioc, [p = impl_.get()]() {
        beast::error_code ec;
        p->acceptor.cancel(ec);
        p->acceptor.close(ec);
        if (p->active_sock) {
            p->active_sock->shutdown(tcp::socket::shutdown_both, ec);
            p->active_sock->close(ec);
        }
        if (p->tls_ws) {
            beast::get_lowest_layer(*p->tls_ws).cancel();
        }
        if (p->plain_ws) {
            beast::get_lowest_layer(*p->plain_ws).cancel();
        }
    });
}

} // namespace control_plane
