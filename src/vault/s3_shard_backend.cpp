#include "s3_shard_backend.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include "at_rest_crypto.hpp"

namespace vault_gateway {

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;

namespace {

std::string sha256_hex(const uint8_t* data, std::size_t len) {
    std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
    SHA256(data, len, digest.data());
    return vault_crypto::bytes_to_hex(digest.data(), digest.size());
}

std::string sha256_hex(std::string_view text) {
    return sha256_hex(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

std::vector<uint8_t> hmac_sha256_raw(const uint8_t* key, std::size_t key_len,
                                     const uint8_t* msg, std::size_t msg_len) {
    std::array<uint8_t, EVP_MAX_MD_SIZE> out{};
    unsigned int out_len = 0;
    if (!HMAC(EVP_sha256(), key, static_cast<int>(key_len), msg, msg_len, out.data(), &out_len) ||
        out_len != 32) {
        throw std::runtime_error("S3MultiBucketShardBackend: HMAC-SHA256 failure");
    }
    return std::vector<uint8_t>(out.begin(), out.begin() + out_len);
}

std::vector<uint8_t> hmac_sha256_raw(std::string_view key, std::string_view msg) {
    return hmac_sha256_raw(reinterpret_cast<const uint8_t*>(key.data()), key.size(),
                           reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
}

std::vector<uint8_t> hmac_sha256_raw(const std::vector<uint8_t>& key, std::string_view msg) {
    return hmac_sha256_raw(key.data(), key.size(),
                           reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
}

std::string uri_encode_path(std::string_view path) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(path.size());
    for (unsigned char c : path) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~' || c == '/') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0F]);
        }
    }
    return out;
}

std::string current_amz_date() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_utc{};
#ifdef _WIN32
    gmtime_s(&tm_utc, &t);
#else
    gmtime_r(&t, &tm_utc);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm_utc, "%Y%m%dT%H%M%SZ");
    return ss.str();
}

std::string make_host_header(const S3BucketConfig& cfg) {
    const bool is_default_port =
        (!cfg.use_tls && cfg.port == "80") || (cfg.use_tls && cfg.port == "443") || cfg.port.empty();
    if (is_default_port) {
        return cfg.host;
    }
    return cfg.host + ":" + cfg.port;
}

std::string make_canonical_uri(const S3BucketConfig& cfg, std::string_view object_key) {
    std::string path = "/" + cfg.bucket;
    if (!cfg.key_prefix.empty()) {
        std::string trimmed = cfg.key_prefix;
        while (!trimmed.empty() && trimmed.front() == '/') trimmed.erase(trimmed.begin());
        while (!trimmed.empty() && trimmed.back() == '/') trimmed.pop_back();
        if (!trimmed.empty()) path += "/" + trimmed;
    }
    std::string clean_key(object_key);
    while (!clean_key.empty() && clean_key.front() == '/') clean_key.erase(clean_key.begin());
    path += "/" + clean_key;
    return uri_encode_path(path);
}

std::string shard_object_key(const std::filesystem::path& blob_name, std::size_t shard_index) {
    return blob_name.filename().string() + ".shard" + std::to_string(shard_index);
}

struct HttpResponseData {
    unsigned status = 0;
    std::vector<uint8_t> body;
};

struct S3OpContext {
    http::verb verb;
    std::chrono::milliseconds timeout;
    http::request<http::vector_body<uint8_t>> req;
    http::response<http::vector_body<uint8_t>> res;
    http::response_parser<http::vector_body<uint8_t>> head_parser;
    beast::flat_buffer buf;
    HttpResponseData out;
    std::optional<std::string> async_err;

    void set_error(const std::string& stage, const beast::error_code& ec) {
        async_err = stage + ": " + ec.message();
    }
};

template <typename Stream, typename CloseFn>
void async_write_and_read_s3(Stream& stream, S3OpContext& ctx, CloseFn close_fn) {
    beast::get_lowest_layer(stream).expires_after(ctx.timeout);
    http::async_write(
        stream, ctx.req,
        [&stream, &ctx, close_fn](const beast::error_code& ec3, std::size_t) {
            if (ec3) return ctx.set_error("write", ec3);
            beast::get_lowest_layer(stream).expires_after(ctx.timeout);
            if (ctx.verb == http::verb::head) {
                ctx.head_parser.skip(true);
                http::async_read(
                    stream, ctx.buf, ctx.head_parser,
                    [&ctx, close_fn](const beast::error_code& ec4, std::size_t) {
                        if (ec4) return ctx.set_error("read_head", ec4);
                        ctx.out.status = ctx.head_parser.get().result_int();
                        close_fn();
                    });
            } else {
                http::async_read(
                    stream, ctx.buf, ctx.res,
                    [&ctx, close_fn](const beast::error_code& ec4, std::size_t) {
                        if (ec4) return ctx.set_error("read", ec4);
                        ctx.out.status = ctx.res.result_int();
                        ctx.out.body = std::move(ctx.res.body());
                        close_fn();
                    });
            }
        });
}

HttpResponseData perform_s3_request(http::verb verb,
                                    const S3BucketConfig& cfg,
                                    std::string_view object_key,
                                    const std::vector<uint8_t>& body) {
    std::string method_str(http::to_string(verb));
    const AwsSigV4SignedHeaders sig = sign_aws_v4(method_str, cfg, object_key, body);

    S3OpContext ctx{
        verb,
        std::chrono::milliseconds(cfg.timeout_ms > 0 ? cfg.timeout_ms : 5000),
        http::request<http::vector_body<uint8_t>>{verb, sig.canonical_uri, 11},
        {},
        {},
        {},
        {},
        std::nullopt
    };
    ctx.req.set(http::field::host, sig.host_header);
    ctx.req.set(http::field::user_agent, "BlindVault-S3Backend/1.0");
    ctx.req.set("x-amz-date", sig.amz_date);
    ctx.req.set("x-amz-content-sha256", sig.content_sha256_hex);
    ctx.req.set(http::field::authorization, sig.authorization);

    if (verb == http::verb::put) {
        ctx.req.set(http::field::content_type, "application/octet-stream");
        ctx.req.body() = body;
        ctx.req.prepare_payload();
    }

    net::io_context ioc;
    tcp::resolver resolver{ioc};

    if (!cfg.use_tls) {
        beast::tcp_stream stream{ioc};
        auto close_fn = [&stream]() {
            beast::error_code ignored;
            stream.socket().shutdown(tcp::socket::shutdown_both, ignored);
        };

        resolver.async_resolve(
            cfg.host, cfg.port,
            [&](const beast::error_code& ec, const tcp::resolver::results_type& results) {
                if (ec) return ctx.set_error("resolve", ec);
                stream.expires_after(ctx.timeout);
                stream.async_connect(
                    results,
                    [&](const beast::error_code& ec2, const tcp::resolver::results_type::endpoint_type&) {
                        if (ec2) return ctx.set_error("connect", ec2);
                        async_write_and_read_s3(stream, ctx, close_fn);
                    });
            });

        ioc.run();
    } else {
        ssl::context ssl_ctx{ssl::context::tls_client};
        ssl_ctx.set_default_verify_paths();
        if (!cfg.ca_file.empty()) {
            ssl_ctx.load_verify_file(cfg.ca_file);
        }
        ssl_ctx.set_verify_mode(ssl::verify_peer);

        beast::ssl_stream<beast::tcp_stream> stream{ioc, ssl_ctx};
        if (!SSL_set_tlsext_host_name(stream.native_handle(), cfg.host.c_str())) {
            throw std::runtime_error("S3MultiBucketShardBackend: failed to set TLS SNI host");
        }
        auto close_fn = [&stream]() {
            beast::error_code ignored;
            stream.shutdown(ignored);
        };

        resolver.async_resolve(
            cfg.host, cfg.port,
            [&](const beast::error_code& ec, const tcp::resolver::results_type& results) {
                if (ec) return ctx.set_error("resolve", ec);
                beast::get_lowest_layer(stream).expires_after(ctx.timeout);
                beast::get_lowest_layer(stream).async_connect(
                    results,
                    [&](const beast::error_code& ec2, const tcp::resolver::results_type::endpoint_type&) {
                        if (ec2) return ctx.set_error("connect", ec2);
                        beast::get_lowest_layer(stream).expires_after(ctx.timeout);
                        stream.async_handshake(
                            ssl::stream_base::client,
                            [&](const beast::error_code& ec_tls) {
                                if (ec_tls) return ctx.set_error("tls_handshake", ec_tls);
                                async_write_and_read_s3(stream, ctx, close_fn);
                            });
                    });
            });

        ioc.run();
    }

    if (ctx.async_err) {
        throw std::runtime_error("S3MultiBucketShardBackend HTTP error (" + sig.host_header + "): " + *ctx.async_err);
    }
    return ctx.out;
}

const char* lookup_env(const char* name) {
    const char* val = std::getenv(name);
    return (val && val[0] != '\0') ? val : nullptr;
}

std::string lookup_shard_env(std::size_t index, std::string_view suffix, std::string_view fallback_env = {}) {
    const std::string key = "BLINDVAULT_SHARD" + std::to_string(index) + "_" + std::string(suffix);
    if (const char* v = lookup_env(key.c_str())) return v;
    if (!fallback_env.empty()) {
        std::string fb(fallback_env);
        if (const char* v = lookup_env(fb.c_str())) return v;
    }
    return {};
}

} // namespace

S3BucketConfig parse_s3_endpoint_url(std::string_view url) {
    S3BucketConfig cfg;
    std::string_view rest = url;
    if (rest.rfind("https://", 0) == 0) {
        cfg.use_tls = true;
        cfg.port = "443";
        rest.remove_prefix(8);
    } else if (rest.rfind("http://", 0) == 0) {
        cfg.use_tls = false;
        cfg.port = "80";
        rest.remove_prefix(7);
    } else {
        throw std::runtime_error("S3 URL must start with http:// or https://: " + std::string(url));
    }

    const std::size_t slash_pos = rest.find('/');
    if (slash_pos == std::string_view::npos) {
        throw std::runtime_error("S3 URL must include /<bucket>: " + std::string(url));
    }

    std::string_view authority = rest.substr(0, slash_pos);
    std::string_view path = rest.substr(slash_pos + 1);
    if (path.empty()) {
        throw std::runtime_error("S3 URL bucket name is empty: " + std::string(url));
    }

    if (const std::size_t at_pos = authority.rfind('@'); at_pos != std::string_view::npos) {
        const std::string_view userinfo = authority.substr(0, at_pos);
        authority = authority.substr(at_pos + 1);
        if (const std::size_t colon_pos = userinfo.find(':'); colon_pos != std::string_view::npos) {
            cfg.access_key = std::string(userinfo.substr(0, colon_pos));
            cfg.secret_key = std::string(userinfo.substr(colon_pos + 1));
        } else {
            cfg.access_key = std::string(userinfo);
        }
    }

    if (!authority.empty() && authority.front() == '[') {
        const std::size_t close_bracket = authority.find(']');
        if (close_bracket == std::string_view::npos) {
            throw std::runtime_error("S3 URL malformed IPv6 host: " + std::string(url));
        }
        cfg.host = std::string(authority.substr(1, close_bracket - 1));
        if (close_bracket + 1 < authority.size() && authority[close_bracket + 1] == ':') {
            cfg.port = std::string(authority.substr(close_bracket + 2));
        }
    } else if (const std::size_t colon_pos = authority.rfind(':'); colon_pos != std::string_view::npos) {
        cfg.host = std::string(authority.substr(0, colon_pos));
        cfg.port = std::string(authority.substr(colon_pos + 1));
    } else {
        cfg.host = std::string(authority);
    }

    if (cfg.host.empty() || cfg.port.empty()) {
        throw std::runtime_error("S3 URL missing host or port: " + std::string(url));
    }

    const std::size_t next_slash = path.find('/');
    if (next_slash == std::string_view::npos) {
        cfg.bucket = std::string(path);
    } else {
        cfg.bucket = std::string(path.substr(0, next_slash));
        cfg.key_prefix = std::string(path.substr(next_slash + 1));
        while (!cfg.key_prefix.empty() && cfg.key_prefix.back() == '/') {
            cfg.key_prefix.pop_back();
        }
    }

    if (cfg.bucket.empty()) {
        throw std::runtime_error("S3 URL bucket name cannot be empty: " + std::string(url));
    }
    return cfg;
}

AwsSigV4SignedHeaders sign_aws_v4(std::string_view method,
                                   const S3BucketConfig& config,
                                   std::string_view object_key,
                                   const std::vector<uint8_t>& body,
                                   std::string_view override_amz_date) {
    if (config.access_key.empty() || config.secret_key.empty()) {
        throw std::runtime_error("S3MultiBucketShardBackend: access_key and secret_key are required");
    }

    AwsSigV4SignedHeaders out;
    out.host_header = make_host_header(config);
    out.amz_date = override_amz_date.empty() ? current_amz_date() : std::string(override_amz_date);
    if (out.amz_date.size() < 8) {
        throw std::runtime_error("S3MultiBucketShardBackend: invalid x-amz-date format");
    }
    const std::string date_stamp = out.amz_date.substr(0, 8);
    out.canonical_uri = make_canonical_uri(config, object_key);
    out.content_sha256_hex = sha256_hex(body.data(), body.size());

    const std::string region = config.region.empty() ? "us-east-1" : config.region;
    const std::string signed_headers = "host;x-amz-content-sha256;x-amz-date";

    std::ostringstream canonical_req;
    canonical_req << method << '\n'
                  << out.canonical_uri << '\n'
                  << '\n' // empty query string
                  << "host:" << out.host_header << '\n'
                  << "x-amz-content-sha256:" << out.content_sha256_hex << '\n'
                  << "x-amz-date:" << out.amz_date << '\n'
                  << '\n'
                  << signed_headers << '\n'
                  << out.content_sha256_hex;

    const std::string scope = date_stamp + "/" + region + "/s3/aws4_request";
    const std::string string_to_sign =
        "AWS4-HMAC-SHA256\n" + out.amz_date + "\n" + scope + "\n" +
        sha256_hex(canonical_req.str());

    const auto k_date = hmac_sha256_raw("AWS4" + config.secret_key, date_stamp);
    const auto k_region = hmac_sha256_raw(k_date, region);
    const auto k_service = hmac_sha256_raw(k_region, "s3");
    const auto k_signing = hmac_sha256_raw(k_service, "aws4_request");
    const auto sig_raw = hmac_sha256_raw(k_signing, string_to_sign);
    const std::string sig_hex = vault_crypto::bytes_to_hex(sig_raw.data(), sig_raw.size());

    out.authorization =
        "AWS4-HMAC-SHA256 Credential=" + config.access_key + "/" + scope +
        ", SignedHeaders=" + signed_headers +
        ", Signature=" + sig_hex;

    return out;
}

S3MultiBucketShardBackend::S3MultiBucketShardBackend(std::array<S3BucketConfig, 3> buckets)
    : buckets_(std::move(buckets)) {
    for (std::size_t i = 0; i < 3; ++i) {
        if (buckets_[i].host.empty() || buckets_[i].bucket.empty()) {
            throw std::runtime_error(
                "S3MultiBucketShardBackend: shard " + std::to_string(i) + " config is incomplete");
        }
    }
}

void S3MultiBucketShardBackend::write_shard(const std::filesystem::path& blob_name,
                                            std::size_t shard_index,
                                            const std::vector<uint8_t>& shard) {
    const auto& cfg = bucket_config(shard_index);
    const std::string key = shard_object_key(blob_name, shard_index);
    const auto resp = perform_s3_request(http::verb::put, cfg, key, shard);
    if (resp.status < 200 || resp.status >= 300) {
        throw std::runtime_error(
            "S3MultiBucketShardBackend: PUT failed for shard " + std::to_string(shard_index) +
            " (" + key + ") HTTP status " + std::to_string(resp.status));
    }
}

std::optional<std::vector<uint8_t>> S3MultiBucketShardBackend::read_shard(
    const std::filesystem::path& blob_name,
    std::size_t shard_index) {
    if (shard_index >= 3) return std::nullopt;
    const auto& cfg = buckets_[shard_index];
    const std::string key = shard_object_key(blob_name, shard_index);
    try {
        const auto resp = perform_s3_request(http::verb::get, cfg, key, {});
        if (resp.status >= 200 && resp.status < 300) {
            return resp.body;
        }
        return std::nullopt;
    } catch (...) {
        // An unreachable/offline shard bucket degrades cleanly to missing shard so 2-of-3 survives.
        return std::nullopt;
    }
}

bool S3MultiBucketShardBackend::head_shard(const std::filesystem::path& blob_name,
                                           std::size_t shard_index) {
    if (shard_index >= 3) return false;
    const auto& cfg = buckets_[shard_index];
    const std::string key = shard_object_key(blob_name, shard_index);
    try {
        const auto resp = perform_s3_request(http::verb::head, cfg, key, {});
        return resp.status >= 200 && resp.status < 300;
    } catch (...) {
        return false;
    }
}

const S3BucketConfig& S3MultiBucketShardBackend::bucket_config(std::size_t shard_index) const {
    if (shard_index >= 3) {
        throw std::out_of_range("S3MultiBucketShardBackend: shard_index must be 0, 1, or 2");
    }
    return buckets_[shard_index];
}

std::shared_ptr<S3MultiBucketShardBackend> create_s3_shard_backend_from_env() {
    std::array<const char*, 3> urls = {
        lookup_env("BLINDVAULT_SHARD0_URL"),
        lookup_env("BLINDVAULT_SHARD1_URL"),
        lookup_env("BLINDVAULT_SHARD2_URL"),
    };

    const std::size_t configured_count =
        (urls[0] ? 1u : 0u) + (urls[1] ? 1u : 0u) + (urls[2] ? 1u : 0u);
    if (configured_count == 0) {
        return nullptr;
    }
    if (configured_count != 3) {
        throw std::runtime_error(
            "S3MultiBucketShardBackend: all three BLINDVAULT_SHARD{0,1,2}_URL variables must be set");
    }

    std::array<S3BucketConfig, 3> configs;
    const std::string shared_ca = lookup_env("BLINDVAULT_S3_CA_FILE") ? lookup_env("BLINDVAULT_S3_CA_FILE") : "";
    for (std::size_t i = 0; i < 3; ++i) {
        S3BucketConfig cfg = parse_s3_endpoint_url(urls[i]);
        if (cfg.access_key.empty()) {
            cfg.access_key = lookup_shard_env(i, "ACCESS_KEY", "AWS_ACCESS_KEY_ID");
        }
        if (cfg.secret_key.empty()) {
            cfg.secret_key = lookup_shard_env(i, "SECRET_KEY", "AWS_SECRET_ACCESS_KEY");
        }
        const std::string env_region = lookup_shard_env(i, "REGION", "AWS_REGION");
        if (!env_region.empty()) {
            cfg.region = env_region;
        } else if (const char* def_reg = lookup_env("AWS_DEFAULT_REGION")) {
            cfg.region = def_reg;
        }
        if (!shared_ca.empty()) {
            cfg.ca_file = shared_ca;
        }
        if (cfg.access_key.empty() || cfg.secret_key.empty()) {
            throw std::runtime_error(
                "S3MultiBucketShardBackend: missing AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY for shard " +
                std::to_string(i));
        }
        configs[i] = std::move(cfg);
    }

    return std::make_shared<S3MultiBucketShardBackend>(std::move(configs));
}

} // namespace vault_gateway
