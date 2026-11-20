#pragma once
// High-speed PII & IP scrubber / deterministic tokenizer with RFC 4180 CSV support
// and AES-256-GCM + RFC 3394 KMS-wrapped envelope encryption at rest ("BVTK").

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "at_rest_crypto.hpp"
#include "kms_provider.hpp"

namespace vault_token {

inline constexpr std::array<uint8_t, 4> TOKEN_FILE_MAGIC = {'B', 'V', 'T', 'K'};
inline constexpr std::size_t WRAPPED_HEX_LEN = vault_crypto::WRAPPED_KEY_LEN * 2; // 80 chars

struct TransactionRecord {
    std::string tx_id;
    std::string timestamp;
    std::string customer_name;
    std::string national_id;
    std::string iban;
    std::string source_ip;
    std::string amount_egp;
    std::string merchant;
};

struct SanitizeStats {
    std::size_t records_processed = 0;
    std::size_t pii_fields_tokenized = 0;
    std::size_t ips_masked = 0;
};

struct TransparentStringHash {
    using is_transparent = void;
    std::size_t operator()(std::string_view sv) const noexcept {
        return std::hash<std::string_view>{}(sv);
    }
    std::size_t operator()(const std::string& s) const noexcept {
        return std::hash<std::string_view>{}(s);
    }
};

struct TransparentStringEqual {
    using is_transparent = void;
    bool operator()(std::string_view lhs, std::string_view rhs) const noexcept {
        return lhs == rhs;
    }
};

// Zero-copy fast path for unquoted CSV lines; falls back cleanly to RFC 4180 unescaping only when quotes exist
inline std::size_t split_csv_line_views(std::string_view line, std::array<std::string_view, 8>& out_views) noexcept {
    if (line.find('"') != std::string_view::npos) {
        return 0; // Signal caller to use quoted RFC 4180 parser
    }
    std::size_t start = 0;
    std::size_t count = 0;
    while (count < 8) {
        const std::size_t comma = line.find(',', start);
        if (comma == std::string_view::npos) {
            out_views[count++] = line.substr(start);
            break;
        }
        out_views[count++] = line.substr(start, comma - start);
        start = comma + 1;
    }
    return count;
}

inline std::vector<std::string> parse_csv_row(std::string_view line) {
    std::vector<std::string> fields;
    fields.reserve(8);
    std::string cur;
    bool in_quotes = false;

    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (in_quotes) {
            if (c == '"') {
                if (i + 1 < line.size() && line[i + 1] == '"') {
                    cur.push_back('"');
                    ++i;
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push_back(c);
            }
        } else {
            if (c == '"') {
                in_quotes = true;
            } else if (c == ',') {
                fields.push_back(std::move(cur));
                cur.clear();
            } else {
                cur.push_back(c);
            }
        }
    }
    fields.push_back(std::move(cur));
    return fields;
}

inline void append_escaped_csv_field(std::string& out, std::string_view field) {
    if (field.find_first_of(",\"\r\n") == std::string_view::npos) {
        out.append(field);
        return;
    }
    out.push_back('"');
    for (char c : field) {
        if (c == '"') out.push_back('"');
        out.push_back(c);
    }
    out.push_back('"');
}

inline std::string escape_csv_field(std::string_view field) {
    std::string out;
    out.reserve(field.size() + 2);
    append_escaped_csv_field(out, field);
    return out;
}

inline std::string format_csv_row(const std::vector<std::string>& cols) {
    std::string out;
    for (std::size_t i = 0; i < cols.size(); ++i) {
        if (i > 0) out.push_back(',');
        append_escaped_csv_field(out, cols[i]);
    }
    return out;
}

class TokenVault {
public:
    TokenVault(std::filesystem::path storage_path,
               std::shared_ptr<vault_kms::KeyManagementProvider> kms,
               const std::array<uint8_t, 32> &pepper = {})
        : storage_path_(std::move(storage_path)),
          kms_(std::move(kms)),
          pepper_(pepper) {
        if (!kms_) {
            throw std::runtime_error("TokenVault: KeyManagementProvider cannot be null");
        }
        if (pepper_ == std::array<uint8_t, 32>{}) {
            pepper_ = kms_->derive_tokenizer_pepper();
        }
        init_hmac_ctx();
        load_unlocked();
    }

    ~TokenVault() {
        if (hmac_ctx_) {
            HMAC_CTX_free(hmac_ctx_);
            hmac_ctx_ = nullptr;
        }
        OPENSSL_cleanse(pepper_.data(), pepper_.size());
    }

    TokenVault(const TokenVault&) = delete;
    TokenVault& operator=(const TokenVault&) = delete;

    std::unordered_map<std::string, std::string> rotate_kms_pepper() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::unordered_map<std::string, std::string> old_to_new;
        old_to_new.reserve(reverse_map_.size());
        pepper_ = kms_->derive_tokenizer_pepper();
        init_hmac_ctx();

        std::unordered_map<std::string, std::string, TransparentStringHash, TransparentStringEqual> old_reverse = std::move(reverse_map_);
        forward_map_.clear();
        reverse_map_.clear();
        forward_map_.reserve(old_reverse.size());
        reverse_map_.reserve(old_reverse.size());

        for (const auto& [old_token, raw] : old_reverse) {
            const std::string token = compute_token_unlocked(raw);
            old_to_new[old_token] = token;
            forward_map_[raw] = token;
            reverse_map_[token] = raw;
        }
        dirty_ = !old_reverse.empty();
        return old_to_new;
    }

    std::string tokenize(std::string_view raw_value) {
        if (raw_value.empty()) return "";
        if (raw_value.rfind("TOK_", 0) == 0) return std::string(raw_value);

        std::lock_guard<std::mutex> lock(mutex_);
        return std::string(tokenize_view_unlocked(raw_value));
    }

    std::optional<std::string> detokenize(std::string_view token) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = reverse_map_.find(token);
        if (it == reverse_map_.end()) return std::nullopt;
        return it->second;
    }

    TransactionRecord sanitize_record(const TransactionRecord& raw, SanitizeStats* stats = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        TransactionRecord clean;
        clean.tx_id         = raw.tx_id;
        clean.timestamp     = raw.timestamp;
        clean.customer_name = std::string(tokenize_view_unlocked(raw.customer_name));
        clean.national_id   = std::string(tokenize_view_unlocked(raw.national_id));
        clean.iban          = std::string(tokenize_view_unlocked(raw.iban));
        clean.source_ip     = "REDACTED_IP";
        clean.amount_egp    = raw.amount_egp;
        clean.merchant      = raw.merchant;

        if (stats) {
            stats->records_processed += 1;
            stats->pii_fields_tokenized += 3;
            if (!raw.source_ip.empty()) stats->ips_masked += 1;
        }
        return clean;
    }

    TransactionRecord rehydrate_record(const TransactionRecord& clean) const {
        std::lock_guard<std::mutex> lock(mutex_);
        TransactionRecord restored = clean;
        if (auto it = reverse_map_.find(clean.customer_name); it != reverse_map_.end()) restored.customer_name = it->second;
        if (auto it = reverse_map_.find(clean.national_id);   it != reverse_map_.end()) restored.national_id   = it->second;
        if (auto it = reverse_map_.find(clean.iban);          it != reverse_map_.end()) restored.iban          = it->second;
        return restored;
    }

    std::string sanitize_csv_batch(std::string_view csv_text, SanitizeStats* out_stats = nullptr) {
        std::string out;
        out.reserve(csv_text.size() + csv_text.size() / 8 + 128);
        out.append("tx_id,timestamp,customer_token,national_id_token,iban_token,ip_status,amount_egp,merchant\n");

        {
            std::lock_guard<std::mutex> lock(mutex_);
            // Pre-reserve ~2.5 unique PII entries per row to prevent mid-batch rehash spikes
            const std::size_t est_entries = (csv_text.size() / 110) * 3 + 64;
            if (forward_map_.bucket_count() < est_entries) {
                forward_map_.reserve(est_entries);
                reverse_map_.reserve(est_entries);
            }

            std::size_t pos = 0;
            bool first_line = true;
            std::array<std::string_view, 8> views{};

            while (pos < csv_text.size()) {
                const std::size_t nl = csv_text.find('\n', pos);
                std::string_view line = (nl == std::string_view::npos)
                    ? csv_text.substr(pos)
                    : csv_text.substr(pos, nl - pos);
                pos = (nl == std::string_view::npos) ? csv_text.size() : (nl + 1);

                if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
                if (line.empty()) continue;
                if (first_line && line.rfind("tx_id,", 0) == 0) {
                    first_line = false;
                    continue;
                }
                first_line = false;

                if (split_csv_line_views(line, views) == 8) {
                    // Zero-allocation fast path (99.9%+ of rows)
                    const std::string_view c_tok = tokenize_view_unlocked(views[2]);
                    const std::string_view n_tok = tokenize_view_unlocked(views[3]);
                    const std::string_view i_tok = tokenize_view_unlocked(views[4]);

                    out.append(views[0]); out.push_back(',');
                    out.append(views[1]); out.push_back(',');
                    out.append(c_tok);    out.push_back(',');
                    out.append(n_tok);    out.push_back(',');
                    out.append(i_tok);    out.push_back(',');
                    out.append("REDACTED_IP,");
                    out.append(views[6]); out.push_back(',');
                    out.append(views[7]); out.push_back('\n');

                    if (out_stats) {
                        out_stats->records_processed += 1;
                        out_stats->pii_fields_tokenized += 3;
                        if (!views[5].empty()) out_stats->ips_masked += 1;
                    }
                } else {
                    // RFC 4180 quoted fallback
                    const auto cols = parse_csv_row(line);
                    if (cols.size() < 8) continue;

                    const std::string_view c_tok = tokenize_view_unlocked(cols[2]);
                    const std::string_view n_tok = tokenize_view_unlocked(cols[3]);
                    const std::string_view i_tok = tokenize_view_unlocked(cols[4]);

                    append_escaped_csv_field(out, cols[0]); out.push_back(',');
                    append_escaped_csv_field(out, cols[1]); out.push_back(',');
                    out.append(c_tok);                      out.push_back(',');
                    out.append(n_tok);                      out.push_back(',');
                    out.append(i_tok);                      out.push_back(',');
                    out.append("REDACTED_IP,");
                    append_escaped_csv_field(out, cols[6]); out.push_back(',');
                    append_escaped_csv_field(out, cols[7]); out.push_back('\n');

                    if (out_stats) {
                        out_stats->records_processed += 1;
                        out_stats->pii_fields_tokenized += 3;
                        if (!cols[5].empty()) out_stats->ips_masked += 1;
                    }
                }
            }
        }

        flush();
        return out;
    }

    std::string rehydrate_csv_batch(std::string_view sanitized_csv) const {
        std::string out;
        out.reserve(sanitized_csv.size() + sanitized_csv.size() / 4 + 128);
        out.append("tx_id,timestamp,customer_name,national_id,iban,ip_status,amount_egp,merchant\n");

        std::lock_guard<std::mutex> lock(mutex_);
        std::size_t pos = 0;
        bool first_line = true;
        std::array<std::string_view, 8> views{};

        auto lookup = [this](std::string_view tok) -> std::string_view {
            auto it = reverse_map_.find(tok);
            return (it != reverse_map_.end()) ? std::string_view(it->second) : tok;
        };

        while (pos < sanitized_csv.size()) {
            const std::size_t nl = sanitized_csv.find('\n', pos);
            std::string_view line = (nl == std::string_view::npos)
                ? sanitized_csv.substr(pos)
                : sanitized_csv.substr(pos, nl - pos);
            pos = (nl == std::string_view::npos) ? sanitized_csv.size() : (nl + 1);

            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            if (line.empty()) continue;
            if (first_line && line.rfind("tx_id,", 0) == 0) {
                first_line = false;
                continue;
            }
            first_line = false;

            if (split_csv_line_views(line, views) == 8) {
                append_escaped_csv_field(out, views[0]);         out.push_back(',');
                append_escaped_csv_field(out, views[1]);         out.push_back(',');
                append_escaped_csv_field(out, lookup(views[2])); out.push_back(',');
                append_escaped_csv_field(out, lookup(views[3])); out.push_back(',');
                append_escaped_csv_field(out, lookup(views[4])); out.push_back(',');
                append_escaped_csv_field(out, views[5]);         out.push_back(',');
                append_escaped_csv_field(out, views[6]);         out.push_back(',');
                append_escaped_csv_field(out, views[7]);         out.push_back('\n');
            } else {
                const auto cols = parse_csv_row(line);
                if (cols.size() < 8) continue;
                append_escaped_csv_field(out, cols[0]);         out.push_back(',');
                append_escaped_csv_field(out, cols[1]);         out.push_back(',');
                append_escaped_csv_field(out, lookup(cols[2])); out.push_back(',');
                append_escaped_csv_field(out, lookup(cols[3])); out.push_back(',');
                append_escaped_csv_field(out, lookup(cols[4])); out.push_back(',');
                append_escaped_csv_field(out, cols[5]);         out.push_back(',');
                append_escaped_csv_field(out, cols[6]);         out.push_back(',');
                append_escaped_csv_field(out, cols[7]);         out.push_back('\n');
            }
        }
        return out;
    }

    // Encrypts the token mapping under a fresh DEK wrapped by the HSM/KMS and writes atomically (0600)
    void flush() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!dirty_) return;

        std::string plaintext;
        plaintext.reserve(reverse_map_.size() * 48);
        for (const auto& [token, raw] : reverse_map_) {
            plaintext.append(token);
            plaintext.push_back('\t');
            plaintext.append(raw);
            plaintext.push_back('\n');
        }

        vault_crypto::SecretKey vault_dek = vault_crypto::generate_key();
        const std::string wrapped_dek_hex = kms_->wrap_dek_hex(vault_dek);
        const std::vector<uint8_t> ciphertext =
            vault_crypto::encrypt_envelope(
                plaintext, vault_dek, /*pad_traffic=*/false, "BVTK:v1");
        vault_dek.cleanse();
        OPENSSL_cleanse(plaintext.data(), plaintext.size());

        std::string file_blob;
        file_blob.reserve(TOKEN_FILE_MAGIC.size() + WRAPPED_HEX_LEN + ciphertext.size());
        file_blob.append(reinterpret_cast<const char*>(TOKEN_FILE_MAGIC.data()), TOKEN_FILE_MAGIC.size());
        file_blob.append(wrapped_dek_hex);
        file_blob.append(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());

        vault_crypto::write_secret_file_0600(storage_path_, file_blob);
        OPENSSL_cleanse(file_blob.data(), file_blob.size());
        dirty_ = false;
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return reverse_map_.size();
    }

private:
    void init_hmac_ctx() {
        if (!hmac_ctx_) {
            hmac_ctx_ = HMAC_CTX_new();
            if (!hmac_ctx_) {
                throw std::runtime_error("TokenVault: HMAC_CTX_new failed");
            }
        }
        if (HMAC_Init_ex(hmac_ctx_, pepper_.data(), static_cast<int>(pepper_.size()), EVP_sha256(), nullptr) != 1) {
            throw std::runtime_error("TokenVault: HMAC_Init_ex failed");
        }
    }

    // Returns a std::string_view pointing directly into forward_map_'s stable node value
    std::string_view tokenize_view_unlocked(std::string_view raw_value) {
        if (raw_value.empty()) return {};
        if (raw_value.rfind("TOK_", 0) == 0) return raw_value;

        if (auto it = forward_map_.find(raw_value); it != forward_map_.end()) {
            return it->second;
        }

        std::string key(raw_value);
        std::string token = compute_token_unlocked(key);
        reverse_map_.emplace(token, key);
        auto [inserted_it, _] = forward_map_.emplace(std::move(key), std::move(token));
        dirty_ = true;
        return inserted_it->second;
    }

    std::string compute_token_unlocked(std::string_view input) const {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        // Reuses pre-computed HMAC ipad/opad state in hmac_ctx_
        if (HMAC_Init_ex(hmac_ctx_, nullptr, 0, nullptr, nullptr) != 1 ||
            HMAC_Update(hmac_ctx_, reinterpret_cast<const unsigned char*>(input.data()), input.size()) != 1 ||
            HMAC_Final(hmac_ctx_, digest, &digest_len) != 1 || digest_len < 8) {
            throw std::runtime_error("TokenVault: HMAC-SHA256 computation failed");
        }
        static constexpr char hex[] = "0123456789abcdef";
        std::string token(20, '\0');
        token[0] = 'T'; token[1] = 'O'; token[2] = 'K'; token[3] = '_';
        for (int i = 0; i < 8; ++i) {
            token[4 + i * 2]     = hex[digest[i] >> 4];
            token[4 + i * 2 + 1] = hex[digest[i] & 0x0F];
        }
        return token;
    }

    void load_unlocked() {
        if (!std::filesystem::exists(storage_path_)) return;
        const auto bytes = vault_crypto::read_bytes_from_file(storage_path_.string());
        constexpr std::size_t prefix_len = TOKEN_FILE_MAGIC.size() + WRAPPED_HEX_LEN;

        if (bytes.size() < prefix_len ||
            std::memcmp(bytes.data(), TOKEN_FILE_MAGIC.data(), TOKEN_FILE_MAGIC.size()) != 0) {
            throw std::runtime_error("TokenVault: invalid or unencrypted token file header (expected BVTK)");
        }

        const std::string wrapped_hex(
            reinterpret_cast<const char*>(bytes.data() + TOKEN_FILE_MAGIC.size()), WRAPPED_HEX_LEN);
        vault_crypto::SecretKey vault_dek = kms_->unwrap_dek_hex(wrapped_hex);

        vault_crypto::SecretBuffer decrypted = vault_crypto::decrypt_envelope(
            bytes.data() + prefix_len, bytes.size() - prefix_len, vault_dek,
            /*unpad_traffic=*/false, "BVTK:v1");
        vault_dek.cleanse();

        std::string plaintext = decrypted.as_string();
        decrypted.cleanse();

        std::string_view sv(plaintext);
        const std::size_t approx_lines = sv.size() / 48 + 16;
        forward_map_.reserve(approx_lines);
        reverse_map_.reserve(approx_lines);

        std::size_t pos = 0;
        while (pos < sv.size()) {
            const std::size_t nl = sv.find('\n', pos);
            std::string_view line = (nl == std::string_view::npos) ? sv.substr(pos) : sv.substr(pos, nl - pos);
            pos = (nl == std::string_view::npos) ? sv.size() : (nl + 1);

            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            const std::size_t tab = line.find('\t');
            if (tab == std::string_view::npos) continue;

            std::string token(line.substr(0, tab));
            std::string raw(line.substr(tab + 1));
            reverse_map_[token] = raw;
            forward_map_[std::move(raw)] = std::move(token);
        }
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
    }

    std::filesystem::path storage_path_;
    std::shared_ptr<vault_kms::KeyManagementProvider> kms_;
    std::array<uint8_t, 32> pepper_;
    mutable HMAC_CTX* hmac_ctx_ = nullptr;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string, TransparentStringHash, TransparentStringEqual> forward_map_;
    std::unordered_map<std::string, std::string, TransparentStringHash, TransparentStringEqual> reverse_map_;
    bool dirty_ = false;
};

} // namespace vault_token