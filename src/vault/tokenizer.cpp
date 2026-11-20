#include "tokenizer.hpp"

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

namespace vault_token {

std::size_t split_csv_line_views(std::string_view line, std::array<std::string_view, 8>& out_views) noexcept {
    if (line.find('"') != std::string_view::npos) {
        return 0;
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

std::vector<std::string> parse_csv_row(std::string_view line) {
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

void append_escaped_csv_field(std::string& out, std::string_view field) {
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

std::string escape_csv_field(std::string_view field) {
    std::string out;
    out.reserve(field.size() + 2);
    append_escaped_csv_field(out, field);
    return out;
}

std::string format_csv_row(const std::vector<std::string>& cols) {
    std::string out;
    for (std::size_t i = 0; i < cols.size(); ++i) {
        if (i > 0) out.push_back(',');
        append_escaped_csv_field(out, cols[i]);
    }
    return out;
}

TokenVault::TokenVault(std::filesystem::path storage_path,
                       std::shared_ptr<vault_kms::KeyManagementProvider> kms,
                       const std::array<uint8_t, 32>& pepper)
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

TokenVault::~TokenVault() {
    if (hmac_ctx_) {
        EVP_MAC_CTX_free(hmac_ctx_);
        hmac_ctx_ = nullptr;
    }
    if (hmac_alg_) {
        EVP_MAC_free(hmac_alg_);
        hmac_alg_ = nullptr;
    }
    OPENSSL_cleanse(pepper_.data(), pepper_.size());
}

std::unordered_map<std::string, std::string> TokenVault::rotate_kms_pepper() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_map<std::string, std::string> old_to_new;
    old_to_new.reserve(reverse_map_.size());
    pepper_ = kms_->derive_tokenizer_pepper();
    init_hmac_ctx();

    auto old_reverse = std::move(reverse_map_);
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

std::string TokenVault::tokenize(std::string_view raw_value) {
    if (raw_value.empty()) return "";
    if (raw_value.rfind("TOK_", 0) == 0) return std::string(raw_value);

    std::lock_guard<std::mutex> lock(mutex_);
    return std::string(tokenize_view_unlocked(raw_value));
}

std::optional<std::string> TokenVault::detokenize(std::string_view token) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = reverse_map_.find(token);
    if (it == reverse_map_.end()) return std::nullopt;
    return it->second;
}

TransactionRecord TokenVault::sanitize_record(const TransactionRecord& raw, SanitizeStats* stats) {
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

TransactionRecord TokenVault::rehydrate_record(const TransactionRecord& clean) const {
    std::lock_guard<std::mutex> lock(mutex_);
    TransactionRecord restored = clean;
    if (auto it = reverse_map_.find(clean.customer_name); it != reverse_map_.end()) restored.customer_name = it->second;
    if (auto it = reverse_map_.find(clean.national_id);   it != reverse_map_.end()) restored.national_id   = it->second;
    if (auto it = reverse_map_.find(clean.iban);          it != reverse_map_.end()) restored.iban          = it->second;
    return restored;
}

void TokenVault::sanitize_single_line_unlocked(std::string_view line,
                                               std::string& line_out,
                                               std::array<std::string_view, 8>& views,
                                               SanitizeStats* out_stats,
                                               std::unordered_set<std::string>* out_tokens) {
    if (split_csv_line_views(line, views) == 8) {
        const std::string_view c_tok = tokenize_view_unlocked(views[2]);
        const std::string_view n_tok = tokenize_view_unlocked(views[3]);
        const std::string_view i_tok = tokenize_view_unlocked(views[4]);

        line_out.append(views[0]); line_out.push_back(',');
        line_out.append(views[1]); line_out.push_back(',');
        line_out.append(c_tok);    line_out.push_back(',');
        line_out.append(n_tok);    line_out.push_back(',');
        line_out.append(i_tok);    line_out.push_back(',');
        line_out.append("REDACTED_IP,");
        line_out.append(views[6]); line_out.push_back(',');
        line_out.append(views[7]); line_out.push_back('\n');

        if (out_tokens) {
            if (!c_tok.empty()) out_tokens->emplace(c_tok);
            if (!n_tok.empty()) out_tokens->emplace(n_tok);
            if (!i_tok.empty()) out_tokens->emplace(i_tok);
        }
        if (out_stats) {
            out_stats->records_processed += 1;
            out_stats->pii_fields_tokenized += 3;
            if (!views[5].empty()) out_stats->ips_masked += 1;
        }
    } else {
        const auto cols = parse_csv_row(line);
        if (cols.size() < 8) return;

        const std::string_view c_tok = tokenize_view_unlocked(cols[2]);
        const std::string_view n_tok = tokenize_view_unlocked(cols[3]);
        const std::string_view i_tok = tokenize_view_unlocked(cols[4]);

        append_escaped_csv_field(line_out, cols[0]); line_out.push_back(',');
        append_escaped_csv_field(line_out, cols[1]); line_out.push_back(',');
        line_out.append(c_tok);                      line_out.push_back(',');
        line_out.append(n_tok);                      line_out.push_back(',');
        line_out.append(i_tok);                      line_out.push_back(',');
        line_out.append("REDACTED_IP,");
        append_escaped_csv_field(line_out, cols[6]); line_out.push_back(',');
        append_escaped_csv_field(line_out, cols[7]); line_out.push_back('\n');

        if (out_tokens) {
            if (!c_tok.empty()) out_tokens->emplace(c_tok);
            if (!n_tok.empty()) out_tokens->emplace(n_tok);
            if (!i_tok.empty()) out_tokens->emplace(i_tok);
        }
        if (out_stats) {
            out_stats->records_processed += 1;
            out_stats->pii_fields_tokenized += 3;
            if (!cols[5].empty()) out_stats->ips_masked += 1;
        }
    }
}

std::string TokenVault::sanitize_csv_batch(std::string_view csv_text, SanitizeStats* out_stats) {
    std::string out;
    out.reserve(csv_text.size() + csv_text.size() / 8 + 128);
    out.append("tx_id,timestamp,customer_token,national_id_token,iban_token,ip_status,amount_egp,merchant\n");

    {
        std::lock_guard<std::mutex> lock(mutex_);
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

            sanitize_single_line_unlocked(line, out, views, out_stats, nullptr);
        }
    }

    flush();
    return out;
}

void TokenVault::sanitize_csv_stream(std::istream& in,
                                     std::ostream& out,
                                     SanitizeStats* out_stats,
                                     std::unordered_set<std::string>* out_tokens) {
    static constexpr const char kHeader[] =
        "tx_id,timestamp,customer_token,national_id_token,iban_token,ip_status,amount_egp,merchant\n";
    out.write(kHeader, sizeof(kHeader) - 1);

    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string raw_line;
        std::string row_buf;
        row_buf.reserve(512);
        std::array<std::string_view, 8> views{};
        bool first_line = true;

        while (std::getline(in, raw_line)) {
            std::string_view line(raw_line);
            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            if (line.empty()) continue;
            if (first_line && line.rfind("tx_id,", 0) == 0) {
                first_line = false;
                OPENSSL_cleanse(raw_line.data(), raw_line.size());
                continue;
            }
            first_line = false;

            row_buf.clear();
            sanitize_single_line_unlocked(line, row_buf, views, out_stats, out_tokens);
            if (!row_buf.empty()) {
                out.write(row_buf.data(), static_cast<std::streamsize>(row_buf.size()));
            }
            OPENSSL_cleanse(raw_line.data(), raw_line.size());
        }
        OPENSSL_cleanse(row_buf.data(), row_buf.capacity());
    }

    out.flush();
    flush();
}

std::string TokenVault::rehydrate_csv_batch(std::string_view sanitized_csv) const {
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

void TokenVault::rehydrate_csv_stream(std::istream& in, std::ostream& out) const {
    static constexpr const char kHeader[] =
        "tx_id,timestamp,customer_name,national_id,iban,ip_status,amount_egp,merchant\n";
    out.write(kHeader, sizeof(kHeader) - 1);

    std::lock_guard<std::mutex> lock(mutex_);
    std::string raw_line;
    std::string row_buf;
    row_buf.reserve(512);
    std::array<std::string_view, 8> views{};
    bool first_line = true;

    auto lookup = [this](std::string_view tok) -> std::string_view {
        auto it = reverse_map_.find(tok);
        return (it != reverse_map_.end()) ? std::string_view(it->second) : tok;
    };

    while (std::getline(in, raw_line)) {
        std::string_view line(raw_line);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) continue;
        if (first_line && line.rfind("tx_id,", 0) == 0) {
            first_line = false;
            continue;
        }
        first_line = false;

        row_buf.clear();
        if (split_csv_line_views(line, views) == 8) {
            append_escaped_csv_field(row_buf, views[0]);         row_buf.push_back(',');
            append_escaped_csv_field(row_buf, views[1]);         row_buf.push_back(',');
            append_escaped_csv_field(row_buf, lookup(views[2])); row_buf.push_back(',');
            append_escaped_csv_field(row_buf, lookup(views[3])); row_buf.push_back(',');
            append_escaped_csv_field(row_buf, lookup(views[4])); row_buf.push_back(',');
            append_escaped_csv_field(row_buf, views[5]);         row_buf.push_back(',');
            append_escaped_csv_field(row_buf, views[6]);         row_buf.push_back(',');
            append_escaped_csv_field(row_buf, views[7]);         row_buf.push_back('\n');
        } else {
            const auto cols = parse_csv_row(line);
            if (cols.size() < 8) continue;
            append_escaped_csv_field(row_buf, cols[0]);         row_buf.push_back(',');
            append_escaped_csv_field(row_buf, cols[1]);         row_buf.push_back(',');
            append_escaped_csv_field(row_buf, lookup(cols[2])); row_buf.push_back(',');
            append_escaped_csv_field(row_buf, lookup(cols[3])); row_buf.push_back(',');
            append_escaped_csv_field(row_buf, lookup(cols[4])); row_buf.push_back(',');
            append_escaped_csv_field(row_buf, cols[5]);         row_buf.push_back(',');
            append_escaped_csv_field(row_buf, cols[6]);         row_buf.push_back(',');
            append_escaped_csv_field(row_buf, cols[7]);         row_buf.push_back('\n');
        }
        out.write(row_buf.data(), static_cast<std::streamsize>(row_buf.size()));
    }
    OPENSSL_cleanse(row_buf.data(), row_buf.capacity());
    out.flush();
}

void TokenVault::flush() {
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

std::size_t TokenVault::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return reverse_map_.size();
}

void TokenVault::init_hmac_ctx() {
    if (!hmac_alg_) {
        hmac_alg_ = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
        if (!hmac_alg_) {
            throw std::runtime_error("TokenVault: EVP_MAC_fetch(HMAC) failed");
        }
    }
    if (!hmac_ctx_) {
        hmac_ctx_ = EVP_MAC_CTX_new(hmac_alg_);
        if (!hmac_ctx_) {
            throw std::runtime_error("TokenVault: EVP_MAC_CTX_new failed");
        }
    }
    char digest_name[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0),
        OSSL_PARAM_construct_end()
    };
    if (EVP_MAC_init(hmac_ctx_, pepper_.data(), pepper_.size(), params) != 1) {
        throw std::runtime_error("TokenVault: EVP_MAC_init failed");
    }
}

std::string_view TokenVault::tokenize_view_unlocked(std::string_view raw_value) {
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

std::string TokenVault::compute_token_unlocked(std::string_view input) const {
    unsigned char digest[EVP_MAX_MD_SIZE];
    std::size_t digest_len = 0;
    if (EVP_MAC_init(hmac_ctx_, nullptr, 0, nullptr) != 1 ||
        EVP_MAC_update(hmac_ctx_, reinterpret_cast<const unsigned char*>(input.data()), input.size()) != 1 ||
        EVP_MAC_final(hmac_ctx_, digest, &digest_len, sizeof(digest)) != 1 || digest_len < 8) {
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

void TokenVault::load_unlocked() {
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

} // namespace vault_token
