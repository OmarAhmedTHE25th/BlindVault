#pragma once
// High-speed PII & IP scrubber / deterministic tokenizer with RFC 4180 CSV support.

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "at_rest_crypto.hpp"

namespace vault_token {

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

// RFC 4180 CSV row parser: handles quoted fields containing commas and escaped "" quotes
inline std::vector<std::string> parse_csv_row(std::string_view line) {
    std::vector<std::string> fields;
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

// RFC 4180 CSV field escaper & row formatter
inline std::string escape_csv_field(std::string_view field) {
    const bool needs_quotes = field.find_first_of(",\"\r\n") != std::string_view::npos;
    if (!needs_quotes) return std::string(field);

    std::string out;
    out.reserve(field.size() + 2);
    out.push_back('"');
    for (char c : field) {
        if (c == '"') out.push_back('"');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

inline std::string format_csv_row(const std::vector<std::string>& cols) {
    std::ostringstream out;
    for (std::size_t i = 0; i < cols.size(); ++i) {
        if (i > 0) out << ',';
        out << escape_csv_field(cols[i]);
    }
    return out.str();
}

class TokenVault {
public:
    explicit TokenVault(std::filesystem::path storage_path, std::array<uint8_t, 32> pepper = {})
        : storage_path_(std::move(storage_path)), pepper_(pepper) {
        if (pepper_ == std::array<uint8_t, 32>{}) {
            if (RAND_bytes(pepper_.data(), static_cast<int>(pepper_.size())) != 1) {
                throw std::runtime_error("TokenVault: failed to generate HMAC pepper");
            }
        }
        load_unlocked();
    }

    std::string tokenize(std::string_view raw_value) {
        if (raw_value.empty()) return "";
        if (raw_value.rfind("TOK_", 0) == 0) return std::string(raw_value);

        std::string key(raw_value);
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = forward_map_.find(key);
        if (it != forward_map_.end()) {
            return it->second;
        }

        const std::string token = compute_token(key);
        forward_map_.emplace(key, token);
        reverse_map_.emplace(token, key);
        dirty_ = true;
        return token;
    }

    std::optional<std::string> detokenize(const std::string& token) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = reverse_map_.find(token);
        if (it == reverse_map_.end()) return std::nullopt;
        return it->second;
    }

    TransactionRecord sanitize_record(const TransactionRecord& raw, SanitizeStats* stats = nullptr) {
        TransactionRecord clean;
        clean.tx_id         = raw.tx_id;
        clean.timestamp     = raw.timestamp;
        clean.customer_name = tokenize(raw.customer_name);
        clean.national_id   = tokenize(raw.national_id);
        clean.iban          = tokenize(raw.iban);
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
        TransactionRecord restored = clean;
        if (auto v = detokenize(clean.customer_name)) restored.customer_name = *v;
        if (auto v = detokenize(clean.national_id))   restored.national_id   = *v;
        if (auto v = detokenize(clean.iban))          restored.iban          = *v;
        return restored;
    }

    std::string sanitize_csv_batch(std::string_view csv_text, SanitizeStats* out_stats = nullptr) {
        std::istringstream in{std::string(csv_text)};
        std::ostringstream out;
        out << "tx_id,timestamp,customer_token,national_id_token,iban_token,ip_status,amount_egp,merchant\n";

        std::string line;
        bool first_line = true;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            if (first_line && line.rfind("tx_id,", 0) == 0) {
                first_line = false;
                continue;
            }
            first_line = false;

            const auto cols = parse_csv_row(line);
            if (cols.size() < 8) continue;

            TransactionRecord raw{cols[0], cols[1], cols[2], cols[3], cols[4], cols[5], cols[6], cols[7]};
            const TransactionRecord clean = sanitize_record(raw, out_stats);
            out << format_csv_row({
                clean.tx_id, clean.timestamp, clean.customer_name,
                clean.national_id, clean.iban, clean.source_ip,
                clean.amount_egp, clean.merchant
            }) << '\n';
        }
        flush();
        return out.str();
    }

    std::string rehydrate_csv_batch(std::string_view sanitized_csv) const {
        std::istringstream in{std::string(sanitized_csv)};
        std::ostringstream out;
        out << "tx_id,timestamp,customer_name,national_id,iban,ip_status,amount_egp,merchant\n";

        std::string line;
        bool first_line = true;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            if (first_line && line.rfind("tx_id,", 0) == 0) {
                first_line = false;
                continue;
            }
            first_line = false;

            const auto cols = parse_csv_row(line);
            if (cols.size() < 8) continue;

            TransactionRecord clean{cols[0], cols[1], cols[2], cols[3], cols[4], cols[5], cols[6], cols[7]};
            const TransactionRecord restored = rehydrate_record(clean);
            out << format_csv_row({
                restored.tx_id, restored.timestamp, restored.customer_name,
                restored.national_id, restored.iban, restored.source_ip,
                restored.amount_egp, restored.merchant
            }) << '\n';
        }
        return out.str();
    }

    void flush() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!dirty_) return;
        std::ostringstream buf;
        for (const auto& [token, raw] : reverse_map_) {
            buf << token << '\t' << raw << '\n';
        }
        vault_crypto::write_secret_file_0600(storage_path_, buf.str());
        dirty_ = false;
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return reverse_map_.size();
    }

private:
    std::string compute_token(const std::string& input) const {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        if (!HMAC(EVP_sha256(),
                  pepper_.data(), static_cast<int>(pepper_.size()),
                  reinterpret_cast<const unsigned char*>(input.data()), input.size(),
                  digest, &digest_len) || digest_len < 8) {
            throw std::runtime_error("TokenVault: HMAC-SHA256 computation failed");
        }
        static constexpr char hex[] = "0123456789abcdef";
        std::string token = "TOK_";
        token.reserve(20);
        for (int i = 0; i < 8; ++i) {
            token.push_back(hex[digest[i] >> 4]);
            token.push_back(hex[digest[i] & 0x0F]);
        }
        return token;
    }

    void load_unlocked() {
        std::ifstream in(storage_path_, std::ios::binary);
        if (!in) return;
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            const std::size_t tab = line.find('\t');
            if (tab == std::string::npos) continue;
            const std::string token = line.substr(0, tab);
            const std::string raw   = line.substr(tab + 1);
            reverse_map_[token] = raw;
            forward_map_[raw]   = token;
        }
    }

    std::filesystem::path storage_path_;
    std::array<uint8_t, 32> pepper_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string> forward_map_;
    std::unordered_map<std::string, std::string> reverse_map_;
    bool dirty_ = false;
};

} // namespace vault_token