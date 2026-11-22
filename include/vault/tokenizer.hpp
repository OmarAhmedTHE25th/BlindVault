#pragma once
// High-speed PII & IP scrubber / deterministic tokenizer with RFC 4180 CSV support,
// O(1)-RAM streaming CSV sanitization, and AES-256-GCM + RFC 3394 KMS-wrapped envelope
// encryption at rest ("BVTK").

#include <array>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <openssl/evp.h>

#include "at_rest_crypto.hpp"
#include "kms_provider.hpp"

namespace vault_token {

inline constexpr std::array<uint8_t, 4> TOKEN_FILE_MAGIC = {'B', 'V', 'T', 'K'};
inline constexpr std::size_t WRAPPED_HEX_LEN = vault_crypto::WRAPPED_KEY_LEN * 2; // 80 chars
inline constexpr std::size_t TOKEN_DIGEST_BYTES = 16;
inline constexpr std::size_t TOKEN_HEX_LEN = TOKEN_DIGEST_BYTES * 2;
inline constexpr std::size_t TOKEN_TOTAL_LEN = 4 + TOKEN_HEX_LEN;

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

std::size_t split_csv_line_views(std::string_view line, std::array<std::string_view, 8>& out_views) noexcept;
std::vector<std::string> parse_csv_row(std::string_view line);
void append_escaped_csv_field(std::string& out, std::string_view field);
std::string escape_csv_field(std::string_view field);
std::string format_csv_row(const std::vector<std::string>& cols);

struct TokenVaultTestAccessor;

class TokenVault {
public:
    TokenVault(std::filesystem::path storage_path,
               std::shared_ptr<vault_kms::KeyManagementProvider> kms,
               const std::array<uint8_t, 32>& pepper = {});
    ~TokenVault();

    TokenVault(const TokenVault&) = delete;
    TokenVault& operator=(const TokenVault&) = delete;

    std::unordered_map<std::string, std::string> rotate_kms_pepper();

    std::string tokenize(std::string_view raw_value);
    std::optional<std::string> detokenize(std::string_view token) const;

    TransactionRecord sanitize_record(const TransactionRecord& raw, SanitizeStats* stats = nullptr);
    TransactionRecord rehydrate_record(const TransactionRecord& clean) const;

    // In-memory batch sanitization/rehydration
    std::string sanitize_csv_batch(std::string_view csv_text, SanitizeStats* out_stats = nullptr);
    std::string rehydrate_csv_batch(std::string_view sanitized_csv) const;

    // O(1)-RAM streaming line-by-line sanitization and rehydration
    void sanitize_csv_stream(std::istream& in,
                             std::ostream& out,
                             SanitizeStats* out_stats = nullptr,
                             std::unordered_set<std::string>* out_tokens = nullptr);
    void rehydrate_csv_stream(std::istream& in, std::ostream& out) const;

    // Encrypts the token mapping under a fresh DEK wrapped by the HSM/KMS and writes atomically (0600)
    void flush();

    [[nodiscard]] std::size_t size() const;

private:
    friend struct TokenVaultTestAccessor;
    void init_hmac_ctx();
    std::string_view tokenize_view_unlocked(std::string_view raw_value);
    std::string compute_token_unlocked(std::string_view input, std::uint64_t collision_attempt = 0) const;
    void sanitize_single_line_unlocked(std::string_view line,
                                       std::string& line_out,
                                       std::array<std::string_view, 8>& views,
                                       SanitizeStats* out_stats,
                                       std::unordered_set<std::string>* out_tokens);
    void load_unlocked();

    std::filesystem::path storage_path_;
    std::shared_ptr<vault_kms::KeyManagementProvider> kms_;
    std::array<uint8_t, 32> pepper_;
    EVP_MAC* hmac_alg_ = nullptr;
    mutable EVP_MAC_CTX* hmac_ctx_ = nullptr;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string, TransparentStringHash, TransparentStringEqual> forward_map_;
    std::unordered_map<std::string, std::string, TransparentStringHash, TransparentStringEqual> reverse_map_;
    bool dirty_ = false;
};

} // namespace vault_token
