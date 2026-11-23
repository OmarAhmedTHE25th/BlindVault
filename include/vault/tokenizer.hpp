#pragma once
// High-speed PII & IP scrubber / deterministic 128-bit tokenizer with strict RFC 4180
// streaming CSV state-machine parsing, O(1)-RAM (with respect to total file size, bounded
// by CsvParserLimits::max_record_bytes) CSV sanitization, and AES-256-GCM + RFC 3394
// KMS-wrapped envelope encryption at rest ("BVTK").

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
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
inline constexpr std::size_t EXPECTED_CSV_COLUMNS = 8;

inline constexpr std::size_t TOKEN_DIGEST_BYTES = 16;                 // 128-bit HMAC-SHA256 truncation
inline constexpr std::size_t TOKEN_HEX_LEN = TOKEN_DIGEST_BYTES * 2;  // 32 lowercase hex chars
inline constexpr std::size_t TOKEN_TOTAL_LEN = 4 + TOKEN_HEX_LEN;     // "TOK_" + 32 hex = 36 chars

// Validates exact BlindVault token syntax: "TOK_" followed by exactly 32 lowercase hex digits.
[[nodiscard]] bool is_valid_token_format(std::string_view sv) noexcept;

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

enum class ParseError {
    None,
    FieldSizeLimitExceeded,
    RecordSizeLimitExceeded,
    ColumnCountLimitExceeded,
    ColumnCountMismatch,
    UnclosedQuoteAtEof,
    UnexpectedQuoteInUnquotedField,
    UnexpectedCharAfterClosingQuote,
    StreamReadError,
    MultipleRecordsInSingleRow
};

class CsvParseException : public std::runtime_error {
public:
    CsvParseException(ParseError code, const std::string& message)
        : std::runtime_error(message), code_(code) {}

    [[nodiscard]] ParseError code() const noexcept { return code_; }

private:
    ParseError code_;
};

struct CsvParserLimits {
    std::size_t max_field_bytes = 64 * 1024;    // 64 KiB max per field
    std::size_t max_record_bytes = 1024 * 1024; // 1 MiB max total field bytes per record
    std::size_t max_columns = 64;               // max columns per record
};

// Strict RFC 4180 streaming CSV state machine.
// Uses O(1) memory with respect to total file size, strictly bounded by CsvParserLimits
// (max_record_bytes / max_field_bytes / max_columns).
// Properly handles quoted fields spanning multiple physical lines (\n and \r\n),
// escaped double quotes (""), arbitrary chunk boundaries, and rejects unclosed quotes,
// malformed quote placement, or oversized fields/records with explicit errors.
class CsvStreamParser {
public:
    using RecordCallback = std::function<void(const std::vector<std::string>& fields,
                                              std::size_t record_index,
                                              std::size_t start_line)>;

    explicit CsvStreamParser(CsvParserLimits limits = {});
    ~CsvStreamParser();

    CsvStreamParser(const CsvStreamParser&) = delete;
    CsvStreamParser& operator=(const CsvStreamParser&) = delete;

    void feed(std::string_view chunk, const RecordCallback& on_record);
    void finish(const RecordCallback& on_record);
    void parse_stream(std::istream& in,
                      const RecordCallback& on_record,
                      std::size_t chunk_size = 16384);
    void reset() noexcept;

    [[nodiscard]] const CsvParserLimits& limits() const noexcept { return limits_; }

private:
    enum class State {
        FieldStart,
        UnquotedField,
        QuotedField,
        QuoteInQuotedField,
        AfterCr
    };

    void append_field_char(char c);
    void commit_current_field();
    void emit_current_record(const RecordCallback& on_record);
    void cleanse_buffers() noexcept;

    CsvParserLimits limits_{};
    State state_ = State::FieldStart;
    bool in_record_ = false;
    std::size_t line_number_ = 1;
    std::size_t record_index_ = 0;
    std::size_t record_start_line_ = 1;
    std::size_t current_record_bytes_ = 0;
    std::string current_field_;
    std::vector<std::string> current_record_;
};

std::vector<std::string> parse_csv_row(std::string_view record_text);
void append_escaped_csv_field(std::string& out, std::string_view field);
void append_escaped_csv_field(vault_crypto::SecureString& out, std::string_view field);
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

    // In-memory batch sanitization/rehydration (strict RFC 4180, exact 8 columns)
    std::string sanitize_csv_batch(std::string_view csv_text, SanitizeStats* out_stats = nullptr);
    std::string rehydrate_csv_batch(std::string_view sanitized_csv) const;

    // Streaming RFC 4180 sanitization and rehydration in O(1) RAM relative to total
    // file size, bounded by CsvParserLimits::max_record_bytes (exact 8 columns).
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
    template <typename RowBuffer>
    void sanitize_record_fields_unlocked(const std::vector<std::string>& cols,
                                         std::size_t record_index,
                                         std::size_t start_line,
                                         bool& first_record,
                                         RowBuffer& row_out,
                                         SanitizeStats* out_stats,
                                         std::unordered_set<std::string>* out_tokens);
    template <typename RowBuffer>
    void rehydrate_record_fields_unlocked(const std::vector<std::string>& cols,
                                          std::size_t record_index,
                                          std::size_t start_line,
                                          bool& first_record,
                                          RowBuffer& row_out) const;
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
