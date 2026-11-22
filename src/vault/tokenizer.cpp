#include "tokenizer.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

namespace vault_token {

namespace {

constexpr std::uint64_t kMaxCollisionAttempts = 4096;

[[noreturn]] void log_and_throw_csv_error(const std::string& msg) {
    std::cerr << "[BlindVault CSV Error] " << msg << '\n';
    throw std::runtime_error(msg);
}

void validate_column_count(const std::vector<std::string>& cols,
                           std::size_t record_index,
                           std::size_t start_line,
                           const char* context) {
    if (cols.size() != EXPECTED_CSV_COLUMNS) {
        std::ostringstream oss;
        oss << context << ": malformed CSV at record " << record_index
            << " (line " << start_line << "): expected exactly "
            << EXPECTED_CSV_COLUMNS << " columns, got " << cols.size();
        log_and_throw_csv_error(oss.str());
    }
}

std::string escape_tsv_value(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    for (char c : raw) {
        switch (c) {
            case '\\': out.append("\\\\"); break;
            case '\n': out.append("\\n"); break;
            case '\r': out.append("\\r"); break;
            case '\t': out.append("\\t"); break;
            default:   out.push_back(c); break;
        }
    }
    return out;
}

std::string unescape_tsv_value(std::string_view escaped) {
    std::string out;
    out.reserve(escaped.size());
    for (std::size_t i = 0; i < escaped.size(); ++i) {
        if (escaped[i] == '\\' && i + 1 < escaped.size()) {
            const char next = escaped[++i];
            switch (next) {
                case '\\': out.push_back('\\'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                default:
                    out.push_back('\\');
                    out.push_back(next);
                    break;
            }
        } else {
            out.push_back(escaped[i]);
        }
    }
    return out;
}

} // namespace

CsvStreamParser::~CsvStreamParser() {
    cleanse_buffers();
}

void CsvStreamParser::cleanse_buffers() noexcept {
    if (!current_field_.empty()) {
        OPENSSL_cleanse(current_field_.data(), current_field_.size());
        current_field_.clear();
    }
    for (auto& field : current_record_) {
        if (!field.empty()) {
            OPENSSL_cleanse(field.data(), field.size());
        }
    }
    current_record_.clear();
}

void CsvStreamParser::reset() noexcept {
    cleanse_buffers();
    state_ = State::FieldStart;
    in_record_ = false;
    line_number_ = 1;
    record_index_ = 0;
    record_start_line_ = 1;
}

void CsvStreamParser::emit_current_record(const RecordCallback& on_record) {
    ++record_index_;
    try {
        on_record(current_record_, record_index_, record_start_line_);
    } catch (...) {
        cleanse_buffers();
        in_record_ = false;
        throw;
    }
    for (auto& field : current_record_) {
        if (!field.empty()) {
            OPENSSL_cleanse(field.data(), field.size());
        }
    }
    current_record_.clear();
    in_record_ = false;
}

void CsvStreamParser::feed(std::string_view chunk, const RecordCallback& on_record) {
    for (std::size_t i = 0; i < chunk.size(); ++i) {
        const char c = chunk[i];

        if (state_ == State::AfterCr) {
            if (c == '\n') {
                ++line_number_;
                state_ = State::FieldStart;
                continue;
            }
            // Bare CR line ending: transition to FieldStart and process current char.
            ++line_number_;
            state_ = State::FieldStart;
        }

        switch (state_) {
            case State::FieldStart:
                if (c == '"') {
                    if (!in_record_) {
                        record_start_line_ = line_number_;
                        in_record_ = true;
                    }
                    state_ = State::QuotedField;
                } else if (c == ',') {
                    if (!in_record_) {
                        record_start_line_ = line_number_;
                        in_record_ = true;
                    }
                    current_record_.push_back(std::move(current_field_));
                    current_field_.clear();
                } else if (c == '\r') {
                    if (!in_record_) {
                        record_start_line_ = line_number_;
                    }
                    current_record_.push_back(std::move(current_field_));
                    current_field_.clear();
                    emit_current_record(on_record);
                    state_ = State::AfterCr;
                } else if (c == '\n') {
                    if (!in_record_) {
                        record_start_line_ = line_number_;
                    }
                    ++line_number_;
                    current_record_.push_back(std::move(current_field_));
                    current_field_.clear();
                    emit_current_record(on_record);
                    state_ = State::FieldStart;
                } else {
                    if (!in_record_) {
                        record_start_line_ = line_number_;
                        in_record_ = true;
                    }
                    current_field_.push_back(c);
                    state_ = State::UnquotedField;
                }
                break;

            case State::UnquotedField:
                if (c == ',') {
                    current_record_.push_back(std::move(current_field_));
                    current_field_.clear();
                    state_ = State::FieldStart;
                } else if (c == '\r') {
                    current_record_.push_back(std::move(current_field_));
                    current_field_.clear();
                    emit_current_record(on_record);
                    state_ = State::AfterCr;
                } else if (c == '\n') {
                    ++line_number_;
                    current_record_.push_back(std::move(current_field_));
                    current_field_.clear();
                    emit_current_record(on_record);
                    state_ = State::FieldStart;
                } else if (c == '"') {
                    std::ostringstream oss;
                    oss << "CsvStreamParser: unescaped quote inside unquoted field at record "
                        << (record_index_ + 1) << " (line " << line_number_ << ")";
                    cleanse_buffers();
                    log_and_throw_csv_error(oss.str());
                } else {
                    current_field_.push_back(c);
                }
                break;

            case State::QuotedField:
                if (c == '"') {
                    state_ = State::QuoteInQuotedField;
                } else {
                    if (c == '\n') {
                        ++line_number_;
                    }
                    current_field_.push_back(c);
                }
                break;

            case State::QuoteInQuotedField:
                if (c == '"') {
                    // RFC 4180 escaped quote ("")
                    current_field_.push_back('"');
                    state_ = State::QuotedField;
                } else if (c == ',') {
                    current_record_.push_back(std::move(current_field_));
                    current_field_.clear();
                    state_ = State::FieldStart;
                } else if (c == '\r') {
                    current_record_.push_back(std::move(current_field_));
                    current_field_.clear();
                    emit_current_record(on_record);
                    state_ = State::AfterCr;
                } else if (c == '\n') {
                    ++line_number_;
                    current_record_.push_back(std::move(current_field_));
                    current_field_.clear();
                    emit_current_record(on_record);
                    state_ = State::FieldStart;
                } else {
                    std::ostringstream oss;
                    oss << "CsvStreamParser: unexpected character '" << c
                        << "' after closing quote at record " << (record_index_ + 1)
                        << " (line " << line_number_ << ")";
                    cleanse_buffers();
                    log_and_throw_csv_error(oss.str());
                }
                break;

            case State::AfterCr:
                // Handled above before switch
                break;
        }
    }
}

void CsvStreamParser::finish(const RecordCallback& on_record) {
    if (state_ == State::QuotedField) {
        std::ostringstream oss;
        oss << "CsvStreamParser: unclosed quoted field at EOF for record "
            << (record_index_ + 1) << " (started on line " << record_start_line_ << ")";
        cleanse_buffers();
        log_and_throw_csv_error(oss.str());
    }

    if (state_ == State::QuoteInQuotedField ||
        state_ == State::UnquotedField ||
        (state_ == State::FieldStart && in_record_)) {
        current_record_.push_back(std::move(current_field_));
        current_field_.clear();
        emit_current_record(on_record);
    }

    state_ = State::FieldStart;
    in_record_ = false;
}

void CsvStreamParser::parse_stream(std::istream& in,
                                   const RecordCallback& on_record,
                                   std::size_t chunk_size) {
    if (chunk_size == 0) {
        chunk_size = 16384;
    }
    std::vector<char> buf(chunk_size);
    struct BufGuard {
        std::vector<char>& b;
        ~BufGuard() {
            if (!b.empty()) {
                OPENSSL_cleanse(b.data(), b.size());
            }
        }
    } guard{buf};

    while (in.good()) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = in.gcount();
        if (got > 0) {
            feed(std::string_view(buf.data(), static_cast<std::size_t>(got)), on_record);
        }
    }
    if (in.bad()) {
        cleanse_buffers();
        log_and_throw_csv_error("CsvStreamParser: I/O read failure on input stream");
    }
    finish(on_record);
}

std::vector<std::string> parse_csv_row(std::string_view record_text) {
    std::vector<std::string> result;
    std::size_t record_count = 0;
    CsvStreamParser parser;
    auto cb = [&](const std::vector<std::string>& fields, std::size_t, std::size_t) {
        ++record_count;
        if (record_count > 1) {
            log_and_throw_csv_error("parse_csv_row: input contained multiple CSV records");
        }
        result = fields;
    };
    parser.feed(record_text, cb);
    parser.finish(cb);
    return result;
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

    // Sort by raw value so deterministic collision resolution order is stable across runs.
    std::vector<std::pair<std::string, std::string>> entries;
    entries.reserve(reverse_map_.size());
    for (auto& [old_token, raw] : reverse_map_) {
        entries.emplace_back(std::move(old_token), std::move(raw));
    }
    std::sort(entries.begin(), entries.end(),
              [](const auto& a, const auto& b) { return a.second < b.second; });

    forward_map_.clear();
    reverse_map_.clear();
    forward_map_.reserve(entries.size());
    reverse_map_.reserve(entries.size());

    for (const auto& [old_token, raw] : entries) {
        const std::string_view new_token = tokenize_view_unlocked(raw);
        old_to_new[old_token] = std::string(new_token);
    }
    dirty_ = !entries.empty();
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

void TokenVault::sanitize_record_fields_unlocked(const std::vector<std::string>& cols,
                                                 std::size_t record_index,
                                                 std::size_t start_line,
                                                 bool& first_record,
                                                 std::string& row_out,
                                                 SanitizeStats* out_stats,
                                                 std::unordered_set<std::string>* out_tokens) {
    validate_column_count(cols, record_index, start_line, "TokenVault::sanitize_csv");

    if (first_record) {
        first_record = false;
        if (cols[0] == "tx_id") {
            return;
        }
    }

    const std::string_view c_tok = tokenize_view_unlocked(cols[2]);
    const std::string_view n_tok = tokenize_view_unlocked(cols[3]);
    const std::string_view i_tok = tokenize_view_unlocked(cols[4]);

    append_escaped_csv_field(row_out, cols[0]); row_out.push_back(',');
    append_escaped_csv_field(row_out, cols[1]); row_out.push_back(',');
    append_escaped_csv_field(row_out, c_tok);   row_out.push_back(',');
    append_escaped_csv_field(row_out, n_tok);   row_out.push_back(',');
    append_escaped_csv_field(row_out, i_tok);   row_out.push_back(',');
    row_out.append("REDACTED_IP,");
    append_escaped_csv_field(row_out, cols[6]); row_out.push_back(',');
    append_escaped_csv_field(row_out, cols[7]); row_out.push_back('\n');

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

void TokenVault::rehydrate_record_fields_unlocked(const std::vector<std::string>& cols,
                                                  std::size_t record_index,
                                                  std::size_t start_line,
                                                  bool& first_record,
                                                  std::string& row_out) const {
    validate_column_count(cols, record_index, start_line, "TokenVault::rehydrate_csv");

    if (first_record) {
        first_record = false;
        if (cols[0] == "tx_id") {
            return;
        }
    }

    auto lookup = [this](std::string_view tok) -> std::string_view {
        auto it = reverse_map_.find(tok);
        return (it != reverse_map_.end()) ? std::string_view(it->second) : tok;
    };

    append_escaped_csv_field(row_out, cols[0]);         row_out.push_back(',');
    append_escaped_csv_field(row_out, cols[1]);         row_out.push_back(',');
    append_escaped_csv_field(row_out, lookup(cols[2])); row_out.push_back(',');
    append_escaped_csv_field(row_out, lookup(cols[3])); row_out.push_back(',');
    append_escaped_csv_field(row_out, lookup(cols[4])); row_out.push_back(',');
    append_escaped_csv_field(row_out, cols[5]);         row_out.push_back(',');
    append_escaped_csv_field(row_out, cols[6]);         row_out.push_back(',');
    append_escaped_csv_field(row_out, cols[7]);         row_out.push_back('\n');
}

std::string TokenVault::sanitize_csv_batch(std::string_view csv_text, SanitizeStats* out_stats) {
    std::string out;
    out.reserve(csv_text.size() + csv_text.size() / 4 + 128);
    out.append("tx_id,timestamp,customer_token,national_id_token,iban_token,ip_status,amount_egp,merchant\n");

    {
        std::lock_guard<std::mutex> lock(mutex_);
        const std::size_t est_entries = (csv_text.size() / 110) * 3 + 64;
        if (forward_map_.bucket_count() < est_entries) {
            forward_map_.reserve(est_entries);
            reverse_map_.reserve(est_entries);
        }

        bool first_record = true;
        CsvStreamParser parser;
        auto on_record = [&](const std::vector<std::string>& cols,
                             std::size_t record_index,
                             std::size_t start_line) {
            sanitize_record_fields_unlocked(
                cols, record_index, start_line, first_record, out, out_stats, nullptr);
        };
        parser.feed(csv_text, on_record);
        parser.finish(on_record);
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
        std::string row_buf;
        row_buf.reserve(512);
        struct RowBufGuard {
            std::string& s;
            ~RowBufGuard() {
                if (s.capacity() > 0) {
                    OPENSSL_cleanse(s.data(), s.size());
                }
            }
        } row_guard{row_buf};

        bool first_record = true;
        CsvStreamParser parser;
        auto on_record = [&](const std::vector<std::string>& cols,
                             std::size_t record_index,
                             std::size_t start_line) {
            row_buf.clear();
            sanitize_record_fields_unlocked(
                cols, record_index, start_line, first_record, row_buf, out_stats, out_tokens);
            if (!row_buf.empty()) {
                out.write(row_buf.data(), static_cast<std::streamsize>(row_buf.size()));
                OPENSSL_cleanse(row_buf.data(), row_buf.size());
            }
        };
        parser.parse_stream(in, on_record);
    }

    out.flush();
    flush();
}

std::string TokenVault::rehydrate_csv_batch(std::string_view sanitized_csv) const {
    std::string out;
    out.reserve(sanitized_csv.size() + sanitized_csv.size() / 4 + 128);
    out.append("tx_id,timestamp,customer_name,national_id,iban,ip_status,amount_egp,merchant\n");

    std::lock_guard<std::mutex> lock(mutex_);
    bool first_record = true;
    CsvStreamParser parser;
    auto on_record = [&](const std::vector<std::string>& cols,
                         std::size_t record_index,
                         std::size_t start_line) {
        rehydrate_record_fields_unlocked(cols, record_index, start_line, first_record, out);
    };
    parser.feed(sanitized_csv, on_record);
    parser.finish(on_record);
    return out;
}

void TokenVault::rehydrate_csv_stream(std::istream& in, std::ostream& out) const {
    static constexpr const char kHeader[] =
        "tx_id,timestamp,customer_name,national_id,iban,ip_status,amount_egp,merchant\n";
    out.write(kHeader, sizeof(kHeader) - 1);

    std::lock_guard<std::mutex> lock(mutex_);
    std::string row_buf;
    row_buf.reserve(512);
    struct RowBufGuard {
        std::string& s;
        ~RowBufGuard() {
            if (!s.empty()) {
                OPENSSL_cleanse(s.data(), s.size());
            }
        }
    } row_guard{row_buf};

    bool first_record = true;
    CsvStreamParser parser;
    auto on_record = [&](const std::vector<std::string>& cols,
                         std::size_t record_index,
                         std::size_t start_line) {
        row_buf.clear();
        rehydrate_record_fields_unlocked(cols, record_index, start_line, first_record, row_buf);
        if (!row_buf.empty()) {
            out.write(row_buf.data(), static_cast<std::streamsize>(row_buf.size()));
            OPENSSL_cleanse(row_buf.data(), row_buf.size());
        }
    };
    parser.parse_stream(in, on_record);
    out.flush();
}

void TokenVault::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!dirty_) return;

    std::string plaintext;
    plaintext.reserve(reverse_map_.size() * 64);
    for (const auto& [token, raw] : reverse_map_) {
        plaintext.append(token);
        plaintext.push_back('\t');
        plaintext.append(escape_tsv_value(raw));
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
    for (std::uint64_t attempt = 0; attempt < kMaxCollisionAttempts; ++attempt) {
        std::string candidate = compute_token_unlocked(key, attempt);
        auto [rev_it, inserted] = reverse_map_.emplace(candidate, key);
        if (inserted || rev_it->second == key) {
            auto [fwd_it, fwd_inserted] = forward_map_.emplace(std::move(key), std::move(candidate));
            if (!fwd_inserted) {
                fwd_it->second = rev_it->first;
            }
            dirty_ = true;
            return fwd_it->second;
        }
        // Collision detected: candidate is already assigned to a different raw value.
        // Deterministically derive the next domain-separated candidate token.
    }

    throw std::runtime_error(
        "TokenVault: failed to resolve token collision after maximum deterministic attempts");
}

std::string TokenVault::compute_token_unlocked(std::string_view input,
                                               std::uint64_t collision_attempt) const {
    unsigned char digest[EVP_MAX_MD_SIZE];
    std::size_t digest_len = 0;

    if (EVP_MAC_init(hmac_ctx_, nullptr, 0, nullptr) != 1) {
        throw std::runtime_error("TokenVault: HMAC-SHA256 re-init failed");
    }

    if (collision_attempt > 0) {
        static constexpr char kCollisionDomain[] = "BLINDVAULT_TOK_COLLISION_V1";
        std::array<unsigned char, 8> ctr_be{};
        for (int i = 0; i < 8; ++i) {
            ctr_be[static_cast<std::size_t>(i)] =
                static_cast<unsigned char>((collision_attempt >> (56 - i * 8)) & 0xFF);
        }
        const unsigned char sep = 0x00;
        if (EVP_MAC_update(hmac_ctx_,
                           reinterpret_cast<const unsigned char*>(kCollisionDomain),
                           sizeof(kCollisionDomain)) != 1 || // includes trailing '\0'
            EVP_MAC_update(hmac_ctx_, ctr_be.data(), ctr_be.size()) != 1 ||
            EVP_MAC_update(hmac_ctx_, &sep, 1) != 1) {
            throw std::runtime_error("TokenVault: HMAC-SHA256 collision domain update failed");
        }
    }

    if (EVP_MAC_update(hmac_ctx_,
                       reinterpret_cast<const unsigned char*>(input.data()),
                       input.size()) != 1 ||
        EVP_MAC_final(hmac_ctx_, digest, &digest_len, sizeof(digest)) != 1 ||
        digest_len < TOKEN_DIGEST_BYTES) {
        throw std::runtime_error("TokenVault: HMAC-SHA256 computation failed");
    }

    static constexpr char hex[] = "0123456789abcdef";
    std::string token(TOKEN_TOTAL_LEN, '\0');
    token[0] = 'T';
    token[1] = 'O';
    token[2] = 'K';
    token[3] = '_';
    for (std::size_t i = 0; i < TOKEN_DIGEST_BYTES; ++i) {
        token[4 + i * 2]     = hex[digest[i] >> 4];
        token[4 + i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    OPENSSL_cleanse(digest, sizeof(digest));
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
    const std::size_t approx_lines = sv.size() / 64 + 16;
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
        std::string raw = unescape_tsv_value(line.substr(tab + 1));

        auto [rev_it, inserted] = reverse_map_.emplace(token, raw);
        if (!inserted && rev_it->second != raw) {
            OPENSSL_cleanse(plaintext.data(), plaintext.size());
            throw std::runtime_error(
                "TokenVault: conflicting duplicate token detected while loading persisted token store");
        }
        forward_map_[std::move(raw)] = std::move(token);
    }
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
}

} // namespace vault_token
