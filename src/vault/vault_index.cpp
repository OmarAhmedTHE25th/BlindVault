#include "vault_index.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

namespace vault_index {

namespace {

bool is_leap_year(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

int days_in_month(int year, int month) {
    static constexpr std::array<int, 12> kDays = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month == 2 && is_leap_year(year)) return 29;
    return kDays[static_cast<std::size_t>(month - 1)];
}

} // namespace

std::string generate_challenge_nonce_hex() {
    std::array<uint8_t, 16> raw{};
    if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
        throw std::runtime_error("QuorumGate: CSPRNG failure generating challenge nonce");
    }
    return vault_crypto::bytes_to_hex(raw.data(), raw.size());
}

std::string utc_iso_offset_seconds(std::int64_t offset_seconds) {
    const auto target = std::chrono::system_clock::now() + std::chrono::seconds(offset_seconds);
    const std::time_t t = std::chrono::system_clock::to_time_t(target);
    std::tm tm_utc{};
#ifdef _WIN32
    gmtime_s(&tm_utc, &t);
#else
    gmtime_r(&t, &tm_utc);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

bool is_utc_iso_expired(const std::string& expires_utc) {
    if (expires_utc.size() != 20) return true;
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    char trailing = '\0';
    if (std::sscanf(expires_utc.c_str(), "%4d-%2d-%2dT%2d:%2d:%2dZ%c",
                    &year, &month, &day, &hour, &minute, &second, &trailing) != 6) {
        return true;
    }
    if (expires_utc[4] != '-' || expires_utc[7] != '-' || expires_utc[10] != 'T' ||
        expires_utc[13] != ':' || expires_utc[16] != ':' || expires_utc[19] != 'Z') {
        return true;
    }
    if (month < 1 || month > 12 || day < 1 || day > days_in_month(year, month) ||
        hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60) {
        return true;
    }

    std::tm tm_utc{};
    tm_utc.tm_year = year - 1900;
    tm_utc.tm_mon = month - 1;
    tm_utc.tm_mday = day;
    tm_utc.tm_hour = hour;
    tm_utc.tm_min = minute;
    tm_utc.tm_sec = second;
    tm_utc.tm_isdst = 0;

#ifdef _WIN32
    const std::time_t expires_epoch = _mkgmtime(&tm_utc);
#else
    const std::time_t expires_epoch = timegm(&tm_utc);
#endif
    if (expires_epoch == static_cast<std::time_t>(-1)) {
        return true;
    }

    const std::time_t now_epoch = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    return now_epoch >= expires_epoch;
}

std::string build_release_payload(const std::string& officer_id,
                                  const std::string& target_token,
                                  const std::string& blob_name,
                                  const std::string& wrapped_dek_hex,
                                  const std::string& challenge_nonce_hex,
                                  const std::string& expires_utc) {
    return officer_id + "|" + target_token + "|" + blob_name + "|" +
           wrapped_dek_hex + "|" + challenge_nonce_hex + "|" + expires_utc;
}

void generate_officer_ed25519_keypair(const std::filesystem::path& priv_pem_path,
                                      const std::filesystem::path& pub_pem_path) {
    using PkeyCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    using Pkey    = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using BioPtr  = std::unique_ptr<BIO, decltype(&BIO_free)>;

    if (priv_pem_path.has_parent_path()) {
        std::filesystem::create_directories(priv_pem_path.parent_path());
    }
    if (pub_pem_path.has_parent_path()) {
        std::filesystem::create_directories(pub_pem_path.parent_path());
    }

    PkeyCtx kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), &EVP_PKEY_CTX_free);
    if (!kctx || EVP_PKEY_keygen_init(kctx.get()) <= 0) {
        throw std::runtime_error("QuorumGate: Ed25519 keygen init failed");
    }
    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_keygen(kctx.get(), &raw_pkey) <= 0 || !raw_pkey) {
        throw std::runtime_error("QuorumGate: Ed25519 keygen failed");
    }
    Pkey pkey(raw_pkey, &EVP_PKEY_free);

    BioPtr priv_bio(BIO_new(BIO_s_mem()), &BIO_free);
    BioPtr pub_bio(BIO_new(BIO_s_mem()), &BIO_free);
    if (!priv_bio || !pub_bio ||
        PEM_write_bio_PrivateKey(priv_bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1 ||
        PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) != 1) {
        throw std::runtime_error("QuorumGate: failed serializing Ed25519 PEM keys");
    }

    char* priv_data = nullptr;
    const long priv_len = BIO_get_mem_data(priv_bio.get(), &priv_data);
    std::string priv_pem(priv_data, static_cast<std::size_t>(priv_len));
    vault_crypto::write_secret_file_0600(priv_pem_path, priv_pem);
    OPENSSL_cleanse(priv_pem.data(), priv_pem.size());

    char* pub_data = nullptr;
    const long pub_len = BIO_get_mem_data(pub_bio.get(), &pub_data);
    std::ofstream pub_out(pub_pem_path, std::ios::binary | std::ios::trunc);
    if (!pub_out) {
        throw std::runtime_error("QuorumGate: cannot write public key " + pub_pem_path.string());
    }
    pub_out.write(pub_data, pub_len);
    pub_out.flush();
    if (!pub_out) {
        throw std::runtime_error("QuorumGate: failed flushing public key " + pub_pem_path.string());
    }
}

std::string sign_blob_release_offline(const std::filesystem::path& priv_pem_path,
                                      const std::string& officer_id,
                                      const std::string& target_token,
                                      const std::string& blob_name,
                                      const std::string& wrapped_dek_hex,
                                      const std::string& challenge_nonce_hex,
                                      const std::string& expires_utc) {
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
    using Pkey   = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using MdCtx  = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

    if (challenge_nonce_hex.empty() || expires_utc.empty()) {
        throw std::runtime_error("QuorumGate: challenge_nonce_hex and expires_utc are required for signing");
    }

    std::ifstream in(priv_pem_path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("QuorumGate: cannot open private key " + priv_pem_path.string());
    }
    std::string pem((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
    Pkey pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, const_cast<char*>("")), &EVP_PKEY_free);
    OPENSSL_cleanse(pem.data(), pem.size());
    if (!pkey || EVP_PKEY_id(pkey.get()) != EVP_PKEY_ED25519) {
        throw std::runtime_error("QuorumGate: invalid Ed25519 private key");
    }

    const std::string payload = build_release_payload(
        officer_id, target_token, blob_name, wrapped_dek_hex, challenge_nonce_hex, expires_utc);
    MdCtx mctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!mctx || EVP_DigestSignInit(mctx.get(), nullptr, nullptr, nullptr, pkey.get()) <= 0) {
        throw std::runtime_error("QuorumGate: EVP_DigestSignInit failed");
    }

    std::array<uint8_t, 64> sig{};
    std::size_t sig_len = sig.size();
    if (EVP_DigestSign(mctx.get(), sig.data(), &sig_len,
                       reinterpret_cast<const uint8_t*>(payload.data()), payload.size()) <= 0 ||
        sig_len != 64) {
        throw std::runtime_error("QuorumGate: Ed25519 signing failed");
    }
    return vault_crypto::bytes_to_hex(sig.data(), sig.size());
}

QuorumGate::QuorumGate(std::filesystem::path officer_pubkey_dir, std::size_t threshold)
    : officer_pubkey_dir_(std::move(officer_pubkey_dir)), threshold_(threshold) {
    std::filesystem::create_directories(officer_pubkey_dir_);
    reload_public_keys();
}

void QuorumGate::reload_public_keys() {
    officer_pubkeys_.clear();
    if (!std::filesystem::exists(officer_pubkey_dir_)) return;
    for (const auto& entry : std::filesystem::directory_iterator(officer_pubkey_dir_)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".pub") continue;
        const std::string officer_id = entry.path().stem().string();
        officer_pubkeys_.emplace(officer_id, load_public_key(entry.path()));
    }
}

std::vector<std::string> QuorumGate::registered_officers() const {
    std::vector<std::string> ids;
    ids.reserve(officer_pubkeys_.size());
    for (const auto& [id, _] : officer_pubkeys_) ids.push_back(id);
    std::ranges::sort(ids);
    return ids;
}

bool QuorumGate::verify_blob_release(const std::string& target_token,
                                     const BlobEntry& blob,
                                     const std::string& challenge_nonce_hex,
                                     const std::string& expires_utc,
                                     const std::vector<OfficerApproval>& approvals) const {
    if (officer_pubkeys_.size() < threshold_) return false;
    if (challenge_nonce_hex.empty() || is_utc_iso_expired(expires_utc)) return false;

    std::unordered_set<std::string> valid_officers;
    for (const auto& approval : approvals) {
        auto it = officer_pubkeys_.find(approval.officer_id);
        if (it == officer_pubkeys_.end()) continue;

        std::vector<uint8_t> sig_bytes;
        try {
            sig_bytes = vault_crypto::hex_to_bytes(approval.signature_hex);
        } catch (...) {
            continue;
        }
        if (sig_bytes.size() != 64) continue;

        const std::string payload = build_release_payload(
            approval.officer_id, target_token, blob.blob_name, blob.wrapped_dek_hex,
            challenge_nonce_hex, expires_utc);

        using MdCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
        MdCtx mctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
        if (!mctx ||
            EVP_DigestVerifyInit(mctx.get(), nullptr, nullptr, nullptr, it->second.get()) <= 0) {
            continue;
        }
        if (EVP_DigestVerify(mctx.get(), sig_bytes.data(), sig_bytes.size(),
                             reinterpret_cast<const uint8_t*>(payload.data()),
                             payload.size()) == 1) {
            valid_officers.insert(approval.officer_id);
        }
    }
    return valid_officers.size() >= threshold_;
}

QuorumGate::PkeyPtr QuorumGate::load_public_key(const std::filesystem::path& pub_path) {
    std::ifstream in(pub_path, std::ios::binary);
    if (!in) throw std::runtime_error("QuorumGate: cannot open public key " + pub_path.string());
    std::string pem((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
    EVP_PKEY* raw = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!raw || EVP_PKEY_id(raw) != EVP_PKEY_ED25519) {
        if (raw) EVP_PKEY_free(raw);
        throw std::runtime_error("QuorumGate: invalid Ed25519 public key in " + pub_path.string());
    }
    return PkeyPtr(raw, &EVP_PKEY_free);
}

MetadataIndex::MetadataIndex(std::filesystem::path index_file,
                             std::filesystem::path audit_log_file,
                             std::shared_ptr<vault_kms::KeyManagementProvider> kms)
    : index_file_(std::move(index_file)),
      audit_log_file_(std::move(audit_log_file)),
      kms_(std::move(kms)) {
    if (!kms_) throw std::runtime_error("MetadataIndex: KMS provider is required");
    load_and_verify_index_unlocked();
    load_and_verify_audit_chain_unlocked();
}

void MetadataIndex::register_blob(const BlobEntry& entry, const std::vector<std::string>& tokens_in_blob) {
    std::lock_guard lock(mutex_);
    BlobEntry stored = entry;
    if (stored.created_utc.empty()) stored.created_utc = current_utc_iso();
    blobs_[stored.blob_name] = stored;

    for (const auto& tok : tokens_in_blob) {
        if (!tok.empty()) {
            token_to_blobs_[tok].insert(stored.blob_name);
        }
    }
    save_authenticated_index_unlocked();
    append_chained_audit_unlocked(
        "INGEST",
        "Offloaded 64KiB-padded blob '" + stored.blob_name + "' (" +
        std::to_string(stored.record_count) + " records, DEK wrapped via RFC3394)");
}

std::vector<BlobEntry> MetadataIndex::find_candidate_blobs(const std::string& token) const {
    std::lock_guard lock(mutex_);
    std::vector<BlobEntry> results;
    if (const auto it = token_to_blobs_.find(token); it != token_to_blobs_.end()) {
        for (const auto& blob_name : it->second) {
            if (auto b_it = blobs_.find(blob_name); b_it != blobs_.end()) {
                results.push_back(b_it->second);
            }
        }
    }
    std::ranges::sort(results, {}, &BlobEntry::blob_name);
    return results;
}

std::vector<BlobEntry> MetadataIndex::blob_entries() const {
    std::lock_guard lock(mutex_);
    std::vector<BlobEntry> results;
    results.reserve(blobs_.size());
    for (const auto& [_, entry] : blobs_) results.push_back(entry);
    return results;
}

void MetadataIndex::update_wrapped_dek(const std::string& blob_name, const std::string& wrapped_dek_hex) {
    std::lock_guard lock(mutex_);
    auto it = blobs_.find(blob_name);
    if (it == blobs_.end()) {
        throw std::runtime_error("MetadataIndex: unknown blob '" + blob_name + "'");
    }
    it->second.wrapped_dek_hex = wrapped_dek_hex;
    save_authenticated_index_unlocked();
}

void MetadataIndex::update_blob_metadata(const std::string& blob_name,
                                         const std::string& wrapped_dek_hex,
                                         std::size_t padded_bytes) {
    std::lock_guard lock(mutex_);
    auto it = blobs_.find(blob_name);
    if (it == blobs_.end()) {
        throw std::runtime_error("MetadataIndex: unknown blob '" + blob_name + "'");
    }
    it->second.wrapped_dek_hex = wrapped_dek_hex;
    it->second.padded_bytes = padded_bytes;
    save_authenticated_index_unlocked();
}

void MetadataIndex::remap_tokens(const std::unordered_map<std::string, std::string>& old_to_new) {
    std::lock_guard lock(mutex_);
    for (const auto& [old_token, new_token] : old_to_new) {
        auto it = token_to_blobs_.find(old_token);
        if (it == token_to_blobs_.end()) continue;
        auto& target = token_to_blobs_[new_token];
        target.insert(it->second.begin(), it->second.end());
        token_to_blobs_.erase(it);
    }
    for (auto& [_, chal] : challenges_) {
        if (const auto cit = old_to_new.find(chal.target_token); cit != old_to_new.end()) {
            chal.target_token = cit->second;
        }
    }
    save_authenticated_index_unlocked();
}

void MetadataIndex::issue_challenge(const std::string& nonce_hex,
                                    const std::string& target_token,
                                    const std::string& expires_utc) {
    if (nonce_hex.empty() || target_token.empty() || expires_utc.empty()) {
        throw std::runtime_error("MetadataIndex: invalid challenge parameters");
    }
    if (nonce_hex.find_first_of("\t\r\n") != std::string::npos ||
        target_token.find_first_of("\t\r\n") != std::string::npos ||
        expires_utc.find_first_of("\t\r\n") != std::string::npos) {
        throw std::runtime_error("MetadataIndex: challenge fields cannot contain control characters");
    }
    std::lock_guard lock(mutex_);
    challenges_[nonce_hex] = ChallengeRecord{nonce_hex, target_token, expires_utc, false};
    save_authenticated_index_unlocked();
}

bool MetadataIndex::validate_challenge_active(const std::string& nonce_hex,
                                              const std::string& target_token,
                                              const std::string& expires_utc) const {
    if (nonce_hex.empty() || target_token.empty() || expires_utc.empty()) {
        return false;
    }
    std::lock_guard lock(mutex_);
    const auto it = challenges_.find(nonce_hex);
    if (it == challenges_.end()) return false;
    const auto& rec = it->second;
    if (rec.consumed) return false;
    if (rec.target_token != target_token) return false;
    if (rec.expires_utc != expires_utc) return false;
    if (is_utc_iso_expired(rec.expires_utc)) return false;
    return true;
}

void MetadataIndex::consume_challenge(const std::string& nonce_hex) {
    std::lock_guard lock(mutex_);
    const auto it = challenges_.find(nonce_hex);
    if (it == challenges_.end()) {
        throw std::runtime_error("MetadataIndex: unknown challenge nonce");
    }
    if (it->second.consumed) {
        throw std::runtime_error("MetadataIndex: challenge nonce already consumed (replay rejected)");
    }
    it->second.consumed = true;
    save_authenticated_index_unlocked();
}

std::optional<ChallengeRecord> MetadataIndex::find_challenge(const std::string& nonce_hex) const {
    std::lock_guard lock(mutex_);
    const auto it = challenges_.find(nonce_hex);
    if (it == challenges_.end()) return std::nullopt;
    return it->second;
}

void MetadataIndex::reauthenticate_after_kms_rotation() {
    std::lock_guard lock(mutex_);

    save_authenticated_index_unlocked();
    if (!std::filesystem::exists(audit_log_file_)) {
        audit_seq_ = 1;
        last_audit_mac_ = std::string(64, '0');
        return;
    }

    std::ifstream in(audit_log_file_, std::ios::binary);
    if (!in) throw std::runtime_error("MetadataIndex: cannot read audit log for key rotation");

    std::vector<std::array<std::string, 4>> entries;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        std::vector<std::string> cols;
        std::istringstream ss(line);
        std::string part;
        while (std::getline(ss, part, '\t')) cols.push_back(part);
        if (cols.size() != 6) {
            throw std::runtime_error("MetadataIndex: malformed audit log during key rotation");
        }
        entries.push_back({cols[1], cols[2], cols[3], cols[0]});
    }

    audit_seq_ = 1;
    last_audit_mac_ = std::string(64, '0');
    std::ostringstream rewritten;
    for (const auto& entry : entries) {
        const std::string seq = std::to_string(audit_seq_);
        const std::string body =
            seq + "|" + entry[0] + "|" + entry[1] + "|" + entry[2] + "|" + last_audit_mac_;
        const std::string mac = kms_->hmac_audit_hex(body);
        rewritten << seq << '\t' << entry[0] << '\t' << entry[1] << '\t'
                  << entry[2] << '\t' << last_audit_mac_ << '\t' << mac << '\n';
        last_audit_mac_ = mac;
        audit_seq_ += 1;
    }
    vault_crypto::write_secret_file_0600(audit_log_file_, rewritten.str());
}

void MetadataIndex::log_security_event(const std::string& action, const std::string& detail) {
    std::lock_guard lock(mutex_);
    append_chained_audit_unlocked(action, detail);
}

bool MetadataIndex::verify_audit_chain() const {
    std::lock_guard lock(mutex_);
    try {
        uint64_t expected_seq = 1;
        std::string expected_prev(64, '0');
        return verify_audit_file_internal(
            audit_log_file_, kms_, expected_seq, expected_prev);
    } catch (...) {
        return false;
    }
}

std::string MetadataIndex::current_utc_iso() {
    return utc_iso_offset_seconds(0);
}

void MetadataIndex::append_chained_audit_unlocked(const std::string& action, const std::string& detail) {
    const std::string ts = current_utc_iso();
    const std::string body = std::to_string(audit_seq_) + "|" + ts + "|" +
                             action + "|" + detail + "|" + last_audit_mac_;
    const std::string entry_mac = kms_->hmac_audit_hex(body);

    std::ofstream log(audit_log_file_, std::ios::app);
    if (!log) throw std::runtime_error("MetadataIndex: cannot append to audit log");
    log << audit_seq_ << '\t' << ts << '\t' << action << '\t'
        << detail << '\t' << last_audit_mac_ << '\t' << entry_mac << '\n';
    log.flush();

    last_audit_mac_ = entry_mac;
    audit_seq_ += 1;
}

bool MetadataIndex::verify_audit_file_internal(const std::filesystem::path& path,
                                               const std::shared_ptr<vault_kms::KeyManagementProvider>& kms,
                                               uint64_t& out_next_seq,
                                               std::string& out_last_mac) {
    out_next_seq = 1;
    out_last_mac = std::string(64, '0');
    if (!std::filesystem::exists(path)) return true;

    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        std::vector<std::string> cols;
        std::istringstream ss(line);
        std::string part;
        while (std::getline(ss, part, '\t')) cols.push_back(part);
        if (cols.size() != 6) return false;

        const uint64_t seq = std::stoull(cols[0]);
        if (seq != out_next_seq) return false;
        if (!vault_crypto::constant_time_hex_equal(cols[4], out_last_mac)) return false;

        const std::string body = cols[0] + "|" + cols[1] + "|" + cols[2] + "|" + cols[3] + "|" + cols[4];
        const std::string expected_mac = kms->hmac_audit_hex(body);
        if (!vault_crypto::constant_time_hex_equal(cols[5], expected_mac)) return false;

        out_last_mac = cols[5];
        out_next_seq += 1;
    }
    return true;
}

void MetadataIndex::load_and_verify_audit_chain_unlocked() {
    if (!verify_audit_file_internal(
            audit_log_file_, kms_, audit_seq_, last_audit_mac_)) {
        throw std::runtime_error("MetadataIndex: tamper detected in regtech_audit.log hash chain!");
    }
}

std::string MetadataIndex::serialize_canonical_body_unlocked() const {
    std::vector<std::string> blob_names;
    blob_names.reserve(blobs_.size());
    for (const auto& name : blobs_ | std::views::keys) blob_names.push_back(name);
    std::ranges::sort(blob_names);

    std::ostringstream body;
    for (const auto& name : blob_names) {
        const auto& e = blobs_.at(name);
        body << "BLOB\t" << e.blob_name << '\t' << e.wrapped_dek_hex
             << '\t' << e.record_count << '\t' << e.padded_bytes
             << '\t' << e.created_utc << '\n';
    }

    std::vector<std::string> tokens;
    tokens.reserve(token_to_blobs_.size());
    for (const auto& tok : token_to_blobs_ | std::views::keys) tokens.push_back(tok);
    std::ranges::sort(tokens);

    for (const auto& tok : tokens) {
        const auto& bset = token_to_blobs_.at(tok);
        std::vector<std::string> sorted_b(bset.begin(), bset.end());
        std::ranges::sort(sorted_b);
        for (const auto& bname : sorted_b) {
            body << "MAP\t" << tok << '\t' << bname << '\n';
        }
    }

    std::vector<std::string> nonces;
    nonces.reserve(challenges_.size());
    for (const auto& nonce : challenges_ | std::views::keys) nonces.push_back(nonce);
    std::ranges::sort(nonces);

    for (const auto& nonce : nonces) {
        const auto& c = challenges_.at(nonce);
        body << "CHAL\t" << c.nonce_hex << '\t' << c.target_token << '\t'
             << c.expires_utc << '\t' << (c.consumed ? "1" : "0") << '\n';
    }

    return body.str();
}

void MetadataIndex::save_authenticated_index_unlocked() const {
    const std::string body = serialize_canonical_body_unlocked();
    const std::string mac = kms_->hmac_index_hex(body);
    vault_crypto::write_secret_file_0600(index_file_, body + "MAC\t" + mac + "\n");
}

void MetadataIndex::load_and_verify_index_unlocked() {
    blobs_.clear();
    token_to_blobs_.clear();
    challenges_.clear();
    if (!std::filesystem::exists(index_file_)) return;
    std::ifstream in(index_file_, std::ios::binary);
    if (!in) throw std::runtime_error("MetadataIndex: cannot read " + index_file_.string());

    std::ostringstream body_accum;
    std::string file_mac;
    bool saw_mac = false;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        if (line.rfind("MAC\t", 0) == 0) {
            if (saw_mac) {
                throw std::runtime_error("MetadataIndex: malformed record in index file");
            }
            file_mac = line.substr(4);
            saw_mac = true;
            continue;
        }
        if (saw_mac) {
            throw std::runtime_error("MetadataIndex: unexpected data after index MAC");
        }
        body_accum << line << '\n';

        std::vector<std::string> parts;
        std::istringstream ss(line);
        std::string item;
        while (std::getline(ss, item, '\t')) parts.push_back(item);

        if (parts.size() == 6 && parts[0] == "BLOB") {
            BlobEntry e{parts[1], parts[2],
                        static_cast<std::size_t>(std::stoull(parts[3])),
                        static_cast<std::size_t>(std::stoull(parts[4])),
                        parts[5]};
            blobs_[e.blob_name] = std::move(e);
        } else if (parts.size() == 3 && parts[0] == "MAP") {
            token_to_blobs_[parts[1]].insert(parts[2]);
        } else if (parts.size() == 5 && parts[0] == "CHAL") {
            if (parts[4] != "0" && parts[4] != "1") {
                throw std::runtime_error("MetadataIndex: malformed challenge record in index file");
            }
            ChallengeRecord rec{parts[1], parts[2], parts[3], parts[4] == "1"};
            challenges_[rec.nonce_hex] = std::move(rec);
        } else {
            throw std::runtime_error("MetadataIndex: malformed record in index file");
        }
    }

    const std::string expected_mac = kms_->hmac_index_hex(body_accum.str());
    if (!vault_crypto::constant_time_hex_equal(file_mac, expected_mac)) {
        throw std::runtime_error("MetadataIndex: HMAC verification failed — vault_index.tsv was tampered with!");
    }
}

} // namespace vault_index
