#pragma once
// Hardened Metadata Index, Data-Bound M-of-N Compliance Quorum Gate,
// & Tamper-Evident HMAC Hash-Chained Audit Log.

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <mutex>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include "at_rest_crypto.hpp"
#include "kms_provider.hpp"

namespace vault_index {

struct BlobEntry {
    std::string blob_name;        // e.g., "vault_batch_1731870000.enc"
    std::string wrapped_dek_hex;  // 80-char hex (40-byte RFC 3394 wrapped DEK)
    std::size_t record_count = 0;
    std::size_t padded_bytes = 0;
    std::string created_utc;
};

// M-of-N Dual-Custody Quorum Gate:
//   - Generates per-officer 256-bit secrets on disk (0600 permissions) — zero hardcoded passwords in source
//   - Binds approvals to (target_token, blob_name, wrapped_dek_hex) so forged index entries cannot bypass quorum
//   - Verifies signatures in constant time (CRYPTO_memcmp)
class QuorumGate {
public:
    explicit QuorumGate(std::filesystem::path  officer_key_dir, std::size_t threshold = 2)
        : officer_key_dir_(std::move(officer_key_dir)), threshold_(threshold) {
        std::filesystem::create_directories(officer_key_dir_);
        const std::vector<std::string> default_officers = {
            "CBE-Officer-1", "CBE-Officer-2", "CBE-Officer-3"
        };
        for (const auto& officer : default_officers) {
            officer_keys_.emplace(officer, load_or_create_officer_key(officer));
        }
    }

    std::size_t threshold() const noexcept { return threshold_; }

    // Signs an authorization bound to the specific token, cloud blob, and wrapped DEK
    std::string sign_blob_release(const std::string& officer_id,
                                  const std::string& target_token,
                                  const BlobEntry& blob) const {
        auto it = officer_keys_.find(officer_id);
        if (it == officer_keys_.end()) {
            throw std::runtime_error("QuorumGate: unknown compliance officer '" + officer_id + "'");
        }
        const std::string payload = build_release_payload(officer_id, target_token, blob);
        return vault_crypto::hmac_sha256_hex(it->second.data(), vault_crypto::SecretKey::size(), payload);
    }

    // Constant-time verification that >= threshold distinct officers signed this exact blob release
    bool verify_blob_release(const std::string& target_token,
                             const BlobEntry& blob,
                             const std::vector<std::pair<std::string, std::string>>& approvals) const {
        std::unordered_set<std::string> valid_officers;
        for (const auto& [officer_id, sig_hex] : approvals) {
            auto it = officer_keys_.find(officer_id);
            if (it == officer_keys_.end()) continue;
            const std::string payload = build_release_payload(officer_id, target_token, blob);
            const std::string expected_hex =
                vault_crypto::hmac_sha256_hex(it->second.data(), vault_crypto::SecretKey::size(), payload);
            if (vault_crypto::constant_time_hex_equal(sig_hex, expected_hex)) {
                valid_officers.insert(officer_id);
            }
        }
        return valid_officers.size() >= threshold_;
    }

private:
    static std::string build_release_payload(const std::string& officer_id,
                                             const std::string& target_token,
                                             const BlobEntry& blob) {
        return officer_id + "|" + target_token + "|" + blob.blob_name + "|" + blob.wrapped_dek_hex;
    }

    vault_crypto::SecretKey load_or_create_officer_key(const std::string& officer_id) const {
        const auto key_path = officer_key_dir_ / (officer_id + ".key");
        if (std::filesystem::exists(key_path)) {
            std::ifstream in(key_path, std::ios::binary);
            std::string hex_str;
            std::getline(in, hex_str);
            const auto raw = vault_crypto::hex_to_bytes(hex_str);
            if (raw.size() != vault_crypto::KEY_LEN) {
                throw std::runtime_error("QuorumGate: corrupted key for " + officer_id);
            }
            vault_crypto::SecretKey k;
            std::memcpy(k.data(), raw.data(), vault_crypto::KEY_LEN);
            return k;
        }
        vault_crypto::SecretKey k = vault_crypto::generate_key();
        vault_crypto::write_secret_file_0600(
            key_path, vault_crypto::bytes_to_hex(k.data(), vault_crypto::SecretKey::size()) + "\n");
        return k;
    }

    std::filesystem::path officer_key_dir_;
    std::size_t threshold_;
    std::unordered_map<std::string, vault_crypto::SecretKey> officer_keys_;
};

// HMAC-Authenticated Metadata Index & Cryptographic Hash-Chained Audit Log
class MetadataIndex {
public:
    MetadataIndex(std::filesystem::path index_file,
                  std::filesystem::path audit_log_file,
                  std::shared_ptr<vault_kms::KeyManagementProvider> kms)
        : index_file_(std::move(index_file)),
          audit_log_file_(std::move(audit_log_file)),
          kms_(std::move(kms)) {
        if (!kms_) throw std::runtime_error("MetadataIndex: KMS provider is required");
        load_and_verify_index_unlocked();
        load_and_verify_audit_chain_unlocked();
    }

    void register_blob(const BlobEntry& entry, const std::vector<std::string>& tokens_in_blob) {
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

    std::vector<BlobEntry> find_candidate_blobs(const std::string& token) const {
        std::lock_guard lock(mutex_);
        std::vector<BlobEntry> results;
        if (const auto it = token_to_blobs_.find(token); it != token_to_blobs_.end()) {
            for (const auto& blob_name : it->second) {
                if (auto b_it = blobs_.find(blob_name); b_it != blobs_.end()) {
                    results.push_back(b_it->second);
                }
            }
        }
        return results;
    }

    std::vector<BlobEntry> blob_entries() const {
        std::lock_guard lock(mutex_);
        std::vector<BlobEntry> results;
        results.reserve(blobs_.size());
        for (const auto& [_, entry] : blobs_) results.push_back(entry);
        return results;
    }

    void update_wrapped_dek(const std::string& blob_name, const std::string& wrapped_dek_hex) {
        std::lock_guard lock(mutex_);
        auto it = blobs_.find(blob_name);
        if (it == blobs_.end()) {
            throw std::runtime_error("MetadataIndex: unknown blob '" + blob_name + "'");
        }
        it->second.wrapped_dek_hex = wrapped_dek_hex;
        save_authenticated_index_unlocked();
    }

    void remap_tokens(const std::unordered_map<std::string, std::string>& old_to_new) {
        std::lock_guard lock(mutex_);
        for (const auto& [old_token, new_token] : old_to_new) {
            auto it = token_to_blobs_.find(old_token);
            if (it == token_to_blobs_.end()) continue;
            auto& target = token_to_blobs_[new_token];
            target.insert(it->second.begin(), it->second.end());
            token_to_blobs_.erase(it);
        }
        save_authenticated_index_unlocked();
    }

    void reauthenticate_after_kms_rotation() {
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

    void log_security_event(const std::string& action, const std::string& detail) {
        std::lock_guard lock(mutex_);
        append_chained_audit_unlocked(action, detail);
    }

    // Re-verifies every HMAC link in regtech_audit.log from genesis to latest entry
    bool verify_audit_chain() const {
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

private:
    static std::string current_utc_iso() {
        const auto now = std::chrono::system_clock::now();
        const std::time_t t = std::chrono::system_clock::to_time_t(now);
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

    void append_chained_audit_unlocked(const std::string& action, const std::string& detail) {
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

    static bool verify_audit_file_internal(const std::filesystem::path& path,
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

    void load_and_verify_audit_chain_unlocked() {
        if (!verify_audit_file_internal(
                audit_log_file_, kms_, audit_seq_, last_audit_mac_)) {
            throw std::runtime_error("MetadataIndex: tamper detected in regtech_audit.log hash chain!");
        }
    }

    std::string serialize_canonical_body_unlocked() const {
        // Deterministic sorted serialization so MAC verification is invariant
        std::vector<std::string> blob_names;
        blob_names.reserve(blobs_.size());
        for (const auto &name: blobs_ | std::views::keys) blob_names.push_back(name);
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
        for (const auto &tok: token_to_blobs_ | std::views::keys) tokens.push_back(tok);
        std::ranges::sort(tokens);

        for (const auto& tok : tokens) {
            const auto& bset = token_to_blobs_.at(tok);
            std::vector<std::string> sorted_b(bset.begin(), bset.end());
            std::ranges::sort(sorted_b);
            for (const auto& bname : sorted_b) {
                body << "MAP\t" << tok << '\t' << bname << '\n';
            }
        }
        return body.str();
    }

    void save_authenticated_index_unlocked() const {
        const std::string body = serialize_canonical_body_unlocked();
        const std::string mac = kms_->hmac_index_hex(body);
        vault_crypto::write_secret_file_0600(index_file_, body + "MAC\t" + mac + "\n");
    }

    void load_and_verify_index_unlocked() {
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
            } else {
                throw std::runtime_error("MetadataIndex: malformed record in index file");
            }
        }

        const std::string expected_mac = kms_->hmac_index_hex(body_accum.str());
        if (!vault_crypto::constant_time_hex_equal(file_mac, expected_mac)) {
            throw std::runtime_error("MetadataIndex: HMAC verification failed — vault_index.tsv was tampered with!");
        }
    }

    std::filesystem::path index_file_;
    std::filesystem::path audit_log_file_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, BlobEntry> blobs_;
    std::unordered_map<std::string, std::unordered_set<std::string>> token_to_blobs_;
    uint64_t audit_seq_ = 1;
    std::string last_audit_mac_ = std::string(64, '0');
    std::shared_ptr<vault_kms::KeyManagementProvider> kms_;
};

} // namespace vault_index