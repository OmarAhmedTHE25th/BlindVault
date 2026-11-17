#pragma once
// Local Metadata Index, RFC 3394 Wrapped-DEK Store, & M-of-N Compliance Quorum Gate.

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "at_rest_crypto.hpp"

namespace vault_index {

struct BlobEntry {
    std::string blob_name;        // e.g., "vault_batch_1731870000.enc"
    std::string wrapped_dek_hex;  // 80-char hex (40-byte RFC 3394 wrapped DEK; zero plaintext keys on disk)
    std::size_t record_count = 0;
    std::size_t padded_bytes = 0; // 64 KiB-aligned ciphertext size
    std::string created_utc;
};

// M-of-N Dual-Custody Quorum Gate: requires cryptographic sign-off from at least `threshold`
// distinct Compliance Officers before unmasking customer PII.
class QuorumGate {
public:
    explicit QuorumGate(std::size_t threshold = 2) : threshold_(threshold) {
        // Pre-provisioned CBE Compliance Officer signing secrets (simulated HSM officer keys)
        officer_secrets_["CBE-Officer-1"] = "cbe_quorum_secret_alpha_2026";
        officer_secrets_["CBE-Officer-2"] = "cbe_quorum_secret_beta_2026";
        officer_secrets_["CBE-Officer-3"] = "cbe_quorum_secret_gamma_2026";
    }

    std::size_t threshold() const noexcept { return threshold_; }

    // Generates a cryptographic approval token for (officer_id, target_identifier)
    std::string sign_approval(const std::string& officer_id, const std::string& target_identifier) const {
        auto it = officer_secrets_.find(officer_id);
        if (it == officer_secrets_.end()) {
            throw std::runtime_error("QuorumGate: unknown compliance officer '" + officer_id + "'");
        }
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        const std::string msg = officer_id + ":" + target_identifier;
        if (!HMAC(EVP_sha256(),
                  it->second.data(), static_cast<int>(it->second.size()),
                  reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                  digest, &len)) {
            throw std::runtime_error("QuorumGate: HMAC approval signing failed");
        }
        return vault_crypto::bytes_to_hex(digest, 16);
    }

    // Verifies that at least `threshold_` distinct authorized officers signed off on `target_identifier`
    bool verify_quorum(const std::string& target_identifier,
                       const std::vector<std::pair<std::string, std::string>>& approvals) const {
        std::unordered_set<std::string> valid_officers;
        for (const auto& [officer_id, sig] : approvals) {
            auto it = officer_secrets_.find(officer_id);
            if (it == officer_secrets_.end()) continue;
            const std::string expected = sign_approval(officer_id, target_identifier);
            if (sig == expected) {
                valid_officers.insert(officer_id);
            }
        }
        return valid_officers.size() >= threshold_;
    }

private:
    std::size_t threshold_;
    std::unordered_map<std::string, std::string> officer_secrets_;
};

class MetadataIndex {
public:
    MetadataIndex(std::filesystem::path index_file, std::filesystem::path audit_log_file)
        : index_file_(std::move(index_file)), audit_log_file_(std::move(audit_log_file)) {
        load_unlocked();
    }

    void register_blob(const BlobEntry& entry, const std::vector<std::string>& tokens_in_blob) {
        std::lock_guard<std::mutex> lock(mutex_);
        BlobEntry stored = entry;
        if (stored.created_utc.empty()) stored.created_utc = current_utc_iso();
        blobs_[stored.blob_name] = stored;

        for (const auto& tok : tokens_in_blob) {
            if (!tok.empty()) {
                token_to_blobs_[tok].insert(stored.blob_name);
            }
        }
        save_unlocked();
        append_audit_unlocked("INGEST", "Offloaded 64KiB-padded blob '" + stored.blob_name +
                                        "' (" + std::to_string(stored.record_count) + " records, " +
                                        std::to_string(stored.padded_bytes) + " bytes, DEK wrapped via RFC3394)");
    }

    std::vector<BlobEntry> lookup_by_token(const std::string& token, const std::string& auditor_id = "system") {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<BlobEntry> results;
        auto it = token_to_blobs_.find(token);
        if (it != token_to_blobs_.end()) {
            for (const auto& blob_name : it->second) {
                auto b_it = blobs_.find(blob_name);
                if (b_it != blobs_.end()) {
                    results.push_back(b_it->second);
                }
            }
        }
        append_audit_unlocked("QUORUM_QUERY", "Auditor '" + auditor_id + "' unlocked token '" + token +
                                             "' -> matched " + std::to_string(results.size()) + " blob(s)");
        return results;
    }

    void log_security_event(const std::string& action, const std::string& detail) const {
        std::lock_guard<std::mutex> lock(mutex_);
        append_audit_unlocked(action, detail);
    }

    std::optional<BlobEntry> get_blob(const std::string& blob_name) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = blobs_.find(blob_name);
        if (it == blobs_.end()) return std::nullopt;
        return it->second;
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

    void append_audit_unlocked(const std::string& action, const std::string& detail) const {
        std::ofstream log(audit_log_file_, std::ios::app);
        if (log) {
            log << current_utc_iso() << " | " << action << " | " << detail << '\n';
        }
    }

    void save_unlocked() const {
        std::filesystem::path tmp = index_file_;
        tmp += ".tmp";
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out) throw std::runtime_error("MetadataIndex: cannot write " + tmp.string());
            for (const auto& [blob_name, entry] : blobs_) {
                out << "BLOB\t" << entry.blob_name << '\t' << entry.wrapped_dek_hex
                    << '\t' << entry.record_count << '\t' << entry.padded_bytes
                    << '\t' << entry.created_utc << '\n';
            }
            for (const auto& [token, blob_set] : token_to_blobs_) {
                for (const auto& blob_name : blob_set) {
                    out << "MAP\t" << token << '\t' << blob_name << '\n';
                }
            }
            out.flush();
            if (!out) throw std::runtime_error("MetadataIndex: flush failed");
        }
        std::error_code ec;
        std::filesystem::rename(tmp, index_file_, ec);
        if (ec) throw std::runtime_error("MetadataIndex: rename failed: " + ec.message());
    }

    void load_unlocked() {
        std::ifstream in(index_file_, std::ios::binary);
        if (!in) return;
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
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
            }
        }
    }

    std::filesystem::path index_file_;
    std::filesystem::path audit_log_file_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, BlobEntry> blobs_;
    std::unordered_map<std::string, std::unordered_set<std::string>> token_to_blobs_;
};

} // namespace vault_index