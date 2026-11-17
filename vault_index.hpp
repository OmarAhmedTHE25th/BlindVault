#pragma once
// Local Metadata Index & RegTech Compliance Audit Trail.
// Tracks which encrypted blob on the untrusted cloud holds which tokenized
// customer records, enabling O(1) targeted retrieval without downloading
// the entire remote archive.

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

namespace vault_index {

struct BlobEntry {
    std::string blob_name;     // e.g., "batch_20261117_221000.enc"
    std::string aes_key_hex;   // 64-char hex AES-256 key (kept strictly on-prem)
    std::size_t record_count = 0;
    std::string created_utc;
};

class MetadataIndex {
public:
    MetadataIndex(std::filesystem::path index_file, std::filesystem::path audit_log_file)
        : index_file_(std::move(index_file)), audit_log_file_(std::move(audit_log_file)) {
        load_unlocked();
    }

    // Registers an offloaded encrypted batch and indexes all tokens inside it
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
        append_audit_unlocked("INGEST", "Offloaded encrypted blob '" + stored.blob_name +
                                        "' (" + std::to_string(stored.record_count) + " records)");
    }

    // Finds every remote encrypted blob containing records for a given token
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
        append_audit_unlocked("QUERY", "Auditor '" + auditor_id + "' queried token '" + token +
                                       "' -> matched " + std::to_string(results.size()) + " blob(s)");
        return results;
    }

    std::optional<BlobEntry> get_blob(const std::string& blob_name) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = blobs_.find(blob_name);
        if (it == blobs_.end()) return std::nullopt;
        return it->second;
    }

    std::vector<BlobEntry> all_blobs() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<BlobEntry> out;
        out.reserve(blobs_.size());
        for (const auto& [_, entry] : blobs_) out.push_back(entry);
        return out;
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
                out << "BLOB\t" << entry.blob_name << '\t' << entry.aes_key_hex
                    << '\t' << entry.record_count << '\t' << entry.created_utc << '\n';
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

            if (parts.size() == 5 && parts[0] == "BLOB") {
                BlobEntry e{parts[1], parts[2], static_cast<std::size_t>(std::stoull(parts[3])), parts[4]};
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