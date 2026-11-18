#pragma once
// Hardened Zero-Knowledge RegTech Gateway Engine (v2.1):
//   - RLIMIT_CORE=0 + move-only OPENSSL_cleanse RAII keys/buffers
//   - Owner-only (0600) HSM Master KEK + per-officer keys
//   - HMAC-authenticated MetadataIndex + hash-chained audit log
//   - Data-bound M-of-N Compliance Quorum Gate
//   - Exact column-level token filtering (supports raw PII or TOK_... queries with zero merchant false positives)

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>
#include "at_rest_crypto.hpp"
#include "kms_provider.hpp"
#include "tokenizer.hpp"
#include "vault_index.hpp"

namespace vault_gateway {

class ErasureShardBackend {
public:
    virtual ~ErasureShardBackend() = default;
    virtual void write_shard(const std::filesystem::path& blob_name,
                             std::size_t shard_index,
                             const std::vector<uint8_t>& shard) = 0;
};

class LocalErasureShardBackend final : public ErasureShardBackend {
public:
    explicit LocalErasureShardBackend(std::filesystem::path shard_dir)
        : shard_dir_(std::move(shard_dir)) {
        std::filesystem::create_directories(shard_dir_);
    }

    void write_shard(const std::filesystem::path& blob_name,
                     std::size_t shard_index,
                     const std::vector<uint8_t>& shard) override {
        vault_crypto::write_bytes_to_file(
            (shard_dir_ / (blob_name.string() + ".shard" + std::to_string(shard_index))).string(),
            shard);
    }

private:
    std::filesystem::path shard_dir_;
};

struct OffloadArtifact {
    std::filesystem::path encrypted_file_path;
    std::string blob_name;
    vault_token::SanitizeStats stats;
    std::size_t padded_size_bytes = 0;
    std::size_t erasure_shard_bytes = 0;
    double elapsed_ms = 0.0;
    double records_per_sec = 0.0;
};

struct AuditorQueryResult {
    bool authorized = false;
    bool found = false;
    std::string denial_reason;
    std::string matched_token;
    std::vector<std::string> blob_names;
    std::string restored_csv;
    std::string raw_cloud_hex_preview;
};

class GatewayEngine {
public:
    explicit GatewayEngine(const std::filesystem::path& state_dir,
                           std::size_t quorum_threshold = 2,
                           std::shared_ptr<vault_kms::KeyManagementProvider> kms = nullptr,
                           std::shared_ptr<ErasureShardBackend> shard_backend = nullptr)
        : state_dir_(state_dir),
          staging_dir_(state_dir / "egress_staging"),
          shards_dir_(state_dir / "erasure_shards"),
          kms_(kms ? std::move(kms) : vault_kms::create_default_kms(state_dir)),
          shard_backend_(shard_backend ? std::move(shard_backend)
                                       : std::make_shared<LocalErasureShardBackend>(state_dir / "erasure_shards")),
          token_vault_(state_dir / "vault_tokens.enc", kms_),
          metadata_index_(state_dir / "vault_index.tsv", state_dir / "regtech_audit.log", kms_),
          quorum_gate_(state_dir / "officers", quorum_threshold) {
        vault_crypto::harden_process_memory();
        std::filesystem::create_directories(staging_dir_);
        std::filesystem::create_directories(shards_dir_);
    }
    const vault_index::QuorumGate& quorum_gate() const noexcept { return quorum_gate_; }
    const vault_index::MetadataIndex& metadata_index() const noexcept { return metadata_index_; }

    // Collects cryptographic officer signatures bound to each candidate blob for `identifier`
    std::vector<std::pair<std::string, std::string>> collect_officer_approvals(
        const std::string& officer_id,
        const std::string& raw_or_token_identifier)  {
        const std::string token = resolve_to_token(raw_or_token_identifier);
        const auto blobs = metadata_index_.find_candidate_blobs(token);
        std::vector<std::pair<std::string, std::string>> signed_releases;
        for (const auto& blob : blobs) {
            signed_releases.emplace_back(
                officer_id,
                quorum_gate_.sign_blob_release(officer_id, token, blob));
        }
        return signed_releases;
    }

    std::filesystem::path generate_synthetic_cbe_batch(std::size_t row_count = 10000) const {
        const auto out_path = staging_dir_ / ("cbe_raw_tx_" + std::to_string(row_count) + ".csv");
        std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("GatewayEngine: cannot create synthetic batch file");

        static const std::vector<std::string> names = {
            "Ahmed Hassan", "Mona El-Sayed", "Youssef Mahmoud", "Nourhan Tarek",
            "Karim Abdel-Rahman", "Salma Ibrahim", "Mostafa Adel", "Hana Sherif"
        };
        static const std::vector<std::string> merchants = {
            "InstaPay-P2P", "Carrefour-Maadi", "Fawry-BillPay", "Amazon-EG",
            "Gourmet-Zamalek", "Talabat-Cairo", "WE-Telecom", "Mobil-NasrCity"
        };

        std::mt19937_64 rng(20261117);
        std::uniform_int_distribution<std::size_t> merch_dist(0, merchants.size() - 1);
        std::uniform_int_distribution<int> ip_octet(2, 254);
        std::uniform_int_distribution<int> amt_dist(50, 45000);

        out << "tx_id,timestamp,customer_name,national_id,iban,source_ip,amount_egp,merchant\n";
        for (std::size_t i = 0; i < row_count; ++i) {
            const std::size_t cust_idx = i % names.size();
            const std::string nat_id = "3010811010" + std::to_string(1000 + cust_idx);
            const std::string iban   = "EG38001900050000000026318" + std::to_string(1000 + cust_idx);
            const std::string ip     = "41." + std::to_string(ip_octet(rng)) + "." +
                                       std::to_string(ip_octet(rng)) + "." + std::to_string(ip_octet(rng));

            out << "TXN" << (1000000 + i) << ','
                << "2026-11-17T20:" << std::setw(2) << std::setfill('0') << (i % 60) << ":00Z,"
                << names[cust_idx] << ','
                << nat_id << ','
                << iban << ','
                << ip << ','
                << amt_dist(rng) << ".00,"
                << merchants[merch_dist(rng)] << '\n';
        }
        return out_path;
    }

    OffloadArtifact prepare_encrypted_offload(const std::filesystem::path& raw_csv_path) {
        const auto t0 = std::chrono::steady_clock::now();

        std::ifstream in(raw_csv_path, std::ios::binary);
        if (!in) throw std::runtime_error("GatewayEngine: cannot open CSV " + raw_csv_path.string());
        std::string raw_csv((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

        vault_token::SanitizeStats stats;
        std::string sanitized_csv = token_vault_.sanitize_csv_batch(raw_csv, &stats);
        OPENSSL_cleanse(raw_csv.data(), raw_csv.size());

        // Structured CSV column extraction (columns 2, 3, 4 only)
        std::vector<std::string> tokens_in_blob = extract_tokens_from_columns(sanitized_csv);

        vault_crypto::SecretKey dek = vault_crypto::generate_key();
        const std::string blob_name = make_blob_filename();
        const std::vector<uint8_t> ciphertext_envelope =
            vault_crypto::encrypt_envelope(
                sanitized_csv, dek, /*pad_traffic=*/true, blob_name);
        OPENSSL_cleanse(sanitized_csv.data(), sanitized_csv.size());

        const std::string wrapped_dek = kms_->wrap_dek_hex(dek);
        dek.cleanse();

        const std::filesystem::path enc_path = staging_dir_ / blob_name;
        vault_crypto::write_bytes_to_file(enc_path.string(), ciphertext_envelope);

        const auto shards = vault_crypto::erasure_split_2of3(ciphertext_envelope);
        for (std::size_t s = 0; s < 3; ++s) {
            shard_backend_->write_shard(blob_name, s, shards[s]);
        }

        vault_index::BlobEntry entry;
        entry.blob_name       = blob_name;
        entry.wrapped_dek_hex = wrapped_dek;
        entry.record_count    = stats.records_processed;
        entry.padded_bytes    = ciphertext_envelope.size();
        metadata_index_.register_blob(entry, tokens_in_blob);

        const auto t1 = std::chrono::steady_clock::now();
        const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        const double rps = (ms > 0.0) ? (static_cast<double>(stats.records_processed) / (ms / 1000.0)) : 0.0;

        return OffloadArtifact{
            enc_path, blob_name, stats,
            ciphertext_envelope.size(), shards[0].size(), ms, rps
        };
    }

    // Per-blob data-bound quorum verification + exact column token filtering BEFORE re-hydration
    AuditorQueryResult auditor_query(
        const std::string& raw_or_token_identifier,
        const std::filesystem::path& cloud_storage_dir,
        const std::vector<std::pair<std::string, std::string>>& blob_quorum_approvals,
        const std::string& auditor_id = "CBE-Auditor-01") {

        AuditorQueryResult res;
        const std::string token = resolve_to_token(raw_or_token_identifier);
        res.matched_token = token;

        const auto candidate_blobs = metadata_index_.find_candidate_blobs(token);
        if (candidate_blobs.empty()) {
            // Even when no blobs match, verify at least threshold distinct officers signed off
            // so unauthorized callers cannot probe token existence
            vault_index::BlobEntry dummy{"NONE", "NONE", 0, 0, ""};
            if (!quorum_gate_.verify_blob_release(token, dummy, blob_quorum_approvals)) {
                res.authorized = false;
                res.denial_reason = "QUORUM DENIED: Requires at least " +
                                    std::to_string(quorum_gate_.threshold()) +
                                    " valid Compliance Officer signatures.";
                metadata_index_.log_security_event(
                    "QUORUM_DENIED",
                    "Blocked unauthorized probe by '" + auditor_id + "' for token '" + token + "'");
                return res;
            }
            res.authorized = true;
            res.found = false;
            return res;
        }

        std::ostringstream combined_restored;
        combined_restored << "tx_id,timestamp,customer_name,national_id,iban,ip_status,amount_egp,merchant\n";
        bool any_blob_authorized = false;
        bool any_row_matched = false;

        for (const auto& blob : candidate_blobs) {
            if (!quorum_gate_.verify_blob_release(token, blob, blob_quorum_approvals)) {
                metadata_index_.log_security_event(
                    "QUORUM_DENIED",
                    "Blocked unauthorized release of blob '" + blob.blob_name + "' for token '" + token + "'");
                continue;
            }
            any_blob_authorized = true;

            std::filesystem::path blob_path = cloud_storage_dir / blob.blob_name;
            if (!std::filesystem::exists(blob_path)) {
                blob_path = staging_dir_ / blob.blob_name;
            }
            if (!std::filesystem::exists(blob_path)) continue;

            const auto encrypted_bytes = vault_crypto::read_bytes_from_file(blob_path.string());
            if (res.raw_cloud_hex_preview.empty()) {
                res.raw_cloud_hex_preview = format_hex_dump(encrypted_bytes, 256);
            }

            vault_crypto::SecretKey dek = kms_->unwrap_dek_hex(blob.wrapped_dek_hex);
            vault_crypto::SecretBuffer decrypted =
                vault_crypto::decrypt_envelope(
                    encrypted_bytes.data(), encrypted_bytes.size(), dek,
                    /*unpad_traffic=*/true, blob.blob_name);
            dek.cleanse();

            std::string sanitized_csv = decrypted.as_string();
            decrypted.cleanse();

            // Filter exact tokenized PII columns (cols 2, 3, 4) BEFORE re-hydrating
            std::istringstream lines(sanitized_csv);
            std::string line;
            bool header = true;
            while (std::getline(lines, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (header) { header = false; continue; }
                if (line.empty()) continue;

                const auto cols = vault_token::parse_csv_row(line);
                if (cols.size() < 8) continue;

                if (cols[2] == token || cols[3] == token || cols[4] == token) {
                    vault_token::TransactionRecord clean{
                        cols[0], cols[1], cols[2], cols[3], cols[4], cols[5], cols[6], cols[7]
                    };
                    const auto restored = token_vault_.rehydrate_record(clean);
                    combined_restored << vault_token::format_csv_row({
                        restored.tx_id, restored.timestamp, restored.customer_name,
                        restored.national_id, restored.iban, restored.source_ip,
                        restored.amount_egp, restored.merchant
                    }) << '\n';
                    any_row_matched = true;
                }
            }
            OPENSSL_cleanse(sanitized_csv.data(), sanitized_csv.size());
            res.blob_names.push_back(blob.blob_name);
        }

        if (!any_blob_authorized) {
            res.authorized = false;
            res.denial_reason = "QUORUM DENIED: Requires at least " +
                                std::to_string(quorum_gate_.threshold()) +
                                " valid Compliance Officer signatures bound to target blob.";
            return res;
        }

        res.authorized = true;
        res.found = any_row_matched;
        res.restored_csv = combined_restored.str();
        metadata_index_.log_security_event(
            "QUORUM_RELEASE",
            "Auditor '" + auditor_id + "' unlocked token '" + token +
            "' across " + std::to_string(res.blob_names.size()) + " blob(s)");
        return res;
    }

    void rotate_master_kek(
        const vault_crypto::SecretKey& new_master_kek,
        const std::filesystem::path& cloud_storage_dir = {}) {
        if (!kms_->can_rotate_master_kek_in_app()) {
            throw std::runtime_error(
                "GatewayEngine: master KEK rotation is administratively managed by the KMS/HSM backend");
        }
        if (!metadata_index_.verify_audit_chain()) {
            throw std::runtime_error("GatewayEngine: refusing KEK rotation with tampered audit chain");
        }

        struct RotationBlob {
            std::string blob_name;
            vault_crypto::SecretKey dek;
            std::string rehydrated_csv;
        };
        std::vector<RotationBlob> rotation_blobs;
        for (const auto& entry : metadata_index_.blob_entries()) {
            auto blob_path = staging_dir_ / entry.blob_name;
            if (!cloud_storage_dir.empty()) {
                const auto cloud_path = cloud_storage_dir / entry.blob_name;
                if (std::filesystem::exists(cloud_path)) blob_path = cloud_path;
            }
            if (!std::filesystem::exists(blob_path)) {
                throw std::runtime_error("GatewayEngine: cannot rotate missing blob '" +
                                         entry.blob_name + "'");
            }

            vault_crypto::SecretKey dek = kms_->unwrap_dek_hex(entry.wrapped_dek_hex);
            const auto encrypted = vault_crypto::read_bytes_from_file(blob_path.string());
            vault_crypto::SecretBuffer decrypted =
                vault_crypto::decrypt_envelope(
                    encrypted.data(), encrypted.size(), dek,
                    /*unpad_traffic=*/true, entry.blob_name);
            std::string sanitized_csv = decrypted.as_string();
            decrypted.cleanse();

            std::string rehydrated_csv = token_vault_.rehydrate_csv_batch(sanitized_csv);
            OPENSSL_cleanse(sanitized_csv.data(), sanitized_csv.size());
            rotation_blobs.push_back(
                RotationBlob{entry.blob_name, std::move(dek), std::move(rehydrated_csv)});
        }

        kms_->rotate_master_kek(new_master_kek);
        metadata_index_.reauthenticate_after_kms_rotation();
        const auto token_remap = token_vault_.rotate_kms_pepper();
        metadata_index_.remap_tokens(token_remap);
        token_vault_.flush();

        for (auto& rotation_blob : rotation_blobs) {
            std::string sanitized_csv =
                token_vault_.sanitize_csv_batch(rotation_blob.rehydrated_csv);
            const auto reencrypted =
                vault_crypto::encrypt_envelope(
                    sanitized_csv, rotation_blob.dek,
                    /*pad_traffic=*/true, rotation_blob.blob_name);
            OPENSSL_cleanse(sanitized_csv.data(), sanitized_csv.size());

            const auto staging_path = staging_dir_ / rotation_blob.blob_name;
            vault_crypto::write_bytes_to_file(staging_path.string(), reencrypted);
            if (!cloud_storage_dir.empty()) {
                vault_crypto::write_bytes_to_file(
                    (cloud_storage_dir / rotation_blob.blob_name).string(), reencrypted);
            }

            const std::string rewrapped = kms_->wrap_dek_hex(rotation_blob.dek);
            metadata_index_.update_wrapped_dek(rotation_blob.blob_name, rewrapped);
        }
    }

private:
    std::string resolve_to_token(const std::string& raw_or_token) {
        if (raw_or_token.rfind("TOK_", 0) == 0) {
            return raw_or_token;
        }
        // Const-safe lookup or deterministic compute via TokenVault
        return const_cast<vault_token::TokenVault&>(token_vault_).tokenize(raw_or_token);
    }

    static std::string make_blob_filename() {
        const auto now = std::chrono::system_clock::now().time_since_epoch();
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        return "vault_batch_" + std::to_string(ms) + ".enc";
    }

    static std::vector<std::string> extract_tokens_from_columns(const std::string& sanitized_csv) {
        std::unordered_set<std::string> unique_tokens;
        std::istringstream in(sanitized_csv);
        std::string line;
        bool header = true;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (header) { header = false; continue; }
            if (line.empty()) continue;

            const auto cols = vault_token::parse_csv_row(line);
            if (cols.size() < 8) continue;
            for (std::size_t col_idx : {2u, 3u, 4u}) {
                if (cols[col_idx].rfind("TOK_", 0) == 0) {
                    unique_tokens.insert(cols[col_idx]);
                }
            }
        }
        return std::vector<std::string>(unique_tokens.begin(), unique_tokens.end());
    }

    static std::string format_hex_dump(const std::vector<uint8_t>& bytes, std::size_t max_bytes) {
        static constexpr char hex[] = "0123456789ABCDEF";
        std::ostringstream ss;
        const std::size_t limit = std::min(bytes.size(), max_bytes);
        for (std::size_t i = 0; i < limit; ++i) {
            if (i > 0 && i % 16 == 0) ss << '\n';
            else if (i > 0) ss << ' ';
            ss << hex[bytes[i] >> 4] << hex[bytes[i] & 0x0F];
        }
        if (bytes.size() > max_bytes) {
            ss << "\n... [" << (bytes.size() - max_bytes) << " more 64KiB-padded BVL2 encrypted bytes]";
        }
        return ss.str();
    }

    std::filesystem::path state_dir_;
    std::filesystem::path staging_dir_;
    std::filesystem::path shards_dir_;
    std::shared_ptr<vault_kms::KeyManagementProvider> kms_;
    std::shared_ptr<ErasureShardBackend> shard_backend_;
    vault_token::TokenVault token_vault_;
    vault_index::MetadataIndex metadata_index_;
    vault_index::QuorumGate quorum_gate_;
};

} // namespace vault_gateway