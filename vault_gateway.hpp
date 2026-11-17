#pragma once
// Hardened Zero-Knowledge RegTech Gateway Engine (v2):
//   - Process memory hardening (RLIMIT_CORE=0 + OPENSSL_cleanse RAII)
//   - HSM Master KEK loading/generation + RFC 3394 DEK wrapping
//   - 64 KiB fixed-bucket traffic-analysis padding
//   - 2-of-3 XOR erasure coding shard generation
//   - M-of-N (2-of-3) Compliance Officer Quorum enforcement on auditor queries

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include "at_rest_crypto.hpp"
#include "tokenizer.hpp"
#include "vault_index.hpp"

namespace vault_gateway {

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
    explicit GatewayEngine(const std::filesystem::path& state_dir, std::size_t quorum_threshold = 2)
        : state_dir_(state_dir),
          staging_dir_(state_dir / "egress_staging"),
          shards_dir_(state_dir / "erasure_shards"),
          token_vault_(state_dir / "vault_tokens.tsv"),
          metadata_index_(state_dir / "vault_index.tsv", state_dir / "regtech_audit.log"),
          quorum_gate_(quorum_threshold) {
        vault_crypto::harden_process_memory();
        std::filesystem::create_directories(staging_dir_);
        std::filesystem::create_directories(shards_dir_);
        master_kek_ = load_or_create_master_kek(state_dir_ / "hsm_master.kek");
    }

    const vault_index::QuorumGate& quorum_gate() const noexcept { return quorum_gate_; }

    std::string sign_quorum_approval(const std::string& officer_id, const std::string& identifier) const {
        return quorum_gate_.sign_approval(officer_id, identifier);
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

        std::vector<std::string> tokens_in_blob = extract_tokens(sanitized_csv);

        vault_crypto::SecretKey dek = vault_crypto::generate_key();
        const std::vector<uint8_t> ciphertext_envelope =
            vault_crypto::encrypt_envelope(sanitized_csv, dek, /*pad_traffic=*/true);
        OPENSSL_cleanse(sanitized_csv.data(), sanitized_csv.size());

        const std::string wrapped_dek = vault_crypto::wrap_dek_hex(dek, master_kek_);
        dek.cleanse();

        const std::string blob_name = make_blob_filename();
        const std::filesystem::path enc_path = staging_dir_ / blob_name;
        vault_crypto::write_bytes_to_file(enc_path.string(), ciphertext_envelope);

        const auto shards = vault_crypto::erasure_split_2of3(ciphertext_envelope);
        for (std::size_t s = 0; s < 3; ++s) {
            const auto shard_path = shards_dir_ / (blob_name + ".shard" + std::to_string(s));
            vault_crypto::write_bytes_to_file(shard_path.string(), shards[s]);
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

    AuditorQueryResult auditor_query(
        const std::string& raw_identifier,
        const std::filesystem::path& cloud_storage_dir,
        const std::vector<std::pair<std::string, std::string>>& quorum_approvals,
        const std::string& auditor_id = "CBE-Auditor-01") {

        AuditorQueryResult res;
        if (!quorum_gate_.verify_quorum(raw_identifier, quorum_approvals)) {
            res.authorized = false;
            res.denial_reason = "QUORUM DENIED: Requires at least " +
                                std::to_string(quorum_gate_.threshold()) +
                                " valid Compliance Officer signatures before PII unmasking.";
            metadata_index_.log_security_event(
                "QUORUM_DENIED",
                "Blocked unauthorized unmask attempt by '" + auditor_id + "' for '" + raw_identifier + "'");
            return res;
        }
        res.authorized = true;

        const std::string token = (raw_identifier.rfind("TOK_", 0) == 0)
                                      ? raw_identifier
                                      : token_vault_.tokenize(raw_identifier);
        res.matched_token = token;

        const auto matching_blobs = metadata_index_.lookup_by_token(token, auditor_id);
        if (matching_blobs.empty()) {
            return res;
        }

        std::ostringstream combined_restored;
        combined_restored << "tx_id,timestamp,customer_name,national_id,iban,ip_status,amount_egp,merchant\n";
        bool any_row_matched = false;

        for (const auto& blob : matching_blobs) {
            std::filesystem::path blob_path = cloud_storage_dir / blob.blob_name;
            if (!std::filesystem::exists(blob_path)) {
                blob_path = staging_dir_ / blob.blob_name;
            }
            if (!std::filesystem::exists(blob_path)) continue;

            const auto encrypted_bytes = vault_crypto::read_bytes_from_file(blob_path.string());
            if (res.raw_cloud_hex_preview.empty()) {
                res.raw_cloud_hex_preview = format_hex_dump(encrypted_bytes, 256);
            }

            vault_crypto::SecretKey dek = vault_crypto::unwrap_dek_hex(blob.wrapped_dek_hex, master_kek_);
            vault_crypto::SecretBuffer decrypted =
                vault_crypto::decrypt_envelope(encrypted_bytes.data(), encrypted_bytes.size(), dek, /*unpad_traffic=*/true);
            dek.cleanse();

            std::string sanitized_csv = decrypted.as_string();
            decrypted.cleanse();

            std::string full_restored = token_vault_.rehydrate_csv_batch(sanitized_csv);
            OPENSSL_cleanse(sanitized_csv.data(), sanitized_csv.size());

            std::istringstream lines(full_restored);
            std::string line;
            bool header = true;
            while (std::getline(lines, line)) {
                if (header) { header = false; continue; }
                if (line.find(raw_identifier) != std::string::npos) {
                    combined_restored << line << '\n';
                    any_row_matched = true;
                }
            }
            OPENSSL_cleanse(full_restored.data(), full_restored.size());
            res.blob_names.push_back(blob.blob_name);
        }

        res.found = any_row_matched;
        res.restored_csv = combined_restored.str();
        return res;
    }

private:
    static vault_crypto::SecretKey load_or_create_master_kek(const std::filesystem::path& kek_path) {
        if (std::filesystem::exists(kek_path)) {
            std::ifstream in(kek_path, std::ios::binary);
            std::string hex_str;
            std::getline(in, hex_str);
            const auto raw = vault_crypto::hex_to_bytes(hex_str);
            if (raw.size() != vault_crypto::KEY_LEN) {
                throw std::runtime_error("GatewayEngine: corrupted HSM master KEK");
            }
            vault_crypto::SecretKey kek;
            std::memcpy(kek.data(), raw.data(), vault_crypto::KEY_LEN);
            return kek;
        }
        vault_crypto::SecretKey kek = vault_crypto::generate_key();
        std::ofstream out(kek_path, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("GatewayEngine: cannot write HSM master KEK");
        out << vault_crypto::bytes_to_hex(kek.data(), kek.size()) << '\n';
        return kek;
    }

    static std::string make_blob_filename() {
        const auto now = std::chrono::system_clock::now().time_since_epoch();
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        return "vault_batch_" + std::to_string(ms) + ".enc";
    }

    static std::vector<std::string> extract_tokens(const std::string& sanitized_csv) {
        std::vector<std::string> tokens;
        std::size_t pos = 0;
        while ((pos = sanitized_csv.find("TOK_", pos)) != std::string::npos) {
            if (pos + 20 <= sanitized_csv.size()) {
                tokens.push_back(sanitized_csv.substr(pos, 20));
            }
            pos += 20;
        }
        return tokens;
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
    vault_token::TokenVault token_vault_;
    vault_index::MetadataIndex metadata_index_;
    vault_index::QuorumGate quorum_gate_;
    vault_crypto::SecretKey master_kek_;
};

} // namespace vault_gateway