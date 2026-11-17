#pragma once
// Orchestrates the Bank-Side Zero-Knowledge RegTech Pipeline:
//   1. Synthetic Egyptian Banking Transaction Generator (for live benchmarking)
//   2. Pre-Egress PII Tokenization + IP Masking + AES-256-GCM Encryption
//   3. Post-Fetch Auditor Query + Decryption + Re-hydration

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include "at_rest_crypto.hpp"
#include "tokenizer.hpp"
#include "vault_index.hpp"

namespace vault_gateway {

struct OffloadArtifact {
    std::filesystem::path encrypted_file_path;
    std::string blob_name;
    vault_token::SanitizeStats stats;
    double elapsed_ms = 0.0;
    double records_per_sec = 0.0;
};

struct AuditorQueryResult {
    bool found = false;
    std::string matched_token;
    std::vector<std::string> blob_names;
    std::string restored_csv;
    std::string raw_cloud_hex_preview;
};

class GatewayEngine {
public:
    explicit GatewayEngine(const std::filesystem::path& state_dir)
        : state_dir_(state_dir),
          staging_dir_(state_dir / "egress_staging"),
          token_vault_(state_dir / "vault_tokens.tsv"),
          metadata_index_(state_dir / "vault_index.tsv", state_dir / "regtech_audit.log") {
        std::filesystem::create_directories(staging_dir_);
    }

    // Generates a realistic synthetic CSV of Egyptian banking transactions for live demos
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
        std::uniform_int_distribution<std::size_t> name_dist(0, names.size() - 1);
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

    // Runs: Read CSV -> Tokenize PII & Mask IPs -> Encrypt AES-256-GCM -> Write .enc -> Index
    OffloadArtifact prepare_encrypted_offload(const std::filesystem::path& raw_csv_path) {
        const auto t0 = std::chrono::steady_clock::now();

        std::ifstream in(raw_csv_path, std::ios::binary);
        if (!in) throw std::runtime_error("GatewayEngine: cannot open CSV " + raw_csv_path.string());
        const std::string raw_csv((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

        vault_token::SanitizeStats stats;
        const std::string sanitized_csv = token_vault_.sanitize_csv_batch(raw_csv, &stats);

        // Extract unique tokens from the sanitized payload to populate the MetadataIndex
        std::vector<std::string> tokens_in_blob = extract_tokens(sanitized_csv);

        // Encrypt at rest with fresh per-batch AES-256-GCM key
        const vault_crypto::Key aes_key = vault_crypto::generate_key();
        const std::vector<uint8_t> ciphertext_envelope = vault_crypto::encrypt_envelope(sanitized_csv, aes_key);

        const std::string blob_name = make_blob_filename();
        const std::filesystem::path enc_path = staging_dir_ / blob_name;
        vault_crypto::write_bytes_to_file(enc_path.string(), ciphertext_envelope);

        vault_index::BlobEntry entry;
        entry.blob_name    = blob_name;
        entry.aes_key_hex  = vault_crypto::key_to_hex(aes_key);
        entry.record_count = stats.records_processed;
        metadata_index_.register_blob(entry, tokens_in_blob);

        const auto t1 = std::chrono::steady_clock::now();
        const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        const double rps = (ms > 0.0) ? (static_cast<double>(stats.records_processed) / (ms / 1000.0)) : 0.0;

        return OffloadArtifact{enc_path, blob_name, stats, ms, rps};
    }

    // Searches by raw PII (Name, National ID, IBAN) or token, locates the .enc blob in cloud storage,
    // decrypts AES-256-GCM locally, and re-hydrates matching rows for the bank auditor.
    AuditorQueryResult auditor_query(const std::string& raw_identifier,
                                     const std::filesystem::path& cloud_storage_dir,
                                     const std::string& auditor_id = "CBE-Auditor-01") {
        AuditorQueryResult res;
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
                // Fallback to local staging if cloud node saved to default directory
                blob_path = staging_dir_ / blob.blob_name;
            }
            if (!std::filesystem::exists(blob_path)) continue;

            const auto encrypted_bytes = vault_crypto::read_bytes_from_file(blob_path.string());
            if (res.raw_cloud_hex_preview.empty()) {
                res.raw_cloud_hex_preview = format_hex_dump(encrypted_bytes, 256);
            }

            const auto key = vault_crypto::hex_to_key(blob.aes_key_hex);
            const auto decrypted_bytes = vault_crypto::decrypt_envelope(
                encrypted_bytes.data(), encrypted_bytes.size(), key);
            const std::string sanitized_csv(
                reinterpret_cast<const char*>(decrypted_bytes.data()), decrypted_bytes.size());

            const std::string full_restored = token_vault_.rehydrate_csv_batch(sanitized_csv);
            std::istringstream lines(full_restored);
            std::string line;
            bool header = true;
            while (std::getline(lines, line)) {
                if (header) { header = false; continue; }
                if (line.find(raw_identifier) != std::string::npos ||
                    sanitized_csv.find(token) != std::string::npos) {
                    if (line.find(raw_identifier) != std::string::npos) {
                        combined_restored << line << '\n';
                        any_row_matched = true;
                    }
                }
            }
            res.blob_names.push_back(blob.blob_name);
        }

        res.found = any_row_matched;
        res.restored_csv = combined_restored.str();
        return res;
    }

private:
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
            ss << "\n... [" << (bytes.size() - max_bytes) << " more encrypted bytes on cloud disk]";
        }
        return ss.str();
    }

    std::filesystem::path state_dir_;
    std::filesystem::path staging_dir_;
    vault_token::TokenVault token_vault_;
    vault_index::MetadataIndex metadata_index_;
};

} // namespace vault_gateway