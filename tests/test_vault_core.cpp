#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>
#include "at_rest_crypto.hpp"
#include "tokenizer.hpp"
#include "vault_gateway.hpp"

namespace {

class TempDir {
public:
    TempDir() {
        std::random_device rd;
        path_ = std::filesystem::temp_directory_path() /
                ("blindvault_test_" + std::to_string(rd()) + std::to_string(rd()));
        std::filesystem::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }

    [[nodiscard]] std::filesystem::path file(const std::string& name) const { return path_ / name; }
private:
    std::filesystem::path path_;
};

} // namespace

// ---------------- AES-256-GCM At-Rest Crypto ----------------

TEST(VaultCrypto, RoundTripEncryptAndDecrypt) {
    const auto key = vault_crypto::generate_key();
    const std::string secret_csv = "TXN1001,2026-11-17T10:00:00Z,TOK_1234567890abcdef,5000.00,InstaPay\n";

    const auto envelope = vault_crypto::encrypt_envelope(secret_csv, key);
    ASSERT_GT(envelope.size(), vault_crypto::HEADER_LEN);
    EXPECT_EQ(envelope[0], 'B');
    EXPECT_EQ(envelope[1], 'V');
    EXPECT_EQ(envelope[2], 'L');
    EXPECT_EQ(envelope[3], 'T');

    const auto decrypted = vault_crypto::decrypt_envelope(envelope.data(), envelope.size(), key);
    const std::string restored(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
    EXPECT_EQ(restored, secret_csv);
}

TEST(VaultCrypto, KeyHexRoundTrip) {
    const auto key = vault_crypto::generate_key();
    const std::string hex = vault_crypto::key_to_hex(key);
    EXPECT_EQ(hex.size(), 64u);
    EXPECT_EQ(vault_crypto::hex_to_key(hex), key);
}

TEST(VaultCrypto, DetectsTamperedCiphertextOrWrongKey) {
    const auto key = vault_crypto::generate_key();
    const auto wrong_key = vault_crypto::generate_key();
    auto envelope = vault_crypto::encrypt_envelope("sensitive banking ledger", key);

    // Wrong key must fail GCM tag verification
    EXPECT_THROW(vault_crypto::decrypt_envelope(envelope.data(), envelope.size(), wrong_key), std::runtime_error);

    // Flipping a single bit in the ciphertext must fail GCM tag verification
    envelope.back() ^= 0x01;
    EXPECT_THROW(vault_crypto::decrypt_envelope(envelope.data(), envelope.size(), key), std::runtime_error);
}

// ---------------- PII & IP Tokenizer ----------------

TEST(Tokenizer, DeterministicTokensAndIpMasking) {
    TempDir dir;
    std::array<uint8_t, 32> fixed_pepper{};
    fixed_pepper.fill(0x42);

    vault_token::TokenVault vault(dir.file("tokens.tsv"), fixed_pepper);

    const std::string t1 = vault.tokenize("30108110101000");
    const std::string t2 = vault.tokenize("30108110101000");
    const std::string t3 = vault.tokenize("29901010102222");

    EXPECT_EQ(t1, t2);
    EXPECT_NE(t1, t3);
    EXPECT_EQ(t1.rfind("TOK_", 0), 0u);
    EXPECT_EQ(t1.size(), 20u);
    EXPECT_EQ(vault.detokenize(t1), "30108110101000");

    vault_token::TransactionRecord raw{
        "TXN99", "2026-11-17T12:00:00Z", "Ahmed Hassan",
        "30108110101000", "EG380019000500000000263181000",
        "41.234.12.88", "1250.00", "Fawry-BillPay"
    };

    vault_token::SanitizeStats stats{};
    const auto clean = vault.sanitize_record(raw, &stats);
    EXPECT_EQ(clean.source_ip, "REDACTED_IP");
    EXPECT_NE(clean.customer_name, "Ahmed Hassan");
    EXPECT_NE(clean.national_id, "30108110101000");
    EXPECT_NE(clean.iban, "EG380019000500000000263181000");
    EXPECT_EQ(stats.records_processed, 1u);
    EXPECT_EQ(stats.pii_fields_tokenized, 3u);
    EXPECT_EQ(stats.ips_masked, 1u);

    const auto restored = vault.rehydrate_record(clean);
    EXPECT_EQ(restored.customer_name, "Ahmed Hassan");
    EXPECT_EQ(restored.national_id, "30108110101000");
    EXPECT_EQ(restored.iban, "EG380019000500000000263181000");
}

TEST(Tokenizer, PersistsAcrossReloads) {
    TempDir dir;
    std::array<uint8_t, 32> fixed_pepper{};
    fixed_pepper.fill(0x11);

    std::string tok;
    {
        vault_token::TokenVault v1(dir.file("tokens.tsv"), fixed_pepper);
        tok = v1.tokenize("Mona El-Sayed");
        v1.flush();
    }
    {
        vault_token::TokenVault v2(dir.file("tokens.tsv"), fixed_pepper);
        EXPECT_EQ(v2.detokenize(tok), "Mona El-Sayed");
    }
}

// ---------------- Metadata Index & End-to-End Gateway ----------------

TEST(VaultGateway, EndToEndOffloadZeroLeakageAndAuditorRehydration) {
    TempDir dir;
    const auto cloud_bucket = dir.file("cloud_bucket");
    std::filesystem::create_directories(cloud_bucket);

    vault_gateway::GatewayEngine gateway(dir.file("bank_state"));

    // 1. Generate 250 synthetic Egyptian banking transactions
    const auto raw_csv_path = gateway.generate_synthetic_cbe_batch(250);
    ASSERT_TRUE(std::filesystem::exists(raw_csv_path));

    // 2. Sanitize, encrypt at rest, and index
    const auto artifact = gateway.prepare_encrypted_offload(raw_csv_path);
    EXPECT_EQ(artifact.stats.records_processed, 250u);
    EXPECT_EQ(artifact.stats.ips_masked, 250u);
    ASSERT_TRUE(std::filesystem::exists(artifact.encrypted_file_path));

    // Simulate network transfer to the untrusted cloud bucket
    const auto cloud_blob_path = cloud_bucket / artifact.blob_name;
    std::filesystem::copy_file(artifact.encrypted_file_path, cloud_blob_path);

    // 3. Zero-knowledge check: the cloud blob must contain zero plaintext PII or IPs
    const auto raw_cloud_bytes = vault_crypto::read_bytes_from_file(cloud_blob_path.string());
    const std::string raw_cloud_str(reinterpret_cast<const char*>(raw_cloud_bytes.data()), raw_cloud_bytes.size());
    EXPECT_EQ(raw_cloud_str.find("Ahmed Hassan"), std::string::npos);
    EXPECT_EQ(raw_cloud_str.find("30108110101000"), std::string::npos);
    EXPECT_EQ(raw_cloud_str.find("EG380019"), std::string::npos);
    EXPECT_EQ(raw_cloud_str.find("41."), std::string::npos);

    // 4. Auditor query by National ID must fetch, decrypt, and restore matching records
    const auto query_res = gateway.auditor_query("30108110101000", cloud_bucket, "Test-Auditor");
    EXPECT_TRUE(query_res.found);
    EXPECT_NE(query_res.restored_csv.find("Ahmed Hassan"), std::string::npos);
    EXPECT_NE(query_res.restored_csv.find("30108110101000"), std::string::npos);
    EXPECT_FALSE(query_res.raw_cloud_hex_preview.empty());
    EXPECT_TRUE(std::filesystem::exists(dir.file("bank_state") / "regtech_audit.log"));
}