#include <gtest/gtest.h>
#include <cstring>
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
    [[nodiscard]] std::filesystem::path path() const { return path_; }
    [[nodiscard]] std::filesystem::path file(const std::string& name) const { return path_ / name; }
private:
    std::filesystem::path path_;
};

} // namespace

// ---------------- AES-256-GCM At-Rest Crypto (v2 BVL2 Envelope) ----------------

TEST(VaultCrypto, RoundTripEncryptAndDecrypt) {
    const auto key = vault_crypto::generate_key();
    const std::string secret_csv = "TXN1001,2026-11-17T10:00:00Z,TOK_1234567890abcdef,5000.00,InstaPay\n";

    const auto envelope = vault_crypto::encrypt_envelope(secret_csv, key, /*pad_traffic=*/true);
    ASSERT_GT(envelope.size(), vault_crypto::HEADER_LEN);
    EXPECT_EQ(envelope[0], 'B');
    EXPECT_EQ(envelope[1], 'V');
    EXPECT_EQ(envelope[2], 'L');
    EXPECT_EQ(envelope[3], '2');

    const auto decrypted = vault_crypto::decrypt_envelope(
        envelope.data(), envelope.size(), key, /*unpad_traffic=*/true);
    EXPECT_EQ(decrypted.as_string(), secret_csv);
}

TEST(VaultCrypto, RejectsBlobNameSwapViaAad) {
    const auto key = vault_crypto::generate_key();
    const std::string plaintext = "blob-a-record";
    const auto blob_a = vault_crypto::encrypt_envelope(
        plaintext, key, /*pad_traffic=*/true, "vault_batch_a.enc");
    const auto blob_b = vault_crypto::encrypt_envelope(
        plaintext, key, /*pad_traffic=*/true, "vault_batch_b.enc");

    EXPECT_NO_THROW(vault_crypto::decrypt_envelope(
        blob_a.data(), blob_a.size(), key, true, "vault_batch_a.enc"));
    EXPECT_THROW(vault_crypto::decrypt_envelope(
        blob_a.data(), blob_a.size(), key, true, "vault_batch_b.enc"),
        std::runtime_error);
    EXPECT_THROW(vault_crypto::decrypt_envelope(
        blob_b.data(), blob_b.size(), key, true, "vault_batch_a.enc"),
        std::runtime_error);
}

TEST(VaultCrypto, KeyHexRoundTrip) {
    const auto key = vault_crypto::generate_key();
    const std::string hex = vault_crypto::bytes_to_hex(key.data(), vault_crypto::SecretKey::size());
    EXPECT_EQ(hex.size(), 64u);

    const auto raw = vault_crypto::hex_to_bytes(hex);
    ASSERT_EQ(raw.size(), vault_crypto::KEY_LEN);
    vault_crypto::SecretKey restored;
    std::memcpy(restored.data(), raw.data(), vault_crypto::KEY_LEN);
    EXPECT_EQ(restored, key);
}

TEST(VaultCrypto, DetectsTamperedCiphertextOrWrongKey) {
    const auto key = vault_crypto::generate_key();
    const auto wrong_key = vault_crypto::generate_key();
    auto envelope = vault_crypto::encrypt_envelope("sensitive banking ledger", key, /*pad_traffic=*/true);

    EXPECT_THROW(vault_crypto::decrypt_envelope(envelope.data(), envelope.size(), wrong_key, true), std::runtime_error);

    envelope.back() ^= 0x01;
    EXPECT_THROW(vault_crypto::decrypt_envelope(envelope.data(), envelope.size(), key, true), std::runtime_error);
}

// ---------------- PII & IP Tokenizer ----------------

TEST(Tokenizer, DeterministicTokensAndIpMasking) {
    TempDir dir;
    auto kms = std::make_shared<vault_kms::LocalSoftwareKmsProvider>(dir.file("test.kek"));
    std::array<uint8_t, 32> fixed_pepper{};
    fixed_pepper.fill(0x42);

    vault_token::TokenVault vault(dir.file("tokens.tsv"), kms, fixed_pepper);

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
    auto kms = std::make_shared<vault_kms::LocalSoftwareKmsProvider>(dir.file("test.kek"));
    std::array<uint8_t, 32> fixed_pepper{};
    fixed_pepper.fill(0x11);

    std::string tok;
    {
        vault_token::TokenVault v1(dir.file("tokens.tsv"), kms, fixed_pepper);
        tok = v1.tokenize("Mona El-Sayed");
        v1.flush();
    }
    {
        vault_token::TokenVault v2(dir.file("tokens.tsv"), kms, fixed_pepper);
        EXPECT_EQ(v2.detokenize(tok), "Mona El-Sayed");
    }
}

// ---------------- Hardened Vault Features (RFC 3394, 64KiB Pad, 2-of-3 Erasure, 2-of-3 Quorum) ----------------

TEST(VaultHardening, Rfc3394KeyWrapAnd64KiBTrafficPadding) {
    const auto kek = vault_crypto::generate_key();
    const auto dek = vault_crypto::generate_key();

    const std::string wrapped_hex = vault_crypto::wrap_dek_hex(dek, kek);
    EXPECT_EQ(wrapped_hex.size(), 80u);

    const auto unwrapped = vault_crypto::unwrap_dek_hex(wrapped_hex, kek);
    EXPECT_EQ(unwrapped, dek);

    const auto wrong_kek = vault_crypto::generate_key();
    EXPECT_THROW(vault_crypto::unwrap_dek_hex(wrapped_hex, wrong_kek), std::runtime_error);

    const std::string tiny_csv = "TXN1,2026-11-18T01:00:00Z,TOK_1111222233334444,500.00,Fawry\n";
    const auto env = vault_crypto::encrypt_envelope(tiny_csv, dek, /*pad_traffic=*/true);
    EXPECT_EQ(env.size(), vault_crypto::HEADER_LEN + vault_crypto::BUCKET_ALIGN);

    const auto dec = vault_crypto::decrypt_envelope(env.data(), env.size(), unwrapped, /*unpad_traffic=*/true);
    EXPECT_EQ(dec.as_string(), tiny_csv);
}

TEST(VaultHardening, TwoOfThreeErasureCodingSurvivesCloudNodeLoss) {
    const auto dek = vault_crypto::generate_key();
    const std::string payload = "CRITICAL_CBE_LEDGER_BATCH_2026";
    const auto env = vault_crypto::encrypt_envelope(payload, dek, /*pad_traffic=*/true);

    const auto shards = vault_crypto::erasure_split_2of3(env);
    const auto reconstructed = vault_crypto::erasure_reconstruct_2of3(shards[0], {}, shards[2], env.size());
    EXPECT_EQ(reconstructed, env);

    const auto dec = vault_crypto::decrypt_envelope(reconstructed.data(), reconstructed.size(), dek, /*unpad_traffic=*/true);
    EXPECT_EQ(dec.as_string(), payload);
}

TEST(VaultHardening, EndToEndTokenSearchExactColumnMatchTamperIndexAndChainedAudit) {
    TempDir dir;
    const auto cloud_bucket = dir.file("cloud_bucket");
    const auto state_dir    = dir.file("bank_state");
    std::filesystem::create_directories(cloud_bucket);

    vault_gateway::GatewayEngine gateway(state_dir, /*quorum_threshold=*/2);

    // Create a custom CSV where a merchant is named "Ahmed-Electronics" while the customer is "Mona El-Sayed"
    const auto custom_csv = dir.file("custom_tx.csv");
    {
        std::ofstream out(custom_csv);
        out << "tx_id,timestamp,customer_name,national_id,iban,source_ip,amount_egp,merchant\n";
        out << "TXN1,2026-11-18T02:00:00Z,Ahmed Hassan,30108110101000,EG380019000500000000263181000,41.10.20.30,500.00,Carrefour\n";
        out << "TXN2,2026-11-18T02:01:00Z,Mona El-Sayed,29901010102222,EG380019000500000000263181001,41.10.20.31,900.00,Ahmed-Electronics\n";
    }

    const auto artifact = gateway.prepare_encrypted_offload(custom_csv);
    std::filesystem::copy_file(artifact.encrypted_file_path, cloud_bucket / artifact.blob_name);

    // 1. Solo officer must be DENIED
    const auto solo = gateway.collect_officer_approvals("CBE-Officer-1", "Ahmed Hassan");
    const auto denied = gateway.auditor_query("Ahmed Hassan", cloud_bucket, solo, "Solo-Auditor");
    EXPECT_FALSE(denied.authorized);

    // 2. Searching "Ahmed Hassan" must return ONLY TXN1, NOT TXN2 ("Ahmed-Electronics")
    auto dual = gateway.collect_officer_approvals("CBE-Officer-1", "Ahmed Hassan");
    auto sig2 = gateway.collect_officer_approvals("CBE-Officer-2", "Ahmed Hassan");
    dual.insert(dual.end(), sig2.begin(), sig2.end());

    const auto by_name = gateway.auditor_query("Ahmed Hassan", cloud_bucket, dual, "Dual-Auditor");
    EXPECT_TRUE(by_name.authorized);
    EXPECT_TRUE(by_name.found);
    EXPECT_NE(by_name.restored_csv.find("TXN1"), std::string::npos);
    EXPECT_EQ(by_name.restored_csv.find("TXN2"), std::string::npos);
    EXPECT_EQ(by_name.restored_csv.find("Ahmed-Electronics"), std::string::npos);

    // 3. Searching directly by TOK_... must work identically
    auto tok_approvals = gateway.collect_officer_approvals("CBE-Officer-1", by_name.matched_token);
    auto tok_sig2      = gateway.collect_officer_approvals("CBE-Officer-2", by_name.matched_token);
    tok_approvals.insert(tok_approvals.end(), tok_sig2.begin(), tok_sig2.end());

    const auto by_tok = gateway.auditor_query(by_name.matched_token, cloud_bucket, tok_approvals, "Dual-Auditor");
    EXPECT_TRUE(by_tok.authorized);
    EXPECT_TRUE(by_tok.found);
    EXPECT_NE(by_tok.restored_csv.find("Ahmed Hassan"), std::string::npos);

    // 4. Audit log hash chain must verify intact
    EXPECT_TRUE(gateway.metadata_index().verify_audit_chain());

    // 5. Tampering with vault_index.tsv must fail HMAC authentication on load
    {
        std::ofstream tamper(state_dir / "vault_index.tsv", std::ios::app);
        tamper << "MAP\tTOK_deadbeefcafebabe\t" << artifact.blob_name << "\n";
    }
    EXPECT_THROW(vault_gateway::GatewayEngine(state_dir, 2), std::runtime_error);
}

TEST(Tokenizer, PersistsAcrossReloadsEncryptedAtRest) {
    TempDir dir;
    auto kms = std::make_shared<vault_kms::LocalSoftwareKmsProvider>(dir.file("test.kek"));
    std::array<uint8_t, 32> fixed_pepper{};
    fixed_pepper.fill(0x11);

    const auto token_file = dir.file("tokens.enc");
    std::string tok;
    {
        vault_token::TokenVault v1(token_file, kms, fixed_pepper);
        tok = v1.tokenize("Mona El-Sayed");
        v1.flush();
    }

    // Verify the file on disk is BVTK-encrypted and contains zero plaintext PII
    const auto raw_disk = vault_crypto::read_bytes_from_file(token_file.string());
    ASSERT_GT(raw_disk.size(), 84u);
    EXPECT_EQ(raw_disk[0], 'B');
    EXPECT_EQ(raw_disk[1], 'V');
    EXPECT_EQ(raw_disk[2], 'T');
    EXPECT_EQ(raw_disk[3], 'K');
    const std::string disk_str(reinterpret_cast<const char*>(raw_disk.data()), raw_disk.size());
    EXPECT_EQ(disk_str.find("Mona El-Sayed"), std::string::npos);

    {
        vault_token::TokenVault v2(token_file, kms, fixed_pepper);
        EXPECT_EQ(v2.detokenize(tok), "Mona El-Sayed");
    }
}

TEST(Tokenizer, DerivedPepperPersistsAcrossKmsInstances) {
    TempDir dir;
    const auto kek_path = dir.file("test.kek");
    const auto token_file = dir.file("tokens.tsv");
    std::string tok;

    {
        auto kms = std::make_shared<vault_kms::LocalSoftwareKmsProvider>(kek_path);
        vault_token::TokenVault v1(token_file, kms);
        tok = v1.tokenize("Cross-Process Customer");
        v1.flush();
    }

    {
        auto kms = std::make_shared<vault_kms::LocalSoftwareKmsProvider>(kek_path);
        vault_token::TokenVault v2(token_file, kms);
        EXPECT_EQ(v2.detokenize(tok), "Cross-Process Customer");
    }
}

TEST(VaultHardening, MasterKekRotationRewrapsAndReauthenticates) {
    TempDir dir;
    const auto state_dir = dir.file("bank_state");
    const auto cloud_bucket = dir.file("cloud_bucket");
    std::filesystem::create_directories(cloud_bucket);

    vault_gateway::GatewayEngine gateway(state_dir, 2);
    const auto custom_csv = dir.file("rotation_tx.csv");
    {
        std::ofstream out(custom_csv);
        out << "tx_id,timestamp,customer_name,national_id,iban,source_ip,amount_egp,merchant\n";
        out << "TXNROT,2026-11-18T12:00:00Z,Rotation Customer,30108110101000,EG380019000500000000263181000,41.10.20.30,500.00,Safe-Merchant\n";
    }

    const auto artifact = gateway.prepare_encrypted_offload(custom_csv);
    std::filesystem::copy_file(artifact.encrypted_file_path, cloud_bucket / artifact.blob_name);
    EXPECT_TRUE(gateway.metadata_index().verify_audit_chain());

    gateway.rotate_master_kek(vault_crypto::generate_key(), cloud_bucket);

    EXPECT_TRUE(gateway.metadata_index().verify_audit_chain());
    const auto blob_entries = gateway.metadata_index().blob_entries();
    ASSERT_EQ(blob_entries.size(), 1u);
    EXPECT_FALSE(blob_entries[0].wrapped_dek_hex.empty());

    const auto approvals = gateway.collect_officer_approvals("CBE-Officer-1", "Rotation Customer");
    auto second = gateway.collect_officer_approvals("CBE-Officer-2", "Rotation Customer");
    std::vector<std::pair<std::string, std::string>> dual = approvals;
    dual.insert(dual.end(), second.begin(), second.end());
    const auto result = gateway.auditor_query("Rotation Customer", cloud_bucket, dual);
    EXPECT_TRUE(result.authorized);
    EXPECT_TRUE(result.found);
    EXPECT_NE(result.restored_csv.find("Rotation Customer"), std::string::npos);
}
