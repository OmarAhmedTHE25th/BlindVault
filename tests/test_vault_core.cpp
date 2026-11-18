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
    };
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    [[nodiscard]] std::filesystem::path path() const { return path_; }
    [[nodiscard]] std::filesystem::path file(const std::string& name) const { return path_ / name; }
private:
    std::filesystem::path path_;
};

class NonRotatableKmsProvider final : public vault_kms::KeyManagementProvider {
public:
    NonRotatableKmsProvider()
        : master_(vault_crypto::generate_key()) {}

    [[nodiscard]] std::string wrap_dek_hex(const vault_crypto::SecretKey& dek) const override {
        return vault_crypto::wrap_dek_hex(dek, master_);
    }

    [[nodiscard]] vault_crypto::SecretKey unwrap_dek_hex(const std::string& wrapped_hex) const override {
        return vault_crypto::unwrap_dek_hex(wrapped_hex, master_);
    }

    [[nodiscard]] std::string hmac_index_hex(std::string_view body) const override {
        return vault_crypto::hmac_sha256_hex(master_.data(), vault_crypto::SecretKey::size(), body);
    }

    [[nodiscard]] std::string hmac_audit_hex(std::string_view body) const override {
        return vault_crypto::hmac_sha256_hex(master_.data(), vault_crypto::SecretKey::size(), body);
    }

    [[nodiscard]] std::array<uint8_t, 32> derive_tokenizer_pepper() const override {
        return vault_crypto::derive_subkey(master_, "test:pepper:v1").bytes;
    }

    [[nodiscard]] bool can_rotate_master_kek_in_app() const override {
        return false;
    }

    void rotate_master_kek(const vault_crypto::SecretKey&) override {
        rotate_called_ = true;
        throw std::runtime_error("unexpected HSM rotation call");
    }

    [[nodiscard]] std::string backend_description() const override {
        return "Test-NonRotatable-HSM";
    }

    mutable bool rotate_called_ = false;

private:
    vault_crypto::SecretKey master_;
};

// Helper: generates 3 offline officer Ed25519 keypairs and installs ONLY *.pub on the Gateway
void setup_offline_officers(const std::filesystem::path& offline_priv_dir,
                            const std::filesystem::path& gateway_pub_dir) {
    std::filesystem::create_directories(offline_priv_dir);
    std::filesystem::create_directories(gateway_pub_dir);
    for (const std::string& id : {"CBE-Officer-1", "CBE-Officer-2", "CBE-Officer-3"}) {
        vault_index::generate_officer_ed25519_keypair(
            offline_priv_dir / (id + ".priv"),
            gateway_pub_dir  / (id + ".pub"));
    }
}

vault_index::OfficerApproval sign_offline(const std::filesystem::path& offline_priv_dir,
                                          const std::string& officer_id,
                                          const std::string& target_token,
                                          const vault_index::BlobEntry& blob) {
    return vault_index::OfficerApproval{
        officer_id,
        vault_index::sign_blob_release_offline(
            offline_priv_dir / (officer_id + ".priv"),
            officer_id,
            target_token,
            blob.blob_name,
            blob.wrapped_dek_hex)
    };
}

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

// ---------------- Hardened Vault Features (RFC 3394, 64KiB Pad, 2-of-3 Erasure, Ed25519 2-of-3 Quorum) ----------------

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
    const auto cloud_bucket     = dir.file("cloud_bucket");
    const auto state_dir        = dir.file("bank_state");
    const auto offline_priv_dir = dir.file("offline_officers");
    std::filesystem::create_directories(cloud_bucket);

    // Install ONLY officer Ed25519 public keys (*.pub) in bank_state/officers
    setup_offline_officers(offline_priv_dir, state_dir / "officers");
    EXPECT_FALSE(std::filesystem::exists(state_dir / "officers" / "CBE-Officer-1.priv"));

    vault_gateway::GatewayEngine gateway(state_dir, /*quorum_threshold=*/2);

    const auto custom_csv = dir.file("custom_tx.csv");
    {
        std::ofstream out(custom_csv);
        out << "tx_id,timestamp,customer_name,national_id,iban,source_ip,amount_egp,merchant\n";
        out << "TXN1,2026-11-18T02:00:00Z,Ahmed Hassan,30108110101000,EG380019000500000000263181000,41.10.20.30,500.00,Carrefour\n";
        out << "TXN2,2026-11-18T02:01:00Z,Mona El-Sayed,29901010102222,EG380019000500000000263181001,41.10.20.31,900.00,Ahmed-Electronics\n";
    }

    const auto artifact = gateway.prepare_encrypted_offload(custom_csv);
    std::filesystem::copy_file(artifact.encrypted_file_path, cloud_bucket / artifact.blob_name);

    const auto challenge = gateway.prepare_release_challenge("Ahmed Hassan");
    ASSERT_EQ(challenge.candidate_blobs.size(), 1u);
    const auto& target_blob = challenge.candidate_blobs[0];

    // 1. Solo officer Ed25519 signature must be DENIED
    const auto solo_sig = sign_offline(offline_priv_dir, "CBE-Officer-1", challenge.target_token, target_blob);
    const auto denied = gateway.auditor_query("Ahmed Hassan", cloud_bucket, {solo_sig}, "Solo-Auditor");
    EXPECT_FALSE(denied.authorized);

    // 2. Duplicate signature from same officer twice must be DENIED
    const auto dup_denied = gateway.auditor_query("Ahmed Hassan", cloud_bucket, {solo_sig, solo_sig}, "Dup-Auditor");
    EXPECT_FALSE(dup_denied.authorized);

    // 3. Forged / corrupted Ed25519 signature must be DENIED
    auto forged_sig = sign_offline(offline_priv_dir, "CBE-Officer-2", challenge.target_token, target_blob);
    forged_sig.signature_hex[0] = (forged_sig.signature_hex[0] == 'a') ? 'b' : 'a';
    const auto forged_denied = gateway.auditor_query("Ahmed Hassan", cloud_bucket, {solo_sig, forged_sig}, "Forged-Auditor");
    EXPECT_FALSE(forged_denied.authorized);

    // 4. Two distinct valid offline Ed25519 signatures -> AUTHORIZED, returning ONLY TXN1 (NOT TXN2 "Ahmed-Electronics")
    const std::vector<vault_index::OfficerApproval> dual = {
        sign_offline(offline_priv_dir, "CBE-Officer-1", challenge.target_token, target_blob),
        sign_offline(offline_priv_dir, "CBE-Officer-2", challenge.target_token, target_blob)
    };

    const auto by_name = gateway.auditor_query("Ahmed Hassan", cloud_bucket, dual, "Dual-Auditor");
    EXPECT_TRUE(by_name.authorized);
    EXPECT_TRUE(by_name.found);
    EXPECT_NE(by_name.restored_csv.find("TXN1"), std::string::npos);
    EXPECT_EQ(by_name.restored_csv.find("TXN2"), std::string::npos);
    EXPECT_EQ(by_name.restored_csv.find("Ahmed-Electronics"), std::string::npos);

    // 5. Searching directly by TOK_... must work identically
    const auto by_tok = gateway.auditor_query(by_name.matched_token, cloud_bucket, dual, "Dual-Auditor");
    EXPECT_TRUE(by_tok.authorized);
    EXPECT_TRUE(by_tok.found);
    EXPECT_NE(by_tok.restored_csv.find("Ahmed Hassan"), std::string::npos);

    // 6. Audit log hash chain must verify intact
    EXPECT_TRUE(gateway.metadata_index().verify_audit_chain());

    // 7. Tampering with vault_index.tsv must fail HMAC authentication on load
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

TEST(VaultHardening, HsmRotationFailsBeforeBlobOrIndexMutation) {
    TempDir dir;
    const auto state_dir = dir.file("bank_state");
    const auto cloud_bucket = dir.file("cloud_bucket");
    std::filesystem::create_directories(cloud_bucket);

    auto kms = std::make_shared<NonRotatableKmsProvider>();
    vault_gateway::GatewayEngine gateway(state_dir, 2, kms);

    const auto custom_csv = dir.file("hsm_rotation_tx.csv");
    {
        std::ofstream out(custom_csv);
        out << "tx_id,timestamp,customer_name,national_id,iban,source_ip,amount_egp,merchant\n";
        out << "TXNHSM,2026-11-18T12:00:00Z,HSM Customer,30108110101000,EG380019000500000000263181000,41.10.20.30,500.00,HSM-Merchant\n";
    }

    const auto artifact = gateway.prepare_encrypted_offload(custom_csv);
    std::filesystem::copy_file(artifact.encrypted_file_path, cloud_bucket / artifact.blob_name);
    const auto blob_before = vault_crypto::read_bytes_from_file(
        (cloud_bucket / artifact.blob_name).string());
    const auto index_before = vault_crypto::read_bytes_from_file(
        (state_dir / "vault_index.tsv").string());

    EXPECT_THROW(
        gateway.rotate_master_kek(vault_crypto::generate_key(), cloud_bucket),
        std::runtime_error);
    EXPECT_FALSE(kms->rotate_called_);

    const auto blob_after = vault_crypto::read_bytes_from_file(
        (cloud_bucket / artifact.blob_name).string());
    const auto index_after = vault_crypto::read_bytes_from_file(
        (state_dir / "vault_index.tsv").string());
    EXPECT_EQ(blob_before, blob_after);
    EXPECT_EQ(index_before, index_after);
}

TEST(VaultHardening, MasterKekRotationRewrapsAndReauthenticates) {
    TempDir dir;
    const auto state_dir        = dir.file("bank_state");
    const auto cloud_bucket     = dir.file("cloud_bucket");
    const auto offline_priv_dir = dir.file("offline_officers");
    std::filesystem::create_directories(cloud_bucket);
    setup_offline_officers(offline_priv_dir, state_dir / "officers");

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

    const auto challenge = gateway.prepare_release_challenge("Rotation Customer");
    ASSERT_EQ(challenge.candidate_blobs.size(), 1u);
    const std::vector<vault_index::OfficerApproval> dual = {
        sign_offline(offline_priv_dir, "CBE-Officer-1", challenge.target_token, challenge.candidate_blobs[0]),
        sign_offline(offline_priv_dir, "CBE-Officer-2", challenge.target_token, challenge.candidate_blobs[0])
    };
    const auto result = gateway.auditor_query("Rotation Customer", cloud_bucket, dual);
    EXPECT_TRUE(result.authorized);
    EXPECT_TRUE(result.found);
    EXPECT_NE(result.restored_csv.find("Rotation Customer"), std::string::npos);
}
