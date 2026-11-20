#include <gtest/gtest.h>
#include <array>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <openssl/evp.h>
#include "at_rest_crypto.hpp"
#include "control_client.hpp"
#include "s3_shard_backend.hpp"
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
                                          const vault_index::BlobEntry& blob,
                                          const std::string& challenge_nonce_hex,
                                          const std::string& expires_utc) {
    return vault_index::OfficerApproval{
        officer_id,
        vault_index::sign_blob_release_offline(
            offline_priv_dir / (officer_id + ".priv"),
            officer_id,
            target_token,
            blob.blob_name,
            blob.wrapped_dek_hex,
            challenge_nonce_hex,
            expires_utc)
    };
}

class ScopedSoftwareKmsMode {
public:
    ScopedSoftwareKmsMode() {
#ifndef _WIN32
        if (const char* v = std::getenv("BLINDVAULT_PKCS11_MODULE"); v && *v) {
            saved_ = v;
            ::unsetenv("BLINDVAULT_PKCS11_MODULE");
        }
#endif
    }
    ~ScopedSoftwareKmsMode() {
#ifndef _WIN32
        if (!saved_.empty()) {
            ::setenv("BLINDVAULT_PKCS11_MODULE", saved_.c_str(), 1);
        }
#endif
    }

private:
    std::string saved_;
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
    const auto solo_sig = sign_offline(
        offline_priv_dir, "CBE-Officer-1", challenge.target_token, target_blob,
        challenge.challenge_nonce_hex, challenge.expires_utc);
    const auto denied = gateway.auditor_query(
        "Ahmed Hassan", cloud_bucket, {solo_sig},
        challenge.challenge_nonce_hex, challenge.expires_utc, "Solo-Auditor");
    EXPECT_FALSE(denied.authorized);

    // 2. Duplicate signature from same officer twice must be DENIED
    const auto dup_denied = gateway.auditor_query(
        "Ahmed Hassan", cloud_bucket, {solo_sig, solo_sig},
        challenge.challenge_nonce_hex, challenge.expires_utc, "Dup-Auditor");
    EXPECT_FALSE(dup_denied.authorized);

    // 3. Forged / corrupted Ed25519 signature must be DENIED
    auto forged_sig = sign_offline(
        offline_priv_dir, "CBE-Officer-2", challenge.target_token, target_blob,
        challenge.challenge_nonce_hex, challenge.expires_utc);
    forged_sig.signature_hex[0] = (forged_sig.signature_hex[0] == 'a') ? 'b' : 'a';
    const auto forged_denied = gateway.auditor_query(
        "Ahmed Hassan", cloud_bucket, {solo_sig, forged_sig},
        challenge.challenge_nonce_hex, challenge.expires_utc, "Forged-Auditor");
    EXPECT_FALSE(forged_denied.authorized);

    // 4. Two distinct valid offline Ed25519 signatures -> AUTHORIZED, returning ONLY TXN1 (NOT TXN2 "Ahmed-Electronics")
    const std::vector<vault_index::OfficerApproval> dual = {
        sign_offline(offline_priv_dir, "CBE-Officer-1", challenge.target_token, target_blob,
                     challenge.challenge_nonce_hex, challenge.expires_utc),
        sign_offline(offline_priv_dir, "CBE-Officer-2", challenge.target_token, target_blob,
                     challenge.challenge_nonce_hex, challenge.expires_utc)
    };

    const auto by_name = gateway.auditor_query(
        "Ahmed Hassan", cloud_bucket, dual,
        challenge.challenge_nonce_hex, challenge.expires_utc, "Dual-Auditor");
    EXPECT_TRUE(by_name.authorized);
    EXPECT_TRUE(by_name.found);
    EXPECT_NE(by_name.restored_csv.find("TXN1"), std::string::npos);
    EXPECT_EQ(by_name.restored_csv.find("TXN2"), std::string::npos);
    EXPECT_EQ(by_name.restored_csv.find("Ahmed-Electronics"), std::string::npos);

    // 4b. Replaying consumed challenge nonce must be DENIED
    const auto replay_denied = gateway.auditor_query(
        "Ahmed Hassan", cloud_bucket, dual,
        challenge.challenge_nonce_hex, challenge.expires_utc, "Replay-Auditor");
    EXPECT_FALSE(replay_denied.authorized);

    // 5. Searching directly by TOK_... with a freshly issued challenge must work identically
    const auto challenge2 = gateway.prepare_release_challenge(by_name.matched_token);
    ASSERT_EQ(challenge2.candidate_blobs.size(), 1u);
    const std::vector<vault_index::OfficerApproval> dual2 = {
        sign_offline(offline_priv_dir, "CBE-Officer-1", challenge2.target_token, challenge2.candidate_blobs[0],
                     challenge2.challenge_nonce_hex, challenge2.expires_utc),
        sign_offline(offline_priv_dir, "CBE-Officer-2", challenge2.target_token, challenge2.candidate_blobs[0],
                     challenge2.challenge_nonce_hex, challenge2.expires_utc)
    };
    const auto by_tok = gateway.auditor_query(
        by_name.matched_token, cloud_bucket, dual2,
        challenge2.challenge_nonce_hex, challenge2.expires_utc, "Dual-Auditor");
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
    ScopedSoftwareKmsMode sw_kms_guard;
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
        sign_offline(offline_priv_dir, "CBE-Officer-1", challenge.target_token, challenge.candidate_blobs[0],
                     challenge.challenge_nonce_hex, challenge.expires_utc),
        sign_offline(offline_priv_dir, "CBE-Officer-2", challenge.target_token, challenge.candidate_blobs[0],
                     challenge.challenge_nonce_hex, challenge.expires_utc)
    };
    const auto result = gateway.auditor_query(
        "Rotation Customer", cloud_bucket, dual,
        challenge.challenge_nonce_hex, challenge.expires_utc);
    EXPECT_TRUE(result.authorized);
    EXPECT_TRUE(result.found);
    EXPECT_NE(result.restored_csv.find("Rotation Customer"), std::string::npos);
}

namespace {

std::string b64_encode_test(const uint8_t* data, std::size_t len) {
    static constexpr char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t i = 0; i < len; i += 3) {
        const uint32_t b0 = data[i];
        const bool has1 = (i + 1) < len;
        const bool has2 = (i + 2) < len;
        const uint32_t b1 = has1 ? data[i + 1] : 0;
        const uint32_t b2 = has2 ? data[i + 2] : 0;
        const uint32_t triple = (b0 << 16) | (b1 << 8) | b2;
        out.push_back(kTable[(triple >> 18) & 0x3F]);
        out.push_back(kTable[(triple >> 12) & 0x3F]);
        out.push_back(has1 ? kTable[(triple >> 6) & 0x3F] : '=');
        out.push_back(has2 ? kTable[triple & 0x3F] : '=');
    }
    return out;
}

class MockS3Server {
public:
    MockS3Server()
        : acceptor_(ioc_, boost::asio::ip::tcp::endpoint(
                              boost::asio::ip::make_address("127.0.0.1"), 0)),
          port_(acceptor_.local_endpoint().port()) {
        start_accept();
        worker_ = std::thread([this]() { ioc_.run(); });
    }

    ~MockS3Server() { stop(); }

    uint16_t port() const noexcept { return port_; }

    void stop() {
        if (stopped_.exchange(true)) return;
        boost::asio::post(ioc_, [this]() {
            boost::system::error_code ec;
            acceptor_.cancel(ec);
            acceptor_.close(ec);
        });
        if (worker_.joinable()) worker_.join();
    }

    std::size_t object_count() const {
        std::lock_guard lock(mu_);
        return objects_.size();
    }

    std::string last_auth_header() const {
        std::lock_guard lock(mu_);
        return last_auth_;
    }

private:
    void start_accept() {
        if (stopped_.load()) return;
        auto sock = std::make_shared<boost::asio::ip::tcp::socket>(ioc_);
        acceptor_.async_accept(*sock, [this, sock](const boost::system::error_code& ec) {
            if (ec || stopped_.load()) return;
            handle_connection(*sock);
            start_accept();
        });
    }

    void handle_connection(boost::asio::ip::tcp::socket& sock) {
        namespace beast = boost::beast;
        namespace http = beast::http;
        try {
            boost::system::error_code ec;
            beast::flat_buffer buf;
            http::request<http::vector_body<uint8_t>> req;
            http::read(sock, buf, req, ec);
            if (ec) return;

            {
                std::lock_guard lock(mu_);
                if (auto it = req.find(http::field::authorization); it != req.end()) {
                    last_auth_ = std::string(it->value());
                }
            }

            http::response<http::vector_body<uint8_t>> res;
            res.version(req.version());
            res.keep_alive(false);

            const std::string target(req.target());
            const std::string auth = req.count(http::field::authorization)
                ? std::string(req[http::field::authorization]) : "";
            if (auth.rfind("AWS4-HMAC-SHA256 ", 0) != 0 ||
                !req.count("x-amz-date") || !req.count("x-amz-content-sha256")) {
                res.result(http::status::forbidden);
            } else if (req.method() == http::verb::put) {
                std::lock_guard lock(mu_);
                objects_[target] = std::move(req.body());
                res.result(http::status::ok);
            } else if (req.method() == http::verb::get) {
                std::lock_guard lock(mu_);
                auto it = objects_.find(target);
                if (it == objects_.end()) {
                    res.result(http::status::not_found);
                } else {
                    res.result(http::status::ok);
                    res.body() = it->second;
                }
            } else if (req.method() == http::verb::head) {
                std::lock_guard lock(mu_);
                res.result(objects_.contains(target) ? http::status::ok : http::status::not_found);
            } else {
                res.result(http::status::method_not_allowed);
            }
            res.prepare_payload();
            http::write(sock, res, ec);
            sock.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        } catch (...) {
        }
    }

    boost::asio::io_context ioc_;
    boost::asio::ip::tcp::acceptor acceptor_;
    uint16_t port_ = 0;
    std::atomic<bool> stopped_{false};
    std::thread worker_;
    mutable std::mutex mu_;
    std::map<std::string, std::vector<uint8_t>> objects_;
    std::string last_auth_;
};

} // namespace

TEST(QuorumGate, ReplayAndExpiryAndTargetBinding) {
    TempDir dir;
    const auto cloud_bucket = dir.file("cloud");
    const auto state_dir = dir.file("state");
    const auto priv_dir = dir.file("priv");
    std::filesystem::create_directories(cloud_bucket);
    setup_offline_officers(priv_dir, state_dir / "officers");

    const auto csv = dir.file("tx.csv");
    {
        std::ofstream out(csv);
        out << "tx_id,timestamp,customer_name,national_id,iban,source_ip,amount_egp,merchant\n"
            << "TXN1,2026-11-20T10:00:00Z,Ahmed Hassan,30108110101000,EG380019000500000000263181000,41.10.20.30,500.00,Carrefour\n";
    }

    std::string consumed_nonce;
    std::string consumed_expires;
    std::vector<vault_index::OfficerApproval> consumed_approvals;

    {
        vault_gateway::GatewayEngine gw(state_dir, 2);
        const auto art = gw.prepare_encrypted_offload(csv);
        std::filesystem::copy_file(art.encrypted_file_path, cloud_bucket / art.blob_name);

        const auto chal = gw.prepare_release_challenge("Ahmed Hassan");
        ASSERT_EQ(chal.challenge_nonce_hex.size(), 32u);
        ASSERT_EQ(chal.expires_utc.size(), 20u);
        ASSERT_EQ(chal.candidate_blobs.size(), 1u);

        consumed_nonce = chal.challenge_nonce_hex;
        consumed_expires = chal.expires_utc;
        consumed_approvals = {
            sign_offline(priv_dir, "CBE-Officer-1", chal.target_token, chal.candidate_blobs[0],
                         chal.challenge_nonce_hex, chal.expires_utc),
            sign_offline(priv_dir, "CBE-Officer-2", chal.target_token, chal.candidate_blobs[0],
                         chal.challenge_nonce_hex, chal.expires_utc)
        };

        // Binding mismatch: wrong target token with valid nonce must fail
        const auto wrong_target = gw.auditor_query(
            "Mona El-Sayed", cloud_bucket, consumed_approvals,
            consumed_nonce, consumed_expires, "Aud");
        EXPECT_FALSE(wrong_target.authorized);

        // First valid query succeeds and consumes nonce
        const auto ok = gw.auditor_query(
            "Ahmed Hassan", cloud_bucket, consumed_approvals,
            consumed_nonce, consumed_expires, "Aud");
        EXPECT_TRUE(ok.authorized);
        EXPECT_TRUE(ok.found);

        // Immediate replay fails
        const auto replay = gw.auditor_query(
            "Ahmed Hassan", cloud_bucket, consumed_approvals,
            consumed_nonce, consumed_expires, "Aud");
        EXPECT_FALSE(replay.authorized);

        // Expired TTL (-10s) must fail even with valid signatures
        const auto exp_chal = gw.prepare_release_challenge("Ahmed Hassan", -10);
        const std::vector<vault_index::OfficerApproval> exp_approvals = {
            sign_offline(priv_dir, "CBE-Officer-1", exp_chal.target_token, exp_chal.candidate_blobs[0],
                         exp_chal.challenge_nonce_hex, exp_chal.expires_utc),
            sign_offline(priv_dir, "CBE-Officer-2", exp_chal.target_token, exp_chal.candidate_blobs[0],
                         exp_chal.challenge_nonce_hex, exp_chal.expires_utc)
        };
        const auto expired_res = gw.auditor_query(
            "Ahmed Hassan", cloud_bucket, exp_approvals,
            exp_chal.challenge_nonce_hex, exp_chal.expires_utc, "Aud");
        EXPECT_FALSE(expired_res.authorized);
    }

    // Reload GatewayEngine from disk: consumed nonce must still be rejected
    vault_gateway::GatewayEngine reloaded(state_dir, 2);
    const auto persisted_replay = reloaded.auditor_query(
        "Ahmed Hassan", cloud_bucket, consumed_approvals,
        consumed_nonce, consumed_expires, "Aud");
    EXPECT_FALSE(persisted_replay.authorized);
}

TEST(VaultCrypto, Bvl3StreamingAndAutoLegacyBvl2Decrypt) {
    const auto dek = vault_crypto::generate_key();
    std::string big_payload;
    big_payload.reserve(150 * 1024);
    for (int i = 0; i < 3000; ++i) {
        big_payload += "ROW_" + std::to_string(i) + ",TOK_deadbeefcafebabe,5000.00,Carrefour-Maadi\n";
    }

    std::stringstream encrypted(std::ios::in | std::ios::out | std::ios::binary);
    std::size_t total_written = 0;
    {
        vault_crypto::Bvl3EncryptingStreamBuf sbuf(encrypted, dek, "stream_test.enc");
        std::ostream out(&sbuf);
        out.write(big_payload.data(), static_cast<std::streamsize>(big_payload.size()));
        out.flush();
        total_written = sbuf.finalize();
    }
    const std::string ct_str = encrypted.str();
    ASSERT_EQ(ct_str.size(), total_written);
    ASSERT_GE(ct_str.size(), vault_crypto::BVL3_HEADER_LEN + 3 * vault_crypto::BVL3_FRAME_BYTES);
    EXPECT_EQ(ct_str.substr(0, 4), "BVL3");

    std::string restored;
    encrypted.clear();
    encrypted.seekg(0);
    vault_crypto::decrypt_stream_auto(
        encrypted, total_written, dek, "stream_test.enc",
        [&](std::string_view chunk) { restored.append(chunk); });
    EXPECT_EQ(restored, big_payload);

    // Corrupted ciphertext byte inside frame 1 must fail GCM authentication
    std::string tampered = ct_str;
    tampered[vault_crypto::BVL3_HEADER_LEN + vault_crypto::BVL3_FRAME_BYTES + 100] ^= 0x42;
    std::istringstream bad_in(tampered, std::ios::binary);
    std::string sink;
    EXPECT_THROW(
        vault_crypto::decrypt_stream_auto(
            bad_in, tampered.size(), dek, "stream_test.enc",
            [&](std::string_view chunk) { sink.append(chunk); }),
        std::runtime_error);

    // Frame swap attack (swap frame 0 and frame 1) must fail AAD / counter check
    std::string swapped = ct_str;
    std::vector<char> tmp_frame(vault_crypto::BVL3_FRAME_BYTES);
    const std::size_t f0 = vault_crypto::BVL3_HEADER_LEN;
    const std::size_t f1 = vault_crypto::BVL3_HEADER_LEN + vault_crypto::BVL3_FRAME_BYTES;
    std::memcpy(tmp_frame.data(), swapped.data() + f0, vault_crypto::BVL3_FRAME_BYTES);
    std::memcpy(swapped.data() + f0, swapped.data() + f1, vault_crypto::BVL3_FRAME_BYTES);
    std::memcpy(swapped.data() + f1, tmp_frame.data(), vault_crypto::BVL3_FRAME_BYTES);
    std::istringstream swap_in(swapped, std::ios::binary);
    EXPECT_THROW(
        vault_crypto::decrypt_stream_auto(
            swap_in, swapped.size(), dek, "stream_test.enc",
            [&](std::string_view chunk) { sink.append(chunk); }),
        std::runtime_error);

    // Legacy BVL2 blob auto-detection
    const std::string small = "TXN9,2026-01-01T00:00:00Z,TOK_1111222233334444,10.00,Fawry\n";
    const auto bvl2_bytes = vault_crypto::encrypt_envelope(small, dek, true, "legacy.enc");
    std::string bvl2_str(reinterpret_cast<const char*>(bvl2_bytes.data()), bvl2_bytes.size());
    std::istringstream bvl2_in(bvl2_str, std::ios::binary);
    std::string bvl2_restored;
    vault_crypto::decrypt_stream_auto(
        bvl2_in, bvl2_bytes.size(), dek, "legacy.enc",
        [&](std::string_view chunk) { bvl2_restored.append(chunk); });
    EXPECT_EQ(bvl2_restored, small);
}

TEST(Tokenizer, StreamingParityWithBatchAndTokenSet) {
    TempDir dir;
    auto kms = std::make_shared<vault_kms::LocalSoftwareKmsProvider>(dir.file("k.kek"));
    vault_token::TokenVault vault(dir.file("tokens.enc"), kms);

    const std::string raw_csv =
        "tx_id,timestamp,customer_name,national_id,iban,source_ip,amount_egp,merchant\n"
        "TX1,2026-11-20T01:00:00Z,\"Ahmed, Hassan\",30108110101000,EG380019000500000000263181000,41.10.20.30,100.00,Carrefour\n"
        "TX2,2026-11-20T01:05:00Z,Mona El-Sayed,29901010102222,EG380019000500000000263181001,192.168.1.5,250.00,Fawry\n";

    std::istringstream in(raw_csv);
    std::ostringstream sanitized_stream;
    vault_token::SanitizeStats stream_stats{};
    std::unordered_set<std::string> extracted_tokens;
    vault.sanitize_csv_stream(in, sanitized_stream, &stream_stats, &extracted_tokens);

    EXPECT_EQ(stream_stats.records_processed, 2u);
    EXPECT_EQ(extracted_tokens.size(), 6u);

    const std::string batch_out = vault.sanitize_csv_batch(raw_csv);
    EXPECT_EQ(sanitized_stream.str(), batch_out);

    std::istringstream rehy_in(sanitized_stream.str());
    std::ostringstream rehy_out;
    vault.rehydrate_csv_stream(rehy_in, rehy_out);
    EXPECT_NE(rehy_out.str().find("\"Ahmed, Hassan\""), std::string::npos);
    EXPECT_NE(rehy_out.str().find("Mona El-Sayed"), std::string::npos);
}

TEST(VaultHardening, AutomaticTwoOfThreeErasureShardRecovery) {
    TempDir dir;
    const auto cloud_bucket = dir.file("cloud");
    const auto state_dir = dir.file("state");
    const auto priv_dir = dir.file("priv");
    std::filesystem::create_directories(cloud_bucket);
    setup_offline_officers(priv_dir, state_dir / "officers");

    const auto csv = dir.file("tx.csv");
    {
        std::ofstream out(csv);
        out << "tx_id,timestamp,customer_name,national_id,iban,source_ip,amount_egp,merchant\n"
            << "TXN_REC,2026-11-20T12:00:00Z,Ahmed Hassan,30108110101000,EG380019000500000000263181000,41.10.20.30,777.00,InstaPay\n";
    }

    vault_gateway::GatewayEngine gw(state_dir, 2);
    const auto art = gw.prepare_encrypted_offload(csv);

    // Case A: Primary missing completely from cloud_bucket -> recovers from erasure shards
    {
        const auto c1 = gw.prepare_release_challenge("Ahmed Hassan");
        ASSERT_EQ(c1.candidate_blobs.size(), 1u);
        const std::vector<vault_index::OfficerApproval> ap1 = {
            sign_offline(priv_dir, "CBE-Officer-1", c1.target_token, c1.candidate_blobs[0],
                         c1.challenge_nonce_hex, c1.expires_utc),
            sign_offline(priv_dir, "CBE-Officer-2", c1.target_token, c1.candidate_blobs[0],
                         c1.challenge_nonce_hex, c1.expires_utc)
        };
        const auto r1 = gw.auditor_query(
            "Ahmed Hassan", cloud_bucket, ap1, c1.challenge_nonce_hex, c1.expires_utc, "Rec-Aud-1");
        EXPECT_TRUE(r1.authorized);
        EXPECT_TRUE(r1.found);
        EXPECT_TRUE(r1.recovered_from_shards);
        EXPECT_NE(r1.restored_csv.find("TXN_REC"), std::string::npos);
    }

    // Case B: Corrupted primary in cloud_bucket + deleted shard 2 -> recovers from shards 0 & 1
    {
        const auto cloud_blob = cloud_bucket / art.blob_name;
        std::filesystem::copy_file(art.encrypted_file_path, cloud_blob);
        auto corrupted = vault_crypto::read_bytes_from_file(cloud_blob.string());
        corrupted[corrupted.size() - 10] ^= 0xFF;
        vault_crypto::write_bytes_to_file(cloud_blob.string(), corrupted);

        std::filesystem::remove(state_dir / "erasure_shards" / (art.blob_name + ".shard2"));

        const auto c2 = gw.prepare_release_challenge("Ahmed Hassan");
        const std::vector<vault_index::OfficerApproval> ap2 = {
            sign_offline(priv_dir, "CBE-Officer-1", c2.target_token, c2.candidate_blobs[0],
                         c2.challenge_nonce_hex, c2.expires_utc),
            sign_offline(priv_dir, "CBE-Officer-3", c2.target_token, c2.candidate_blobs[0],
                         c2.challenge_nonce_hex, c2.expires_utc)
        };
        const auto r2 = gw.auditor_query(
            "Ahmed Hassan", cloud_bucket, ap2, c2.challenge_nonce_hex, c2.expires_utc, "Rec-Aud-2");
        EXPECT_TRUE(r2.authorized);
        EXPECT_TRUE(r2.found);
        EXPECT_TRUE(r2.recovered_from_shards);
        EXPECT_NE(r2.restored_csv.find("Ahmed Hassan"), std::string::npos);
    }

    EXPECT_TRUE(gw.metadata_index().verify_audit_chain());
    std::ifstream log_in(state_dir / "regtech_audit.log");
    const std::string log_str((std::istreambuf_iterator<char>(log_in)), std::istreambuf_iterator<char>());
    EXPECT_NE(log_str.find("SHARD_RECOVERY"), std::string::npos);
}

TEST(VaultHardening, CrashSafeKekRotationRecoveryOnRestart) {
    ScopedSoftwareKmsMode sw_kms_guard;
    TempDir dir;
    const auto state_dir = dir.file("state");
    const auto cloud_dir = dir.file("cloud");
    const auto priv_dir = dir.file("priv");
    std::filesystem::create_directories(cloud_dir);
    setup_offline_officers(priv_dir, state_dir / "officers");

    const auto csv = dir.file("tx.csv");
    {
        std::ofstream out(csv);
        out << "tx_id,timestamp,customer_name,national_id,iban,source_ip,amount_egp,merchant\n"
            << "TXN_SAFE,2026-11-20T13:00:00Z,Salma Ibrahim,30108110101000,EG380019000500000000263181000,41.10.20.30,900.00,Amazon\n";
    }

    std::string blob_name;
    {
        vault_gateway::GatewayEngine gw(state_dir, 2);
        const auto art = gw.prepare_encrypted_offload(csv);
        blob_name = art.blob_name;
        std::filesystem::copy_file(art.encrypted_file_path, cloud_dir / blob_name);
    }

    // Simulate crash mid-rotation: stage backup files + journal = IN_PROGRESS, then corrupt live files
    const auto backup_dir = state_dir / ".rotation_backup";
    std::filesystem::create_directories(backup_dir);
    std::filesystem::copy_file(state_dir / "hsm_master.kek", backup_dir / "hsm_master.kek");
    std::filesystem::copy_file(state_dir / "vault_tokens.enc", backup_dir / "vault_tokens.enc");
    std::filesystem::copy_file(state_dir / "vault_index.tsv", backup_dir / "vault_index.tsv");
    std::filesystem::copy_file(state_dir / "regtech_audit.log", backup_dir / "regtech_audit.log");
    vault_crypto::write_secret_file_0600(state_dir / "rotation.journal", "IN_PROGRESS\n");

    vault_crypto::write_secret_file_0600(state_dir / "vault_index.tsv", "CORRUPTED_MID_ROTATION\n");
    vault_crypto::write_secret_file_0600(state_dir / "hsm_master.kek", "CORRUPTED_KEK\n");

    // Constructing GatewayEngine must automatically roll back from .rotation_backup
    vault_gateway::GatewayEngine recovered(state_dir, 2);
    EXPECT_FALSE(std::filesystem::exists(state_dir / "rotation.journal"));
    EXPECT_FALSE(std::filesystem::exists(backup_dir));
    EXPECT_TRUE(recovered.metadata_index().verify_audit_chain());

    const auto chal = recovered.prepare_release_challenge("Salma Ibrahim");
    ASSERT_EQ(chal.candidate_blobs.size(), 1u);
    const std::vector<vault_index::OfficerApproval> ap = {
        sign_offline(priv_dir, "CBE-Officer-1", chal.target_token, chal.candidate_blobs[0],
                     chal.challenge_nonce_hex, chal.expires_utc),
        sign_offline(priv_dir, "CBE-Officer-2", chal.target_token, chal.candidate_blobs[0],
                     chal.challenge_nonce_hex, chal.expires_utc)
    };
    const auto q = recovered.auditor_query(
        "Salma Ibrahim", cloud_dir, ap, chal.challenge_nonce_hex, chal.expires_utc, "Crash-Test");
    EXPECT_TRUE(q.authorized);
    EXPECT_TRUE(q.found);
    EXPECT_NE(q.restored_csv.find("TXN_SAFE"), std::string::npos);
}

TEST(S3ShardBackend, ParseUrlSigV4AndMockMultiBucketRecovery) {
    const auto parsed = vault_gateway::parse_s3_endpoint_url(
        "https://AKIATEST:SECRETTEST@s3.eu-central-1.amazonaws.com:8443/blindvault-b0/prod/shards");
    EXPECT_TRUE(parsed.use_tls);
    EXPECT_EQ(parsed.host, "s3.eu-central-1.amazonaws.com");
    EXPECT_EQ(parsed.port, "8443");
    EXPECT_EQ(parsed.bucket, "blindvault-b0");
    EXPECT_EQ(parsed.key_prefix, "prod/shards");
    EXPECT_EQ(parsed.access_key, "AKIATEST");
    EXPECT_EQ(parsed.secret_key, "SECRETTEST");

    vault_gateway::S3BucketConfig sig_cfg;
    sig_cfg.use_tls = false;
    sig_cfg.host = "127.0.0.1";
    sig_cfg.port = "9000";
    sig_cfg.bucket = "shard0";
    sig_cfg.region = "us-east-1";
    sig_cfg.access_key = "AKIAEXAMPLE";
    sig_cfg.secret_key = "SECRETEXAMPLE";

    const auto hdr1 = vault_gateway::sign_aws_v4("PUT", sig_cfg, "blob.enc.shard0", {1, 2, 3}, "20261120T120000Z");
    const auto hdr2 = vault_gateway::sign_aws_v4("PUT", sig_cfg, "blob.enc.shard0", {1, 2, 3}, "20261120T120000Z");
    EXPECT_EQ(hdr1.authorization, hdr2.authorization);
    EXPECT_NE(hdr1.authorization.find("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20261120/us-east-1/s3/aws4_request"),
              std::string::npos);
    EXPECT_EQ(hdr1.host_header, "127.0.0.1:9000");

    // Embedded 3-bucket mock HTTP S3 cluster
    MockS3Server s0, s1, s2;
    auto make_cfg = [](uint16_t port, const std::string& bucket) {
        vault_gateway::S3BucketConfig c;
        c.use_tls = false;
        c.host = "127.0.0.1";
        c.port = std::to_string(port);
        c.bucket = bucket;
        c.region = "us-east-1";
        c.access_key = "minioadmin";
        c.secret_key = "minioadmin";
        c.timeout_ms = 2000;
        return c;
    };

    auto backend = std::make_shared<vault_gateway::S3MultiBucketShardBackend>(
        std::array<vault_gateway::S3BucketConfig, 3>{
            make_cfg(s0.port(), "blindvault-shard0"),
            make_cfg(s1.port(), "blindvault-shard1"),
            make_cfg(s2.port(), "blindvault-shard2")
        });

    TempDir dir;
    const auto state_dir = dir.file("state");
    const auto empty_cloud = dir.file("empty_cloud");
    const auto priv_dir = dir.file("priv");
    std::filesystem::create_directories(empty_cloud);
    setup_offline_officers(priv_dir, state_dir / "officers");

    const auto csv = dir.file("s3_tx.csv");
    {
        std::ofstream out(csv);
        out << "tx_id,timestamp,customer_name,national_id,iban,source_ip,amount_egp,merchant\n"
            << "TXN_S3,2026-11-20T14:00:00Z,Mostafa Adel,30108110101000,EG380019000500000000263181000,41.10.20.30,1200.00,Talabat\n";
    }

    vault_gateway::GatewayEngine gw(state_dir, 2, nullptr, backend);
    const auto art = gw.prepare_encrypted_offload(csv);

    EXPECT_EQ(s0.object_count(), 1u);
    EXPECT_EQ(s1.object_count(), 1u);
    EXPECT_EQ(s2.object_count(), 1u);
    EXPECT_TRUE(backend->head_shard(art.blob_name, 1));
    EXPECT_EQ(s0.last_auth_header().rfind("AWS4-HMAC-SHA256 ", 0), 0u);

    // Outage: take bucket 0 offline and query empty cloud dir -> 2-of-3 recovery from buckets 1 & 2
    s0.stop();

    const auto chal = gw.prepare_release_challenge("Mostafa Adel");
    ASSERT_EQ(chal.candidate_blobs.size(), 1u);
    const std::vector<vault_index::OfficerApproval> ap = {
        sign_offline(priv_dir, "CBE-Officer-1", chal.target_token, chal.candidate_blobs[0],
                     chal.challenge_nonce_hex, chal.expires_utc),
        sign_offline(priv_dir, "CBE-Officer-2", chal.target_token, chal.candidate_blobs[0],
                     chal.challenge_nonce_hex, chal.expires_utc)
    };
    const auto res = gw.auditor_query(
        "Mostafa Adel", empty_cloud, ap, chal.challenge_nonce_hex, chal.expires_utc, "S3-Aud");
    EXPECT_TRUE(res.authorized);
    EXPECT_TRUE(res.found);
    EXPECT_TRUE(res.recovered_from_shards);
    EXPECT_NE(res.restored_csv.find("TXN_S3"), std::string::npos);
}

TEST(ControlClient, VerifiesEd25519UdpReflectionIpv4AndIpv6) {
    const auto ep1 = control_plane::parse_control_url("https://ctrl.example.com/ws");
    EXPECT_TRUE(ep1.use_tls);
    EXPECT_EQ(ep1.host, "ctrl.example.com");
    EXPECT_EQ(ep1.port, "443");

    const auto ep2 = control_plane::parse_control_url("wss://[::1]:8443");
    EXPECT_TRUE(ep2.use_tls);
    EXPECT_EQ(ep2.host, "::1");
    EXPECT_EQ(ep2.port, "8443");

    using PkeyCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    using Pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using MdCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

    PkeyCtx kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), &EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_keygen_init(kctx.get()), 1);
    EVP_PKEY* raw_key = nullptr;
    ASSERT_EQ(EVP_PKEY_keygen(kctx.get(), &raw_key), 1);
    Pkey key(raw_key, &EVP_PKEY_free);

    std::array<uint8_t, 32> raw_pub{};
    std::size_t pub_len = raw_pub.size();
    ASSERT_EQ(EVP_PKEY_get_raw_public_key(key.get(), raw_pub.data(), &pub_len), 1);
    const std::string pub_b64 = b64_encode_test(raw_pub.data(), pub_len);

    auto make_packet = [&](uint8_t ip_ver, const std::vector<uint8_t>& ip_bytes,
                           uint16_t port, uint64_t ts, const std::array<uint8_t, 16>& nonce) {
        std::vector<uint8_t> pkt{'B', 'V', 'S', 'T'};
        pkt.insert(pkt.end(), nonce.begin(), nonce.end());
        pkt.push_back(ip_ver);
        pkt.insert(pkt.end(), ip_bytes.begin(), ip_bytes.end());
        pkt.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
        pkt.push_back(static_cast<uint8_t>(port & 0xFF));
        for (int i = 7; i >= 0; --i) {
            pkt.push_back(static_cast<uint8_t>((ts >> (i * 8)) & 0xFF));
        }

        MdCtx mctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
        std::array<uint8_t, 64> sig{};
        std::size_t sig_len = sig.size();
        EVP_DigestSignInit(mctx.get(), nullptr, nullptr, nullptr, key.get());
        EVP_DigestSign(mctx.get(), sig.data(), &sig_len, pkt.data(), pkt.size());
        pkt.insert(pkt.end(), sig.begin(), sig.end());
        return pkt;
    };

    const std::array<uint8_t, 16> nonce{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const auto v4_pkt = make_packet(4, {203, 0, 113, 42}, 51820, 1700000000ULL, nonce);
    const auto v4 = control_plane::ControlClient::verify_udp_reflection_packet(v4_pkt, pub_b64, nonce);
    ASSERT_TRUE(v4.has_value());
    EXPECT_EQ(v4->ip, "203.0.113.42");
    EXPECT_EQ(v4->port, 51820u);
    EXPECT_EQ(v4->timestamp, 1700000000ULL);

    // IPv6 check
    const auto v6_addr = boost::asio::ip::make_address_v6("2001:db8::42").to_bytes();
    const auto v6_pkt = make_packet(
        6, std::vector<uint8_t>(v6_addr.begin(), v6_addr.end()), 4433, 1700000123ULL, nonce);
    const auto v6 = control_plane::ControlClient::verify_udp_reflection_packet(v6_pkt, pub_b64, nonce);
    ASSERT_TRUE(v6.has_value());
    EXPECT_EQ(v6->ip, "2001:db8::42");
    EXPECT_EQ(v6->port, 4433u);

    // Tamper port byte -> signature invalid
    auto bad_port = v4_pkt;
    bad_port[25] ^= 0x01;
    EXPECT_FALSE(control_plane::ControlClient::verify_udp_reflection_packet(bad_port, pub_b64, nonce).has_value());

    // Tamper signature -> invalid
    auto bad_sig = v4_pkt;
    bad_sig.back() ^= 0xFF;
    EXPECT_FALSE(control_plane::ControlClient::verify_udp_reflection_packet(bad_sig, pub_b64, nonce).has_value());

    // Wrong nonce -> rejected
    std::array<uint8_t, 16> other_nonce{};
    EXPECT_FALSE(control_plane::ControlClient::verify_udp_reflection_packet(v4_pkt, pub_b64, other_nonce).has_value());
}

TEST(VaultHsm, Pkcs11HardwareRoundTripAndNonExtractableKek) {
#ifdef _WIN32
    GTEST_SKIP() << "POSIX PKCS#11 SoftHSMv2 test skipped on Windows";
#else
    const char* mod = std::getenv("BLINDVAULT_PKCS11_MODULE");
    const char* pin = std::getenv("BLINDVAULT_PKCS11_PIN");
    if (!mod || !*mod || !pin || !*pin) {
        GTEST_SKIP() << "Set BLINDVAULT_PKCS11_MODULE and BLINDVAULT_PKCS11_PIN to run SoftHSMv2 test";
    }

    TempDir dir;
    const auto state_dir = dir.file("hsm_state");
    const auto cloud_dir = dir.file("hsm_cloud");
    const auto priv_dir = dir.file("hsm_priv");
    std::filesystem::create_directories(cloud_dir);
    setup_offline_officers(priv_dir, state_dir / "officers");

    const auto csv = dir.file("hsm_tx.csv");
    {
        std::ofstream out(csv);
        out << "tx_id,timestamp,customer_name,national_id,iban,source_ip,amount_egp,merchant\n"
            << "TXN_HSM,2026-11-20T15:00:00Z,Nourhan Tarek,30108110101000,EG380019000500000000263181000,41.10.20.30,1500.00,WE-Telecom\n";
    }

    auto hsm1 = std::make_shared<vault_kms::Pkcs11HsmProvider>(mod, pin);
    EXPECT_TRUE(hsm1->is_master_kek_non_extractable());
    EXPECT_FALSE(hsm1->can_rotate_master_kek_in_app());

    {
        vault_gateway::GatewayEngine gw(state_dir, 2, hsm1);
        const auto art = gw.prepare_encrypted_offload(csv);
        std::filesystem::copy_file(art.encrypted_file_path, cloud_dir / art.blob_name);
        EXPECT_TRUE(gw.metadata_index().verify_audit_chain());
    }

    // Reopen with a second Pkcs11HsmProvider instance verifying CKR_CRYPTOKI_ALREADY_INITIALIZED & persistence
    auto hsm2 = std::make_shared<vault_kms::Pkcs11HsmProvider>(mod, pin);
    vault_gateway::GatewayEngine gw2(state_dir, 2, hsm2);
    const auto chal = gw2.prepare_release_challenge("Nourhan Tarek");
    ASSERT_EQ(chal.candidate_blobs.size(), 1u);
    const std::vector<vault_index::OfficerApproval> ap = {
        sign_offline(priv_dir, "CBE-Officer-1", chal.target_token, chal.candidate_blobs[0],
                     chal.challenge_nonce_hex, chal.expires_utc),
        sign_offline(priv_dir, "CBE-Officer-2", chal.target_token, chal.candidate_blobs[0],
                     chal.challenge_nonce_hex, chal.expires_utc)
    };
    const auto res = gw2.auditor_query(
        "Nourhan Tarek", cloud_dir, ap, chal.challenge_nonce_hex, chal.expires_utc, "HSM-Aud");
    EXPECT_TRUE(res.authorized);
    EXPECT_TRUE(res.found);
    EXPECT_NE(res.restored_csv.find("TXN_HSM"), std::string::npos);
    EXPECT_TRUE(gw2.metadata_index().verify_audit_chain());
#endif
}

