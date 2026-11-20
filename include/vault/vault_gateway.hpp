#pragma once
// Hardened Zero-Knowledge RegTech Gateway Engine:
//   - RLIMIT_CORE=0 + move-only OPENSSL_cleanse RAII keys/buffers
//   - PKCS#11 Hardware HSM / 0600 Software KMS Master KEK + Crash-Safe KEK Rotation
//   - O(1)-RAM Streaming CSV Tokenization + Chunked BVL3 AEAD Encryption
//   - HMAC-authenticated MetadataIndex + Replay-Proof Nonce/Expiry Challenges + Hash-Chained Audit Log
//   - True Asymmetric Ed25519 M-of-N Compliance Quorum Gate + Automatic 2-of-3 Erasure Shard Recovery

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>
#include "at_rest_crypto.hpp"
#include "erasure_shard_backend.hpp"
#include "kms_provider.hpp"
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

struct ReleaseChallenge {
    std::string target_token;
    std::vector<vault_index::BlobEntry> candidate_blobs;
    std::vector<std::string> registered_officers;
    std::size_t quorum_threshold = 2;
    std::string challenge_nonce_hex;
    std::string expires_utc;
};

struct AuditorQueryResult {
    bool authorized = false;
    bool found = false;
    std::string denial_reason;
    std::string matched_token;
    std::vector<std::string> blob_names;
    std::string restored_csv;
    std::string raw_cloud_hex_preview;
    bool recovered_from_shards = false;
};

class GatewayEngine {
public:
    explicit GatewayEngine(const std::filesystem::path& state_dir,
                           std::size_t quorum_threshold = 2,
                           std::shared_ptr<vault_kms::KeyManagementProvider> kms = nullptr,
                           std::shared_ptr<ErasureShardBackend> shard_backend = nullptr);

    const vault_index::QuorumGate& quorum_gate() const noexcept { return quorum_gate_; }
    vault_index::QuorumGate& quorum_gate() noexcept { return quorum_gate_; }
    const vault_index::MetadataIndex& metadata_index() const noexcept { return metadata_index_; }
    std::filesystem::path officer_pubkey_directory() const { return state_dir_ / "officers"; }
    std::filesystem::path staging_directory() const { return staging_dir_; }

    // Generates and persists a fresh replay-proof quorum release challenge (nonce + UTC expiry)
    ReleaseChallenge prepare_release_challenge(
        const std::string& raw_or_token_identifier,
        std::int64_t ttl_seconds = vault_index::DEFAULT_CHALLENGE_TTL_SECONDS);

    std::filesystem::path generate_synthetic_cbe_batch(std::size_t row_count = 10000) const;

    // Streams CSV through Tokenizer -> chunked BVL3 AEAD in O(1) RAM, then splits 2-of-3 shards
    OffloadArtifact prepare_encrypted_offload(const std::filesystem::path& raw_csv_path);

    // Enforces challenge validity + single-use consumption + Ed25519 quorum + automatic shard recovery
    AuditorQueryResult auditor_query(
        const std::string& raw_or_token_identifier,
        const std::filesystem::path& cloud_storage_dir,
        const std::vector<vault_index::OfficerApproval>& blob_quorum_approvals,
        const std::string& challenge_nonce_hex,
        const std::string& expires_utc,
        const std::string& auditor_id = "CBE-Auditor-01");

    // Crash-safe Master KEK + Tokenizer Pepper + MetadataIndex/Audit Log + Blob Rotation
    void rotate_master_kek(
        const vault_crypto::SecretKey& new_master_kek,
        const std::filesystem::path& cloud_storage_dir = {});

    // Exposed for crash-recovery testing; also invoked automatically before loading GatewayEngine state
    static void recover_incomplete_rotation_if_needed(const std::filesystem::path& state_dir);

private:
    std::string resolve_to_token(const std::string& raw_or_token);
    static std::string make_blob_filename();
    static std::string format_hex_dump(const std::uint8_t* bytes, std::size_t size, std::size_t max_bytes);
    static std::string format_hex_dump(const std::vector<uint8_t>& bytes, std::size_t max_bytes);

    bool decrypt_and_filter_blob_stream(
        std::istream& in,
        std::size_t total_len,
        const vault_crypto::SecretKey& dek,
        const std::string& blob_name,
        const std::string& target_token,
        std::string& out_matched_rows,
        std::size_t& out_match_count) const;

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
