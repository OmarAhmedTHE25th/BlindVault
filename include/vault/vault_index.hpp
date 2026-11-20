#pragma once
// Hardened Metadata Index, Asymmetric Ed25519 M-of-N Compliance Quorum Gate,
// & Tamper-Evident HMAC Hash-Chained Audit Log.
//
// Separation of Duties:
//   - Each Compliance Officer generates an Ed25519 keypair offline on their own workstation/HSM.
//   - Only the officer public keys (*.pub) are installed on the Gateway host.
//   - The Gateway holds ZERO officer private keys and has NO in-process signing capability.

#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <openssl/evp.h>
#include "at_rest_crypto.hpp"
#include "kms_provider.hpp"

namespace vault_index {

inline constexpr std::int64_t DEFAULT_CHALLENGE_TTL_SECONDS = 300;

struct BlobEntry {
    std::string blob_name;        // e.g., "vault_batch_1731870000.enc"
    std::string wrapped_dek_hex;  // 80-char hex (40-byte RFC 3394 wrapped DEK)
    std::size_t record_count = 0;
    std::size_t padded_bytes = 0;
    std::string created_utc;
};

struct OfficerApproval {
    std::string officer_id;
    std::string signature_hex;    // 128-char hex (64-byte Ed25519 signature)
};

struct ChallengeRecord {
    std::string nonce_hex;        // 32-char hex (16 CSPRNG bytes)
    std::string target_token;
    std::string expires_utc;      // UTC ISO-8601: YYYY-MM-DDTHH:MM:SSZ
    bool consumed = false;
};

// Cryptographically random 16-byte challenge nonce encoded as 32 lowercase hex chars.
std::string generate_challenge_nonce_hex();

// Formats UTC ISO-8601 timestamp ("YYYY-MM-DDTHH:MM:SSZ") at now + offset_seconds.
std::string utc_iso_offset_seconds(std::int64_t offset_seconds = 0);

// Returns true if expires_utc is malformed or at/past the current UTC time.
bool is_utc_iso_expired(const std::string& expires_utc);

// Canonical payload signed offline by each Compliance Officer
std::string build_release_payload(const std::string& officer_id,
                                  const std::string& target_token,
                                  const std::string& blob_name,
                                  const std::string& wrapped_dek_hex,
                                  const std::string& challenge_nonce_hex,
                                  const std::string& expires_utc);

// Offline Officer Keygen (run on each officer's own workstation/HSM)
void generate_officer_ed25519_keypair(const std::filesystem::path& priv_pem_path,
                                      const std::filesystem::path& pub_pem_path);

// Offline Officer Signing (run on each officer's own device; never called by GatewayEngine)
std::string sign_blob_release_offline(const std::filesystem::path& priv_pem_path,
                                      const std::string& officer_id,
                                      const std::string& target_token,
                                      const std::string& blob_name,
                                      const std::string& wrapped_dek_hex,
                                      const std::string& challenge_nonce_hex,
                                      const std::string& expires_utc);

// Gateway-Side Verifier:
//   - Holds ONLY officer Ed25519 public keys (*.pub) on disk. Zero private keys on the Gateway host.
//   - Binds approvals to (officer_id, target_token, blob_name, wrapped_dek_hex,
//     challenge_nonce_hex, expires_utc) so forged index entries or replayed signatures
//     cannot bypass quorum.
class QuorumGate {
public:
    using PkeyPtr = std::shared_ptr<EVP_PKEY>;

    explicit QuorumGate(std::filesystem::path officer_pubkey_dir, std::size_t threshold = 2);

    void reload_public_keys();

    std::size_t threshold() const noexcept { return threshold_; }
    std::size_t registered_officer_count() const noexcept { return officer_pubkeys_.size(); }

    std::vector<std::string> registered_officers() const;

    // Verifies expiry and that >= threshold distinct officers signed this exact challenge + blob
    bool verify_blob_release(const std::string& target_token,
                             const BlobEntry& blob,
                             const std::string& challenge_nonce_hex,
                             const std::string& expires_utc,
                             const std::vector<OfficerApproval>& approvals) const;

private:
    static PkeyPtr load_public_key(const std::filesystem::path& pub_path);

    std::filesystem::path officer_pubkey_dir_;
    std::size_t threshold_;
    std::unordered_map<std::string, PkeyPtr> officer_pubkeys_;
};

// HMAC-Authenticated Metadata Index & Cryptographic Hash-Chained Audit Log
class MetadataIndex {
public:
    MetadataIndex(std::filesystem::path index_file,
                  std::filesystem::path audit_log_file,
                  std::shared_ptr<vault_kms::KeyManagementProvider> kms);

    void register_blob(const BlobEntry& entry, const std::vector<std::string>& tokens_in_blob);

    std::vector<BlobEntry> find_candidate_blobs(const std::string& token) const;
    std::vector<BlobEntry> blob_entries() const;

    void update_wrapped_dek(const std::string& blob_name, const std::string& wrapped_dek_hex);
    void update_blob_metadata(const std::string& blob_name,
                              const std::string& wrapped_dek_hex,
                              std::size_t padded_bytes);
    void remap_tokens(const std::unordered_map<std::string, std::string>& old_to_new);

    void issue_challenge(const std::string& nonce_hex,
                         const std::string& target_token,
                         const std::string& expires_utc);

    bool validate_challenge_active(const std::string& nonce_hex,
                                   const std::string& target_token,
                                   const std::string& expires_utc) const;

    void consume_challenge(const std::string& nonce_hex);

    std::optional<ChallengeRecord> find_challenge(const std::string& nonce_hex) const;

    void reauthenticate_after_kms_rotation();

    void log_security_event(const std::string& action, const std::string& detail);

    // Re-verifies every HMAC link in regtech_audit.log from genesis to latest entry
    bool verify_audit_chain() const;

private:
    static std::string current_utc_iso();

    void append_chained_audit_unlocked(const std::string& action, const std::string& detail);

    static bool verify_audit_file_internal(const std::filesystem::path& path,
                                           const std::shared_ptr<vault_kms::KeyManagementProvider>& kms,
                                           uint64_t& out_next_seq,
                                           std::string& out_last_mac);

    void load_and_verify_audit_chain_unlocked();

    std::string serialize_canonical_body_unlocked() const;
    void save_authenticated_index_unlocked() const;
    void load_and_verify_index_unlocked();

    std::filesystem::path index_file_;
    std::filesystem::path audit_log_file_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, BlobEntry> blobs_;
    std::unordered_map<std::string, std::unordered_set<std::string>> token_to_blobs_;
    std::unordered_map<std::string, ChallengeRecord> challenges_;
    uint64_t audit_seq_ = 1;
    std::string last_audit_mac_ = std::string(64, '0');
    std::shared_ptr<vault_kms::KeyManagementProvider> kms_;
};

} // namespace vault_index
