#include "vault_gateway.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <unordered_set>
#include <utility>
#include <openssl/crypto.h>
#include "s3_shard_backend.hpp"

namespace vault_gateway {

namespace {

class MemoryReadStreamBuf final : public std::streambuf {
public:
    MemoryReadStreamBuf(const uint8_t* data, std::size_t size) {
        auto* p = const_cast<char*>(reinterpret_cast<const char*>(data));
        setg(p, p, p + size);
    }

protected:
    pos_type seekoff(off_type off, std::ios_base::seekdir way,
                     std::ios_base::openmode which) override {
        if ((which & std::ios_base::in) == 0) return pos_type(off_type(-1));
        char* next = nullptr;
        if (way == std::ios_base::beg) next = eback() + off;
        else if (way == std::ios_base::cur) next = gptr() + off;
        else if (way == std::ios_base::end) next = egptr() + off;
        if (!next || next < eback() || next > egptr()) return pos_type(off_type(-1));
        setg(eback(), next, egptr());
        return pos_type(next - eback());
    }

    pos_type seekpos(pos_type sp, std::ios_base::openmode which) override {
        return seekoff(off_type(sp), std::ios_base::beg, which);
    }
};

struct CleanseGuard {
    std::string& s;
    ~CleanseGuard() {
        if (!s.empty()) OPENSSL_cleanse(s.data(), s.size());
    }
};

struct KeyCleanseGuard {
    vault_crypto::SecretKey& k;
    ~KeyCleanseGuard() { k.cleanse(); }
};

std::shared_ptr<vault_kms::KeyManagementProvider> init_kms_after_recovery(
    const std::filesystem::path& state_dir,
    std::shared_ptr<vault_kms::KeyManagementProvider> kms) {
    GatewayEngine::recover_incomplete_rotation_if_needed(state_dir);
    return kms ? std::move(kms) : vault_kms::create_default_kms(state_dir);
}

std::shared_ptr<ErasureShardBackend> init_default_shard_backend(
    const std::filesystem::path& state_dir,
    std::shared_ptr<ErasureShardBackend> backend) {
    if (backend) return backend;
    if (auto s3 = create_s3_shard_backend_from_env()) return s3;
    return std::make_shared<LocalErasureShardBackend>(state_dir / "erasure_shards");
}

void copy_file_0600_if_exists(const std::filesystem::path& src, const std::filesystem::path& dst) {
    if (!std::filesystem::exists(src)) return;
    if (dst.has_parent_path()) std::filesystem::create_directories(dst.parent_path());
    std::filesystem::copy_file(src, dst, std::filesystem::copy_options::overwrite_existing);
    std::error_code ec;
    std::filesystem::permissions(
        dst,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
}

void copy_dir_contents_overwrite(const std::filesystem::path& src_dir, const std::filesystem::path& dst_dir) {
    if (!std::filesystem::exists(src_dir)) return;
    std::filesystem::create_directories(dst_dir);
    for (const auto& entry : std::filesystem::directory_iterator(src_dir)) {
        if (!entry.is_regular_file()) continue;
        std::filesystem::copy_file(
            entry.path(),
            dst_dir / entry.path().filename(),
            std::filesystem::copy_options::overwrite_existing);
    }
}

std::string trim_line(std::string s) {
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) s.pop_back();
    return s;
}

} // namespace

LocalErasureShardBackend::LocalErasureShardBackend(std::filesystem::path shard_dir)
    : shard_dir_(std::move(shard_dir)) {
    std::filesystem::create_directories(shard_dir_);
}

void LocalErasureShardBackend::write_shard(const std::filesystem::path& blob_name,
                                           std::size_t shard_index,
                                           const std::vector<uint8_t>& shard) {
    vault_crypto::write_bytes_to_file(
        (shard_dir_ / (blob_name.filename().string() + ".shard" + std::to_string(shard_index))).string(),
        shard);
}

std::optional<std::vector<uint8_t>> LocalErasureShardBackend::read_shard(
    const std::filesystem::path& blob_name,
    std::size_t shard_index) {
    const auto shard_path =
        shard_dir_ / (blob_name.filename().string() + ".shard" + std::to_string(shard_index));
    if (!std::filesystem::exists(shard_path)) {
        return std::nullopt;
    }
    try {
        return vault_crypto::read_bytes_from_file(shard_path.string());
    } catch (...) {
        return std::nullopt;
    }
}

void GatewayEngine::recover_incomplete_rotation_if_needed(const std::filesystem::path& state_dir) {
    const auto journal_path = state_dir / "rotation.journal";
    const auto backup_dir = state_dir / ".rotation_backup";
    if (!std::filesystem::exists(journal_path)) {
        return;
    }

    std::string state;
    std::string cloud_dir_line;
    {
        std::ifstream in(journal_path, std::ios::binary);
        if (in) {
            std::getline(in, state);
            std::getline(in, cloud_dir_line);
        }
    }
    state = trim_line(state);
    cloud_dir_line = trim_line(cloud_dir_line);

    if (state != "COMMITTED" && std::filesystem::exists(backup_dir)) {
        copy_file_0600_if_exists(backup_dir / "hsm_master.kek", state_dir / "hsm_master.kek");
        copy_file_0600_if_exists(backup_dir / "vault_tokens.enc", state_dir / "vault_tokens.enc");
        copy_file_0600_if_exists(backup_dir / "vault_index.tsv", state_dir / "vault_index.tsv");
        copy_file_0600_if_exists(backup_dir / "regtech_audit.log", state_dir / "regtech_audit.log");
        copy_dir_contents_overwrite(backup_dir / "egress_staging", state_dir / "egress_staging");
        copy_dir_contents_overwrite(backup_dir / "erasure_shards", state_dir / "erasure_shards");
        if (cloud_dir_line.rfind("CLOUD_DIR=", 0) == 0) {
            const std::filesystem::path cloud_dir(cloud_dir_line.substr(10));
            if (!cloud_dir.empty()) {
                copy_dir_contents_overwrite(backup_dir / "cloud_blobs", cloud_dir);
            }
        }
    }

    std::error_code ec;
    std::filesystem::remove_all(backup_dir, ec);
    std::filesystem::remove(journal_path, ec);
}

GatewayEngine::GatewayEngine(const std::filesystem::path& state_dir,
                             std::size_t quorum_threshold,
                             std::shared_ptr<vault_kms::KeyManagementProvider> kms,
                             std::shared_ptr<ErasureShardBackend> shard_backend)
    : state_dir_(state_dir),
      staging_dir_(state_dir / "egress_staging"),
      shards_dir_(state_dir / "erasure_shards"),
      kms_(init_kms_after_recovery(state_dir, std::move(kms))),
      shard_backend_(init_default_shard_backend(state_dir, std::move(shard_backend))),
      token_vault_(state_dir / "vault_tokens.enc", kms_),
      metadata_index_(state_dir / "vault_index.tsv", state_dir / "regtech_audit.log", kms_),
      quorum_gate_(state_dir / "officers", quorum_threshold) {
    vault_crypto::harden_process_memory();
    std::filesystem::create_directories(staging_dir_);
    std::filesystem::create_directories(shards_dir_);
}

ReleaseChallenge GatewayEngine::prepare_release_challenge(const std::string& raw_or_token_identifier,
                                                          std::int64_t ttl_seconds) {
    quorum_gate_.reload_public_keys();
    const std::string token = resolve_to_token(raw_or_token_identifier);
    const std::string nonce_hex = vault_index::generate_challenge_nonce_hex();
    const std::string expires_utc = vault_index::utc_iso_offset_seconds(ttl_seconds);
    metadata_index_.issue_challenge(nonce_hex, token, expires_utc);

    return ReleaseChallenge{
        token,
        metadata_index_.find_candidate_blobs(token),
        quorum_gate_.registered_officers(),
        quorum_gate_.threshold(),
        nonce_hex,
        expires_utc
    };
}

std::filesystem::path GatewayEngine::generate_synthetic_cbe_batch(std::size_t row_count) const {
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

OffloadArtifact GatewayEngine::prepare_encrypted_offload(const std::filesystem::path& raw_csv_path) {
    const auto t0 = std::chrono::steady_clock::now();

    std::ifstream in(raw_csv_path, std::ios::binary);
    if (!in) throw std::runtime_error("GatewayEngine: cannot open CSV " + raw_csv_path.string());

    vault_crypto::SecretKey dek = vault_crypto::generate_key();
    KeyCleanseGuard dek_guard{dek};

    const std::string blob_name = make_blob_filename();
    const std::filesystem::path enc_path = staging_dir_ / blob_name;
    std::filesystem::create_directories(staging_dir_);

    vault_token::SanitizeStats stats;
    std::unordered_set<std::string> unique_tokens;
    std::size_t padded_bytes = 0;
    {
        std::ofstream enc_out(enc_path, std::ios::binary | std::ios::trunc);
        if (!enc_out) throw std::runtime_error("GatewayEngine: cannot write encrypted blob " + enc_path.string());
        vault_crypto::Bvl3EncryptingStreamBuf bvl3_buf(enc_out, dek, blob_name);
        std::ostream bvl3_out(&bvl3_buf);
        token_vault_.sanitize_csv_stream(in, bvl3_out, &stats, &unique_tokens);
        bvl3_out.flush();
        padded_bytes = bvl3_buf.finalize();
        enc_out.flush();
        if (!enc_out) {
            throw std::runtime_error("GatewayEngine: failed flushing encrypted blob " + enc_path.string());
        }
    }

    const std::string wrapped_dek = kms_->wrap_dek_hex(dek);
    dek.cleanse();

    const std::vector<uint8_t> ciphertext_bytes = vault_crypto::read_bytes_from_file(enc_path.string());
    const auto shards = vault_crypto::erasure_split_2of3(ciphertext_bytes);
    for (std::size_t s = 0; s < 3; ++s) {
        shard_backend_->write_shard(blob_name, s, shards[s]);
    }

    std::vector<std::string> tokens_in_blob(unique_tokens.begin(), unique_tokens.end());
    vault_index::BlobEntry entry;
    entry.blob_name       = blob_name;
    entry.wrapped_dek_hex = wrapped_dek;
    entry.record_count    = stats.records_processed;
    entry.padded_bytes    = padded_bytes;
    metadata_index_.register_blob(entry, tokens_in_blob);

    const auto t1 = std::chrono::steady_clock::now();
    const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    const double rps = (ms > 0.0) ? (static_cast<double>(stats.records_processed) / (ms / 1000.0)) : 0.0;

    return OffloadArtifact{
        enc_path, blob_name, stats,
        padded_bytes, shards[0].size(), ms, rps
    };
}

bool GatewayEngine::decrypt_and_filter_blob_stream(std::istream& in,
                                                   std::size_t total_len,
                                                   const vault_crypto::SecretKey& dek,
                                                   const std::string& blob_name,
                                                   const std::string& target_token,
                                                   std::string& out_matched_rows,
                                                   std::size_t& out_match_count) const {
    std::string pending;
    CleanseGuard pending_guard{pending};
    bool header_seen = false;
    std::ostringstream blob_rows;
    std::size_t match_count = 0;

    auto process_line = [&](std::string& line) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!header_seen) {
            header_seen = true;
            return;
        }
        if (line.empty()) return;

        const auto cols = vault_token::parse_csv_row(line);
        if (cols.size() < 8) return;
        if (cols[2] == target_token || cols[3] == target_token || cols[4] == target_token) {
            vault_token::TransactionRecord clean{
                cols[0], cols[1], cols[2], cols[3], cols[4], cols[5], cols[6], cols[7]
            };
            const auto restored = token_vault_.rehydrate_record(clean);
            blob_rows << vault_token::format_csv_row({
                restored.tx_id, restored.timestamp, restored.customer_name,
                restored.national_id, restored.iban, restored.source_ip,
                restored.amount_egp, restored.merchant
            }) << '\n';
            ++match_count;
        }
    };

    vault_crypto::decrypt_stream_auto(
        in, total_len, dek, blob_name,
        [&](std::string_view chunk) {
            std::size_t start = 0;
            while (start < chunk.size()) {
                const std::size_t nl = chunk.find('\n', start);
                if (nl == std::string_view::npos) {
                    pending.append(chunk.substr(start));
                    break;
                }
                pending.append(chunk.substr(start, nl - start));
                process_line(pending);
                if (!pending.empty()) OPENSSL_cleanse(pending.data(), pending.size());
                pending.clear();
                start = nl + 1;
            }
        });

    if (!pending.empty()) {
        process_line(pending);
        OPENSSL_cleanse(pending.data(), pending.size());
        pending.clear();
    }

    out_matched_rows = blob_rows.str();
    out_match_count = match_count;
    return true;
}

AuditorQueryResult GatewayEngine::auditor_query(
    const std::string& raw_or_token_identifier,
    const std::filesystem::path& cloud_storage_dir,
    const std::vector<vault_index::OfficerApproval>& blob_quorum_approvals,
    const std::string& challenge_nonce_hex,
    const std::string& expires_utc,
    const std::string& auditor_id) {

    quorum_gate_.reload_public_keys();
    AuditorQueryResult res;
    const std::string token = resolve_to_token(raw_or_token_identifier);
    res.matched_token = token;

    if (quorum_gate_.registered_officer_count() < quorum_gate_.threshold()) {
        res.authorized = false;
        res.denial_reason = "QUORUM UNCONFIGURED: Found " +
                            std::to_string(quorum_gate_.registered_officer_count()) +
                            " officer public key(s) in '" + officer_pubkey_directory().string() +
                            "', need at least " + std::to_string(quorum_gate_.threshold()) + " (*.pub).";
        metadata_index_.log_security_event(
            "QUORUM_DENIED",
            "Blocked query by '" + auditor_id + "': insufficient registered officer public keys");
        return res;
    }

    if (!metadata_index_.validate_challenge_active(challenge_nonce_hex, token, expires_utc)) {
        res.authorized = false;
        const auto existing = metadata_index_.find_challenge(challenge_nonce_hex);
        if (existing && existing->consumed) {
            res.denial_reason = "CHALLENGE REPLAY REJECTED: Challenge nonce has already been consumed.";
        } else if (vault_index::is_utc_iso_expired(expires_utc)) {
            res.denial_reason = "CHALLENGE EXPIRED: Quorum challenge timestamp has expired.";
        } else {
            res.denial_reason = "INVALID CHALLENGE: Challenge nonce is unknown, mismatched, or expired.";
        }
        metadata_index_.log_security_event(
            "QUORUM_DENIED",
            "Blocked challenge by '" + auditor_id + "' for token '" + token + "': " + res.denial_reason);
        return res;
    }

    const auto candidate_blobs = metadata_index_.find_candidate_blobs(token);
    if (candidate_blobs.empty()) {
        vault_index::BlobEntry dummy{"NONE", "NONE", 0, 0, ""};
        if (!quorum_gate_.verify_blob_release(
                token, dummy, challenge_nonce_hex, expires_utc, blob_quorum_approvals)) {
            res.authorized = false;
            res.denial_reason = "QUORUM DENIED: Requires at least " +
                                std::to_string(quorum_gate_.threshold()) +
                                " valid detached Ed25519 officer signatures.";
            metadata_index_.log_security_event(
                "QUORUM_DENIED",
                "Blocked unauthorized probe by '" + auditor_id + "' for token '" + token + "'");
            return res;
        }
        metadata_index_.consume_challenge(challenge_nonce_hex);
        res.authorized = true;
        res.found = false;
        return res;
    }

    std::ostringstream combined_restored;
    combined_restored << "tx_id,timestamp,customer_name,national_id,iban,ip_status,amount_egp,merchant\n";
    bool any_blob_authorized = false;
    bool challenge_consumed = false;
    bool any_row_matched = false;

    for (const auto& blob : candidate_blobs) {
        if (!quorum_gate_.verify_blob_release(
                token, blob, challenge_nonce_hex, expires_utc, blob_quorum_approvals)) {
            metadata_index_.log_security_event(
                "QUORUM_DENIED",
                "Blocked unauthorized release of blob '" + blob.blob_name + "' for token '" + token + "'");
            continue;
        }
        any_blob_authorized = true;
        if (!challenge_consumed) {
            metadata_index_.consume_challenge(challenge_nonce_hex);
            challenge_consumed = true;
        }

        vault_crypto::SecretKey dek = kms_->unwrap_dek_hex(blob.wrapped_dek_hex);
        KeyCleanseGuard dek_guard{dek};

        const std::filesystem::path primary_path =
            cloud_storage_dir.empty()
                ? (staging_dir_ / blob.blob_name)
                : (cloud_storage_dir / blob.blob_name);

        std::string blob_rows;
        std::size_t blob_match_count = 0;
        bool primary_ok = false;

        if (std::filesystem::exists(primary_path) && std::filesystem::is_regular_file(primary_path)) {
            try {
                const auto fsize = static_cast<std::size_t>(std::filesystem::file_size(primary_path));
                std::ifstream blob_in(primary_path, std::ios::binary);
                if (blob_in) {
                    if (res.raw_cloud_hex_preview.empty()) {
                        std::vector<uint8_t> preview(std::min<std::size_t>(256, fsize));
                        blob_in.read(reinterpret_cast<char*>(preview.data()),
                                     static_cast<std::streamsize>(preview.size()));
                        preview.resize(static_cast<std::size_t>(blob_in.gcount()));
                        res.raw_cloud_hex_preview = format_hex_dump(preview.data(), preview.size(), fsize);
                        blob_in.clear();
                        blob_in.seekg(0, std::ios::beg);
                    }
                    primary_ok = decrypt_and_filter_blob_stream(
                        blob_in, fsize, dek, blob.blob_name, token, blob_rows, blob_match_count);
                }
            } catch (...) {
                primary_ok = false;
            }
        }

        if (!primary_ok) {
            if (!shard_backend_ || blob.padded_bytes == 0) {
                throw std::runtime_error(
                    "GatewayEngine: primary blob missing/corrupted and erasure metadata unavailable for '" +
                    blob.blob_name + "'");
            }
            std::array<std::vector<uint8_t>, 3> shards;
            std::size_t present_shards = 0;
            for (std::size_t s = 0; s < 3; ++s) {
                if (auto got = shard_backend_->read_shard(blob.blob_name, s); got && !got->empty()) {
                    shards[s] = std::move(*got);
                    ++present_shards;
                }
            }
            if (present_shards < 2) {
                throw std::runtime_error(
                    "GatewayEngine: fewer than 2 erasure shards available for '" + blob.blob_name + "'");
            }
            const std::vector<uint8_t> recovered = vault_crypto::erasure_reconstruct_2of3(
                shards[0], shards[1], shards[2], blob.padded_bytes);

            if (res.raw_cloud_hex_preview.empty()) {
                res.raw_cloud_hex_preview = format_hex_dump(recovered, 256);
            }

            MemoryReadStreamBuf mem_buf(recovered.data(), recovered.size());
            std::istream rec_in(&mem_buf);
            decrypt_and_filter_blob_stream(
                rec_in, recovered.size(), dek, blob.blob_name, token, blob_rows, blob_match_count);

            res.recovered_from_shards = true;
            metadata_index_.log_security_event(
                "SHARD_RECOVERY",
                "Recovered blob '" + blob.blob_name +
                "' via 2-of-3 erasure shards (primary missing or failed GCM authentication)");
        }

        combined_restored << blob_rows;
        if (!blob_rows.empty()) OPENSSL_cleanse(blob_rows.data(), blob_rows.size());
        if (blob_match_count > 0) any_row_matched = true;
        res.blob_names.push_back(blob.blob_name);
    }

    if (!any_blob_authorized) {
        res.authorized = false;
        res.denial_reason = "QUORUM DENIED: Requires at least " +
                            std::to_string(quorum_gate_.threshold()) +
                            " valid detached Ed25519 officer signatures bound to target blob.";
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

void GatewayEngine::rotate_master_kek(const vault_crypto::SecretKey& new_master_kek,
                                      const std::filesystem::path& cloud_storage_dir) {
    if (!kms_->can_rotate_master_kek_in_app()) {
        throw std::runtime_error(
            "GatewayEngine: master KEK rotation is administratively managed by the KMS/HSM backend");
    }
    if (!metadata_index_.verify_audit_chain()) {
        throw std::runtime_error("GatewayEngine: refusing KEK rotation with tampered audit chain");
    }

    const auto entries = metadata_index_.blob_entries();
    const auto backup_dir = state_dir_ / ".rotation_backup";
    const auto plain_dir = backup_dir / "plain";
    const auto journal_path = state_dir_ / "rotation.journal";

    std::error_code ec;
    std::filesystem::remove_all(backup_dir, ec);
    std::filesystem::remove(journal_path, ec);

    std::filesystem::create_directories(plain_dir);
    copy_file_0600_if_exists(state_dir_ / "hsm_master.kek", backup_dir / "hsm_master.kek");
    copy_file_0600_if_exists(state_dir_ / "vault_tokens.enc", backup_dir / "vault_tokens.enc");
    copy_file_0600_if_exists(state_dir_ / "vault_index.tsv", backup_dir / "vault_index.tsv");
    copy_file_0600_if_exists(state_dir_ / "regtech_audit.log", backup_dir / "regtech_audit.log");
    copy_dir_contents_overwrite(staging_dir_, backup_dir / "egress_staging");
    copy_dir_contents_overwrite(shards_dir_, backup_dir / "erasure_shards");
    if (!cloud_storage_dir.empty()) {
        copy_dir_contents_overwrite(cloud_storage_dir, backup_dir / "cloud_blobs");
    }

    struct RotationPlan {
        std::string blob_name;
        std::filesystem::path plain_file;
        vault_crypto::SecretKey dek;
    };
    std::vector<RotationPlan> plans;
    plans.reserve(entries.size());

    // Phase 1: Decrypt & rehydrate all blobs under current keys before touching key material
    for (const auto& entry : entries) {
        std::filesystem::path blob_path = staging_dir_ / entry.blob_name;
        if (!cloud_storage_dir.empty()) {
            const auto cloud_path = cloud_storage_dir / entry.blob_name;
            if (std::filesystem::exists(cloud_path)) blob_path = cloud_path;
        }
        if (!std::filesystem::exists(blob_path)) {
            std::filesystem::remove_all(backup_dir, ec);
            throw std::runtime_error("GatewayEngine: cannot rotate missing blob '" + entry.blob_name + "'");
        }

        vault_crypto::SecretKey dek = kms_->unwrap_dek_hex(entry.wrapped_dek_hex);
        const auto plain_path = plain_dir / (entry.blob_name + ".plain.csv");
        {
            const auto fsize = static_cast<std::size_t>(std::filesystem::file_size(blob_path));
            std::ifstream blob_in(blob_path, std::ios::binary);
            std::ofstream plain_out(plain_path, std::ios::binary | std::ios::trunc);
            if (!blob_in || !plain_out) {
                std::filesystem::remove_all(backup_dir, ec);
                throw std::runtime_error("GatewayEngine: I/O error preparing blob '" + entry.blob_name + "'");
            }
            std::filesystem::permissions(
                plain_path,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace, ec);

            std::string pending;
            CleanseGuard pending_guard{pending};
            bool header_seen = false;
            auto flush_line = [&](std::string& line) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (!header_seen) {
                    header_seen = true;
                    plain_out << line << '\n';
                    return;
                }
                if (line.empty()) return;
                std::istringstream ls(line);
                // rehydrate line by line without keeping whole file in RAM
                const auto cols = vault_token::parse_csv_row(line);
                if (cols.size() >= 8) {
                    vault_token::TransactionRecord rec{
                        cols[0], cols[1], cols[2], cols[3], cols[4], cols[5], cols[6], cols[7]
                    };
                    const auto r = token_vault_.rehydrate_record(rec);
                    plain_out << vault_token::format_csv_row({
                        r.tx_id, r.timestamp, r.customer_name,
                        r.national_id, r.iban, r.source_ip,
                        r.amount_egp, r.merchant
                    }) << '\n';
                } else {
                    plain_out << line << '\n';
                }
            };

            vault_crypto::decrypt_stream_auto(
                blob_in, fsize, dek, entry.blob_name,
                [&](std::string_view chunk) {
                    std::size_t start = 0;
                    while (start < chunk.size()) {
                        const std::size_t nl = chunk.find('\n', start);
                        if (nl == std::string_view::npos) {
                            pending.append(chunk.substr(start));
                            break;
                        }
                        pending.append(chunk.substr(start, nl - start));
                        flush_line(pending);
                        if (!pending.empty()) OPENSSL_cleanse(pending.data(), pending.size());
                        pending.clear();
                        start = nl + 1;
                    }
                });
            if (!pending.empty()) {
                flush_line(pending);
                OPENSSL_cleanse(pending.data(), pending.size());
                pending.clear();
            }
            plain_out.flush();
            if (!plain_out) {
                std::filesystem::remove_all(backup_dir, ec);
                throw std::runtime_error("GatewayEngine: failed flushing temporary rotation file");
            }
        }
        plans.push_back(RotationPlan{entry.blob_name, plain_path, std::move(dek)});
    }

    // Write journal BEFORE mutating live keys/state so any crash restores from backup
    {
        std::string journal = "IN_PROGRESS\n";
        if (!cloud_storage_dir.empty()) {
            journal += "CLOUD_DIR=" + cloud_storage_dir.string() + "\n";
        }
        vault_crypto::write_secret_file_0600(journal_path, journal);
    }

    try {
        kms_->rotate_master_kek(new_master_kek);
        metadata_index_.reauthenticate_after_kms_rotation();
        const auto token_remap = token_vault_.rotate_kms_pepper();
        metadata_index_.remap_tokens(token_remap);
        token_vault_.flush();

        for (auto& plan : plans) {
            const auto tmp_enc = backup_dir / (plan.blob_name + ".new.enc");
            std::size_t new_padded_bytes = 0;
            {
                std::ifstream plain_in(plan.plain_file, std::ios::binary);
                std::ofstream enc_out(tmp_enc, std::ios::binary | std::ios::trunc);
                if (!plain_in || !enc_out) {
                    throw std::runtime_error("GatewayEngine: failed reopening files during rotation");
                }
                vault_crypto::Bvl3EncryptingStreamBuf bvl3_buf(enc_out, plan.dek, plan.blob_name);
                std::ostream bvl3_out(&bvl3_buf);
                token_vault_.sanitize_csv_stream(plain_in, bvl3_out);
                bvl3_out.flush();
                new_padded_bytes = bvl3_buf.finalize();
                enc_out.flush();
                if (!enc_out) {
                    throw std::runtime_error("GatewayEngine: failed flushing rotated blob");
                }
            }

            const std::vector<uint8_t> rotated_ct = vault_crypto::read_bytes_from_file(tmp_enc.string());
            const auto shards = vault_crypto::erasure_split_2of3(rotated_ct);
            for (std::size_t s = 0; s < 3; ++s) {
                shard_backend_->write_shard(plan.blob_name, s, shards[s]);
            }

            const auto staging_path = staging_dir_ / plan.blob_name;
            std::filesystem::copy_file(
                tmp_enc, staging_path, std::filesystem::copy_options::overwrite_existing);
            if (!cloud_storage_dir.empty()) {
                std::filesystem::copy_file(
                    tmp_enc, cloud_storage_dir / plan.blob_name,
                    std::filesystem::copy_options::overwrite_existing);
            }

            const std::string rewrapped = kms_->wrap_dek_hex(plan.dek);
            metadata_index_.update_blob_metadata(plan.blob_name, rewrapped, new_padded_bytes);
            plan.dek.cleanse();
        }

        metadata_index_.log_security_event(
            "KEK_ROTATION",
            "Rotated Master KEK, tokenizer pepper, index MAC, audit chain, and re-encrypted " +
            std::to_string(plans.size()) + " blob(s) to BVL3");

        vault_crypto::write_secret_file_0600(journal_path, "COMMITTED\n");
        std::filesystem::remove_all(backup_dir, ec);
        std::filesystem::remove(journal_path, ec);
    } catch (...) {
        for (auto& plan : plans) plan.dek.cleanse();
        copy_file_0600_if_exists(backup_dir / "hsm_master.kek", state_dir_ / "hsm_master.kek");
        copy_file_0600_if_exists(backup_dir / "vault_tokens.enc", state_dir_ / "vault_tokens.enc");
        copy_file_0600_if_exists(backup_dir / "vault_index.tsv", state_dir_ / "vault_index.tsv");
        copy_file_0600_if_exists(backup_dir / "regtech_audit.log", state_dir_ / "regtech_audit.log");
        copy_dir_contents_overwrite(backup_dir / "egress_staging", staging_dir_);
        copy_dir_contents_overwrite(backup_dir / "erasure_shards", shards_dir_);
        if (!cloud_storage_dir.empty()) {
            copy_dir_contents_overwrite(backup_dir / "cloud_blobs", cloud_storage_dir);
        }
        std::filesystem::remove_all(backup_dir, ec);
        std::filesystem::remove(journal_path, ec);
        throw;
    }
}

std::string GatewayEngine::resolve_to_token(const std::string& raw_or_token) {
    if (raw_or_token.rfind("TOK_", 0) == 0) {
        return raw_or_token;
    }
    return token_vault_.tokenize(raw_or_token);
}

std::string GatewayEngine::make_blob_filename() {
    static std::atomic<std::uint64_t> seq{0};
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    const auto id = seq.fetch_add(1, std::memory_order_relaxed);
    return "vault_batch_" + std::to_string(ms) + "_" + std::to_string(id) + ".enc";
}

std::string GatewayEngine::format_hex_dump(const std::uint8_t* bytes,
                                           std::size_t size,
                                           std::size_t max_bytes) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::ostringstream ss;
    const std::size_t limit = std::min(size, max_bytes);
    for (std::size_t i = 0; i < limit; ++i) {
        if (i > 0 && i % 16 == 0) ss << '\n';
        else if (i > 0) ss << ' ';
        ss << hex[bytes[i] >> 4] << hex[bytes[i] & 0x0F];
    }
    if (size > max_bytes) {
        ss << "\n... [" << (size - max_bytes) << " more 64KiB-aligned BVL3 encrypted bytes]";
    }
    return ss.str();
}

std::string GatewayEngine::format_hex_dump(const std::vector<uint8_t>& bytes, std::size_t max_bytes) {
    return format_hex_dump(bytes.data(), bytes.size(), max_bytes);
}

} // namespace vault_gateway
