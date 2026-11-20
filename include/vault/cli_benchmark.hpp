#pragma once

#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "at_rest_crypto.hpp"
#include "vault_gateway.hpp"
#include "vault_index.hpp"

namespace cli_bench {

inline int run(std::size_t rows = 10000) {
    namespace fs = std::filesystem;
    using Clock = std::chrono::steady_clock;

    std::random_device rd;
    const fs::path work_dir = fs::temp_directory_path() /
                              ("blindvault_cli_bench_" + std::to_string(rd()));
    fs::create_directories(work_dir);

    struct Cleanup {
        fs::path dir;
        ~Cleanup() {
            std::error_code ec;
            fs::remove_all(dir, ec);
        }
    } cleanup{work_dir};

    const fs::path state_dir = work_dir / "gateway_state";
    const fs::path cloud_dir = work_dir / "cloud_bucket";
    const fs::path keys_dir  = work_dir / "offline_officers";
    fs::create_directories(cloud_dir);

    vault_gateway::GatewayEngine engine(state_dir, /*quorum_threshold=*/2);

    // 1. Setup 2-of-3 Ed25519 Compliance Officers (public keys installed on Gateway)
    for (const std::string id : {"Officer-1", "Officer-2", "Officer-3"}) {
        const auto priv = keys_dir / (id + ".priv");
        const auto pub  = engine.officer_pubkey_directory() / (id + ".pub");
        vault_index::generate_officer_ed25519_keypair(priv, pub);
    }

    // 2. Generate synthetic CBE batch
    const auto t_gen0 = Clock::now();
    const fs::path csv_path = engine.generate_synthetic_cbe_batch(rows);
    const auto t_gen1 = Clock::now();
    const double gen_ms = std::chrono::duration<double, std::milli>(t_gen1 - t_gen0).count();
    const uint64_t raw_bytes = fs::file_size(csv_path);

    // 3. Full Egress Pipeline (Tokenize + 64KiB Pad + AES-256-GCM + RFC3394 Wrap + 2-of-3 Shards + Index)
    const auto artifact = engine.prepare_encrypted_offload(csv_path);
    fs::copy_file(artifact.encrypted_file_path, cloud_dir / artifact.blob_name);

    // 4. 2-of-3 Quorum Auditor Lookup & Re-Hydration
    const std::string target_customer = "Ahmed Hassan";
    const auto challenge = engine.prepare_release_challenge(target_customer);
    std::vector<vault_index::OfficerApproval> approvals;
    if (!challenge.candidate_blobs.empty()) {
        const auto& blob = challenge.candidate_blobs.front();
        for (const std::string id : {"Officer-1", "Officer-2"}) {
            const std::string sig = vault_index::sign_blob_release_offline(
                keys_dir / (id + ".priv"), id, challenge.target_token,
                blob.blob_name, blob.wrapped_dek_hex);
            approvals.push_back({id, sig});
        }
    }

    const auto t_aud0 = Clock::now();
    const auto query_res = engine.auditor_query(target_customer, cloud_dir, approvals, "Bench-Auditor");
    const auto t_aud1 = Clock::now();
    const double audit_ms = std::chrono::duration<double, std::milli>(t_aud1 - t_aud0).count();

    if (!query_res.authorized || !query_res.found) {
        throw std::runtime_error("Benchmark verification failed during quorum auditor query");
    }

    const double egress_mb_s = (artifact.elapsed_ms > 0.0)
        ? (static_cast<double>(raw_bytes) / (1024.0 * 1024.0)) / (artifact.elapsed_ms / 1000.0)
        : 0.0;

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "=== BlindVault Standalone Pipeline Benchmark (" << rows << " records) ===\n"
              << "  Raw CSV Size:          " << (static_cast<double>(raw_bytes) / 1024.0) << " KiB\n"
              << "  64KiB-Padded BVL2:     " << (static_cast<double>(artifact.padded_size_bytes) / 1024.0)
              << " KiB (3x shards @ " << (static_cast<double>(artifact.erasure_shard_bytes) / 1024.0) << " KiB)\n"
              << "  Synthetic CSV Gen:     " << gen_ms << " ms\n"
              << "  Full Egress Offload:   " << artifact.elapsed_ms << " ms  ("
              << std::setprecision(0) << artifact.records_per_sec << " rec/s, "
              << std::setprecision(2) << egress_mb_s << " MiB/s)\n"
              << "  2-of-3 Quorum Audit:   " << audit_ms << " ms  (Ed25519 verify + RFC3394 unwrap + GCM decrypt + rehydrate)\n"
              << "  Audit Hash Chain:      " << (engine.metadata_index().verify_audit_chain() ? "VERIFIED" : "FAILED") << "\n";
    return 0;
}

} // namespace cli_bench