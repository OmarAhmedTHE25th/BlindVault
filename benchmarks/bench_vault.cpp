#include <benchmark/benchmark.h>
#include <chrono>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "at_rest_crypto.hpp"
#include "kms_provider.hpp"
#include "tokenizer.hpp"
#include "vault_gateway.hpp"

namespace fs = std::filesystem;

namespace {

class TempBenchDir {
public:
    explicit TempBenchDir(const std::string& tag) {
        std::random_device rd;
        path_ = fs::temp_directory_path() / ("bv_bench_" + tag + "_" + std::to_string(rd()));
        fs::create_directories(path_);
    }
    ~TempBenchDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    const fs::path& path() const noexcept { return path_; }

private:
    fs::path path_;
};

// In-memory shard sink so microbenchmarks can isolate CPU/crypto from disk I/O if desired
class NullShardBackend final : public vault_gateway::ErasureShardBackend {
public:
    void write_shard(const fs::path&, std::size_t, const std::vector<uint8_t>&) override {}
};

std::string make_synthetic_csv_string(std::size_t rows) {
    TempBenchDir tmp("seed");
    vault_gateway::GatewayEngine engine(tmp.path(), 2, nullptr, std::make_shared<NullShardBackend>());
    const fs::path csv_path = engine.generate_synthetic_cbe_batch(rows);
    std::ifstream in(csv_path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

} // namespace

// 1. TokenVault RFC 4180 CSV Sanitization + HMAC-SHA256 PII Tokenization
static void BM_TokenizeCsvBatch(benchmark::State& state) {
    const auto rows = static_cast<std::size_t>(state.range(0));
    const std::string raw_csv = make_synthetic_csv_string(rows);
    TempBenchDir dir("tok");
    auto kms = std::make_shared<vault_kms::LocalSoftwareKmsProvider>(dir.path() / "master.kek");

    for (auto _ : state) {
        state.PauseTiming();
        const fs::path tok_file = dir.path() / "vault_tokens.enc";
        std::error_code ec;
        fs::remove(tok_file, ec);
        vault_token::TokenVault vault(tok_file, kms);
        state.ResumeTiming();

        vault_token::SanitizeStats stats{};
        std::string out = vault.sanitize_csv_batch(raw_csv, &stats);
        benchmark::DoNotOptimize(out);
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations() * static_cast<int64_t>(rows));
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(raw_csv.size()));
}
BENCHMARK(BM_TokenizeCsvBatch)->Arg(1000)->Arg(10000)->Arg(50000)->Unit(benchmark::kMillisecond);

// 2. 64 KiB CSPRNG Bucket Padding + AES-256-GCM (BVL2 + AAD)
static void BM_EncryptEnvelope64KiB(benchmark::State& state) {
    const auto payload_bytes = static_cast<std::size_t>(state.range(0));
    std::string payload(payload_bytes, 'X');
    vault_crypto::SecretKey dek = vault_crypto::generate_key();

    for (auto _ : state) {
        auto env = vault_crypto::encrypt_envelope(payload, dek, /*pad_traffic=*/true, "vault_batch_bench.enc");
        benchmark::DoNotOptimize(env);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(payload_bytes));
}
BENCHMARK(BM_EncryptEnvelope64KiB)
    ->Arg(64 * 1024)
    ->Arg(512 * 1024)
    ->Arg(2 * 1024 * 1024)
    ->Unit(benchmark::kMicrosecond);

// 3. 2-of-3 XOR Erasure Coding Split
static void BM_ErasureSplit2of3(benchmark::State& state) {
    const auto blob_bytes = static_cast<std::size_t>(state.range(0));
    std::vector<uint8_t> blob(blob_bytes, 0xA5);

    for (auto _ : state) {
        auto shards = vault_crypto::erasure_split_2of3(blob);
        benchmark::DoNotOptimize(shards);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(blob_bytes));
}
BENCHMARK(BM_ErasureSplit2of3)
    ->Arg(256 * 1024)
    ->Arg(1024 * 1024)
    ->Arg(4 * 1024 * 1024)
    ->Unit(benchmark::kMicrosecond);

// 4. Full End-to-End Bank Egress Offload Pipeline (Disk + Crypto + Index + Audit Chain)
static void BM_EndToEndOffloadPipeline(benchmark::State& state) {
    const auto rows = static_cast<std::size_t>(state.range(0));
    TempBenchDir seed_dir("e2e_seed");
    vault_gateway::GatewayEngine seed_engine(seed_dir.path());
    const fs::path csv_path = seed_engine.generate_synthetic_cbe_batch(rows);
    const auto csv_size = static_cast<int64_t>(fs::file_size(csv_path));

    for (auto _ : state) {
        state.PauseTiming();
        TempBenchDir run_dir("e2e_run");
        vault_gateway::GatewayEngine engine(run_dir.path());
        state.ResumeTiming();

        auto artifact = engine.prepare_encrypted_offload(csv_path);
        benchmark::DoNotOptimize(artifact);
    }

    state.SetItemsProcessed(state.iterations() * static_cast<int64_t>(rows));
    state.SetBytesProcessed(state.iterations() * csv_size);
}
BENCHMARK(BM_EndToEndOffloadPipeline)->Arg(1000)->Arg(10000)->Unit(benchmark::kMillisecond);