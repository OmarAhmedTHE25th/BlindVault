#pragma once
// Pluggable 2-of-3 Erasure Shard Storage Backend Interface & Local Filesystem Implementation.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

namespace vault_gateway {

class ErasureShardBackend {
public:
    virtual ~ErasureShardBackend() = default;

    virtual void write_shard(const std::filesystem::path& blob_name,
                             std::size_t shard_index,
                             const std::vector<uint8_t>& shard) = 0;

    virtual std::optional<std::vector<uint8_t>> read_shard(
        const std::filesystem::path& blob_name,
        std::size_t shard_index) = 0;
};

class LocalErasureShardBackend final : public ErasureShardBackend {
public:
    explicit LocalErasureShardBackend(std::filesystem::path shard_dir);

    void write_shard(const std::filesystem::path& blob_name,
                     std::size_t shard_index,
                     const std::vector<uint8_t>& shard) override;

    std::optional<std::vector<uint8_t>> read_shard(
        const std::filesystem::path& blob_name,
        std::size_t shard_index) override;

private:
    std::filesystem::path shard_dir_;
};

} // namespace vault_gateway
