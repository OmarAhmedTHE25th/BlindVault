#pragma once
// Multi-Bucket S3-Compatible 2-of-3 Erasure Shard Backend with AWS SigV4 Signing.
// Supports AWS S3, MinIO, Backblaze B2, and Cloudflare R2 over HTTP or HTTPS via Boost.Beast.

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include "erasure_shard_backend.hpp"

namespace vault_gateway {

struct S3BucketConfig {
    bool use_tls = true;
    std::string host;
    std::string port = "443";
    std::string bucket;
    std::string key_prefix;          // optional key prefix inside bucket (without leading/trailing '/')
    std::string region = "us-east-1";
    std::string access_key;
    std::string secret_key;
    std::string ca_file;             // optional custom CA bundle for private/self-signed S3 endpoints
    std::size_t timeout_ms = 5000;
};

struct AwsSigV4SignedHeaders {
    std::string host_header;
    std::string amz_date;
    std::string content_sha256_hex;
    std::string authorization;
    std::string canonical_uri;
};

// Parses an endpoint URL like "http://127.0.0.1:9000/blindvault-shard0" or
// "https://s3.us-east-1.amazonaws.com/my-bucket/optional-prefix" into S3BucketConfig
// (host, port, use_tls, bucket, key_prefix, optional embedded userinfo credentials).
S3BucketConfig parse_s3_endpoint_url(std::string_view url);

// Pure AWS Signature Version 4 signer ("AWS4-HMAC-SHA256") for S3 PUT/GET/HEAD requests.
AwsSigV4SignedHeaders sign_aws_v4(std::string_view method,
                                   const S3BucketConfig& config,
                                   std::string_view object_key,
                                   const std::vector<uint8_t>& body,
                                   std::string_view override_amz_date = {});

class S3MultiBucketShardBackend final : public ErasureShardBackend {
public:
    explicit S3MultiBucketShardBackend(std::array<S3BucketConfig, 3> buckets);

    void write_shard(const std::filesystem::path& blob_name,
                     std::size_t shard_index,
                     const std::vector<uint8_t>& shard) override;

    std::optional<std::vector<uint8_t>> read_shard(
        const std::filesystem::path& blob_name,
        std::size_t shard_index) override;

    bool head_shard(const std::filesystem::path& blob_name, std::size_t shard_index);

    const S3BucketConfig& bucket_config(std::size_t shard_index) const;

private:
    std::array<S3BucketConfig, 3> buckets_;
};

// Reads BLINDVAULT_SHARD0_URL, BLINDVAULT_SHARD1_URL, BLINDVAULT_SHARD2_URL from the
// environment. Returns nullptr if none are set; throws if partially configured or missing keys.
std::shared_ptr<S3MultiBucketShardBackend> create_s3_shard_backend_from_env();

} // namespace vault_gateway
