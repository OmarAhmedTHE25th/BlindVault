#pragma once
// Hardened Zero-Knowledge At-Rest Cryptography (v3.0):
//   1. Move-only RAII SecretKey & SecretBuffer (OPENSSL_cleanse on move/destroy)
//   2. Owner-only (0600) secret file writer & RLIMIT_CORE=0 process memory lock
//   3. Fixed-Bucket Traffic-Analysis Padding (64 KiB block alignment)
//   4. Authenticated AES-256-GCM ("BVL2" legacy + "BVL3" streaming chunked AEAD)
//   5. RFC 3394 AES-256 Key Wrapping (DEK wrapped under Master KEK)
//   6. 2-of-3 XOR Erasure Coding Shards

#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <streambuf>
#include <string>
#include <string_view>
#include <vector>
#include <openssl/crypto.h>

#ifndef _WIN32
#include <sys/types.h>
#endif

namespace vault_crypto {

inline constexpr std::array<uint8_t, 4> MAGIC      = {'B', 'V', 'L', '2'};
inline constexpr std::array<uint8_t, 4> MAGIC_BVL3 = {'B', 'V', 'L', '3'};
inline constexpr std::size_t KEY_LEN               = 32;     // 256-bit AES key
inline constexpr std::size_t WRAPPED_KEY_LEN       = 40;     // RFC 3394 wraps 32B -> 40B
inline constexpr std::size_t IV_LEN                = 12;     // 96-bit GCM nonce
inline constexpr std::size_t TAG_LEN               = 16;     // 128-bit GCM auth tag
inline constexpr std::size_t HEADER_LEN            = MAGIC.size() + IV_LEN + TAG_LEN; // 32 bytes
inline constexpr std::size_t BUCKET_ALIGN          = 65536;  // 64 KiB traffic-analysis padding

// BVL3 streaming chunked AEAD layout constants
inline constexpr std::size_t BVL3_HEADER_LEN       = 32;     // 4B magic + 12B base_iv + 4B chunk_size + 12B reserved
inline constexpr std::size_t BVL3_FRAME_BYTES      = 65536;  // Exact 64 KiB per frame on disk/wire
inline constexpr std::size_t BVL3_FRAME_CT_BYTES   = BVL3_FRAME_BYTES - TAG_LEN; // 65520 bytes ciphertext
inline constexpr std::size_t BVL3_MAX_CHUNK_PLAIN  = BVL3_FRAME_CT_BYTES - 4;   // 65516 bytes payload + 4B length prefix

void harden_process_memory();

// Move-only RAII 256-bit key: cannot be accidentally copied in RAM; wipes itself via OPENSSL_cleanse
struct SecretKey {
    std::array<uint8_t, KEY_LEN> bytes{};

    SecretKey() = default;
    ~SecretKey() { cleanse(); }

    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;

    SecretKey(SecretKey&& other) noexcept : bytes(other.bytes) {
        other.cleanse();
    }
    SecretKey& operator=(SecretKey&& other) noexcept {
        if (this != &other) {
            cleanse();
            bytes = other.bytes;
            other.cleanse();
        }
        return *this;
    }

    void cleanse() noexcept {
        OPENSSL_cleanse(bytes.data(), bytes.size());
    }

    uint8_t* data() noexcept { return bytes.data(); }
    [[nodiscard]] const uint8_t* data() const noexcept { return bytes.data(); }
    static constexpr std::size_t size() noexcept { return KEY_LEN; }

    bool operator==(const SecretKey& o) const noexcept {
        return CRYPTO_memcmp(bytes.data(), o.bytes.data(), KEY_LEN) == 0;
    }
};

// Move-only RAII buffer that wipes decrypted plaintext from RAM when destroyed
class SecretBuffer {
public:
    SecretBuffer() = default;
    explicit SecretBuffer(std::size_t n) : data_(n) {}
    ~SecretBuffer() { cleanse(); }

    SecretBuffer(const SecretBuffer&) = delete;
    SecretBuffer& operator=(const SecretBuffer&) = delete;

    SecretBuffer(SecretBuffer&& other) noexcept : data_(std::move(other.data_)) {}
    SecretBuffer& operator=(SecretBuffer&& other) noexcept {
        if (this != &other) {
            cleanse();
            data_ = std::move(other.data_);
        }
        return *this;
    }

    void cleanse() noexcept {
        if (!data_.empty()) {
            OPENSSL_cleanse(data_.data(), data_.size());
        }
    }

    std::vector<uint8_t>& vec() noexcept { return data_; }
    [[nodiscard]] const std::vector<uint8_t>& vec() const noexcept { return data_; }
    [[nodiscard]] std::string as_string() const {
        return std::string(reinterpret_cast<const char*>(data_.data()), data_.size());
    }

private:
    std::vector<uint8_t> data_;
};

SecretKey generate_key();
std::string bytes_to_hex(const uint8_t* data, std::size_t len);
std::vector<uint8_t> hex_to_bytes(const std::string& hex_str);
void write_secret_file_0600(const std::filesystem::path& path, const std::string& content);

#ifndef _WIN32
namespace detail {

struct PosixFileOps {
    int (*open_fn)(const char* path, int flags, unsigned int mode) = nullptr;
    ssize_t (*write_fn)(int fd, const void* buf, std::size_t count) = nullptr;
    int (*fsync_fn)(int fd) = nullptr;
    int (*close_fn)(int fd) = nullptr;
    int (*rename_fn)(const char* oldpath, const char* newpath) = nullptr;
    int (*unlink_fn)(const char* path) = nullptr;
};

PosixFileOps default_posix_file_ops() noexcept;
void write_secret_file_0600_posix(const std::filesystem::path& path,
                                  const std::string& content,
                                  const PosixFileOps& ops);

} // namespace detail
#endif
std::string hmac_sha256_hex(const uint8_t* key, std::size_t key_len, std::string_view message);
SecretKey derive_subkey(const SecretKey& master_key, std::string_view context_label);
bool constant_time_hex_equal(const std::string& hex_a, const std::string& hex_b);

std::string wrap_dek_hex(const SecretKey& dek, const SecretKey& master_kek);
SecretKey unwrap_dek_hex(const std::string& wrapped_hex, const SecretKey& master_kek);

SecretBuffer pad_to_bucket(const uint8_t* plaintext, std::size_t len, std::size_t align = BUCKET_ALIGN);
SecretBuffer unpad_from_bucket(const SecretBuffer& padded);

// Legacy BVL2 single-shot envelopes (used for small payloads, BVTK tokens, and backward compatibility)
std::vector<uint8_t> encrypt_envelope(const uint8_t* plaintext, std::size_t plaintext_len,
                                      const SecretKey& dek, bool pad_traffic = true,
                                      std::string_view aad = {});
std::vector<uint8_t> encrypt_envelope(const std::string& plaintext, const SecretKey& dek,
                                      bool pad_traffic = true, std::string_view aad = {});
SecretBuffer decrypt_envelope(const uint8_t* envelope, std::size_t envelope_len,
                              const SecretKey& dek, bool unpad_traffic = true,
                              std::string_view aad = {});

// Streaming O(1)-RAM BVL3 Chunked AEAD Encryptor
class Bvl3StreamEncryptor {
public:
    Bvl3StreamEncryptor(std::ostream& out, const SecretKey& dek, std::string_view blob_name);
    ~Bvl3StreamEncryptor();

    Bvl3StreamEncryptor(const Bvl3StreamEncryptor&) = delete;
    Bvl3StreamEncryptor& operator=(const Bvl3StreamEncryptor&) = delete;

    void write(const uint8_t* data, std::size_t len);
    // Finalizes stream with a CSPRNG-padded terminal frame (is_final=1) and returns total written bytes
    std::size_t finalize();

private:
    void flush_frame(const uint8_t* chunk_data, std::size_t chunk_len, bool is_final);

    std::ostream& out_;
    SecretKey dek_;
    std::string blob_name_;
    std::array<uint8_t, IV_LEN> base_iv_{};
    SecretBuffer pending_;
    std::vector<uint8_t> frame_buf_;
    uint64_t chunk_index_ = 0;
    std::size_t total_written_ = 0;
    bool finalized_ = false;
};

// Adapts Bvl3StreamEncryptor into a std::streambuf so std::ostream streams straight to BVL3 in O(1) RAM
class Bvl3EncryptingStreamBuf final : public std::streambuf {
public:
    Bvl3EncryptingStreamBuf(std::ostream& out, const SecretKey& dek, std::string_view blob_name);

    std::size_t finalize();

protected:
    int_type overflow(int_type ch) override;
    std::streamsize xsputn(const char* s, std::streamsize count) override;

private:
    Bvl3StreamEncryptor encryptor_;
};

std::size_t encrypt_stream_bvl3(std::istream& in, std::ostream& out,
                                const SecretKey& dek, std::string_view blob_name);

void decrypt_stream_bvl3(std::istream& in, std::size_t total_len,
                         const SecretKey& dek, std::string_view blob_name,
                         const std::function<void(std::string_view)>& on_chunk);

// Auto-detects BVL3 (streaming chunked) vs BVL2 (legacy monolithic)
void decrypt_stream_auto(std::istream& in, std::size_t total_len,
                         const SecretKey& dek, std::string_view blob_name,
                         const std::function<void(std::string_view)>& on_chunk);

std::array<std::vector<uint8_t>, 3> erasure_split_2of3(const std::vector<uint8_t>& blob);
std::vector<uint8_t> erasure_reconstruct_2of3(const std::vector<uint8_t>& s0,
                                              const std::vector<uint8_t>& s1,
                                              const std::vector<uint8_t>& s2,
                                              std::size_t original_size);

void write_bytes_to_file(const std::string& path, const std::vector<uint8_t>& data);
std::vector<uint8_t> read_bytes_from_file(const std::string& path);

} // namespace vault_crypto
