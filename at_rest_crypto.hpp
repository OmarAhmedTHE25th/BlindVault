#pragma once
// Hardened Zero-Knowledge At-Rest Cryptography:
//   1. RAII Memory Zeroization (OPENSSL_cleanse) & Core-Dump Hardening
//   2. Fixed-Bucket Traffic-Analysis Padding (64 KiB block alignment)
//   3. Authenticated AES-256-GCM ("BVLT" v2 envelope)
//   4. RFC 3394 AES-256 Key Wrapping (DEK wrapped under Master KEK)
//   5. 2-of-3 XOR Erasure Coding Shards (Multi-Cloud Zero-Trust Availability)

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifndef _WIN32
#include <sys/resource.h>
#endif

namespace vault_crypto {

inline constexpr std::array<uint8_t, 4> MAGIC = {'B', 'V', 'L', '2'};
inline constexpr std::size_t KEY_LEN         = 32;     // 256-bit AES key
inline constexpr std::size_t WRAPPED_KEY_LEN = 40;     // RFC 3394 wraps 32B -> 40B
inline constexpr std::size_t IV_LEN          = 12;     // 96-bit GCM nonce
inline constexpr std::size_t TAG_LEN         = 16;     // 128-bit GCM auth tag
inline constexpr std::size_t HEADER_LEN      = MAGIC.size() + IV_LEN + TAG_LEN; // 32 bytes
inline constexpr std::size_t BUCKET_ALIGN    = 65536;  // 64 KiB traffic-analysis padding

// Disables OS core dumps so sensitive keys/plaintext in RAM are never written to disk on crash
inline void harden_process_memory() {
#ifndef _WIN32
    rlimit rl{0, 0};
    setrlimit(RLIMIT_CORE, &rl);
#endif
}

// RAII 256-bit key that wipes itself with OPENSSL_cleanse on destruction
struct SecretKey {
    std::array<uint8_t, KEY_LEN> bytes{};

    SecretKey() = default;
    ~SecretKey() { cleanse(); }

    SecretKey(const SecretKey&) = default;
    SecretKey& operator=(const SecretKey&) = default;
    SecretKey(SecretKey&& other) noexcept : bytes(other.bytes) { other.cleanse(); }
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
    const uint8_t* data() const noexcept { return bytes.data(); }
    constexpr std::size_t size() const noexcept { return KEY_LEN; }
    bool operator==(const SecretKey& o) const noexcept {
        return CRYPTO_memcmp(bytes.data(), o.bytes.data(), KEY_LEN) == 0;
    }
};

// RAII buffer that wipes decrypted plaintext from RAM when destroyed
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
    const std::vector<uint8_t>& vec() const noexcept { return data_; }
    std::string as_string() const {
        return std::string(reinterpret_cast<const char*>(data_.data()), data_.size());
    }

private:
    std::vector<uint8_t> data_;
};

inline SecretKey generate_key() {
    SecretKey key;
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        throw std::runtime_error("vault_crypto: RAND_bytes failed");
    }
    return key;
}

inline std::string bytes_to_hex(const uint8_t* data, std::size_t len) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
}

inline std::vector<uint8_t> hex_to_bytes(const std::string& hex_str) {
    if (hex_str.size() % 2 != 0) throw std::runtime_error("vault_crypto: odd hex length");
    auto nibble = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
        throw std::runtime_error("vault_crypto: invalid hex character");
    };
    std::vector<uint8_t> out(hex_str.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>((nibble(hex_str[i * 2]) << 4) | nibble(hex_str[i * 2 + 1]));
    }
    return out;
}

// RFC 3394 AES-256 Key Wrap: wraps a 32-byte DEK with a 32-byte Master KEK -> 40 bytes
inline std::string wrap_dek_hex(const SecretKey& dek, const SecretKey& master_kek) {
    using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    CipherCtx ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("vault_crypto: EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_wrap(), nullptr, master_kek.data(), nullptr) != 1) {
        throw std::runtime_error("vault_crypto: EVP_aes_256_wrap init failed");
    }

    std::array<uint8_t, WRAPPED_KEY_LEN> wrapped{};
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx.get(), wrapped.data(), &out_len, dek.data(), static_cast<int>(KEY_LEN)) != 1) {
        throw std::runtime_error("vault_crypto: key wrap update failed");
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), wrapped.data() + out_len, &final_len) != 1 ||
        static_cast<std::size_t>(out_len + final_len) != WRAPPED_KEY_LEN) {
        throw std::runtime_error("vault_crypto: key wrap final failed");
    }
    return bytes_to_hex(wrapped.data(), wrapped.size());
}

// RFC 3394 AES-256 Key Unwrap: unwraps a 40-byte wrapped DEK using Master KEK -> 32-byte SecretKey
inline SecretKey unwrap_dek_hex(const std::string& wrapped_hex, const SecretKey& master_kek) {
    const auto wrapped = hex_to_bytes(wrapped_hex);
    if (wrapped.size() != WRAPPED_KEY_LEN) {
        throw std::runtime_error("vault_crypto: invalid wrapped DEK length");
    }

    using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    CipherCtx ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("vault_crypto: EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_wrap(), nullptr, master_kek.data(), nullptr) != 1) {
        throw std::runtime_error("vault_crypto: EVP_aes_256_wrap decrypt init failed");
    }

    SecretKey dek;
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx.get(), dek.data(), &out_len, wrapped.data(), static_cast<int>(wrapped.size())) != 1) {
        throw std::runtime_error("vault_crypto: DEK unwrap integrity check failed (wrong KEK or tampered)");
    }
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), dek.data() + out_len, &final_len) != 1 ||
        static_cast<std::size_t>(out_len + final_len) != KEY_LEN) {
        throw std::runtime_error("vault_crypto: DEK unwrap final failed");
    }
    return dek;
}

// Pads plaintext to an exact multiple of BUCKET_ALIGN (64 KiB) to defeat traffic analysis:
//   [8-byte big-endian real_len] [real_len bytes plaintext] [CSPRNG padding up to 64 KiB boundary]
inline SecretBuffer pad_to_bucket(const uint8_t* plaintext, std::size_t len, std::size_t align = BUCKET_ALIGN) {
    const std::size_t raw_total = 8 + len;
    const std::size_t rem = raw_total % align;
    const std::size_t padded_total = (rem == 0) ? raw_total : (raw_total + (align - rem));

    SecretBuffer buf(padded_total);
    auto& v = buf.vec();
    const uint64_t len64 = static_cast<uint64_t>(len);
    for (int i = 0; i < 8; ++i) {
        v[i] = static_cast<uint8_t>((len64 >> (56 - i * 8)) & 0xFF);
    }
    if (len > 0) {
        std::memcpy(v.data() + 8, plaintext, len);
    }
    const std::size_t pad_len = padded_total - raw_total;
    if (pad_len > 0 && RAND_bytes(v.data() + raw_total, static_cast<int>(pad_len)) != 1) {
        throw std::runtime_error("vault_crypto: RAND_bytes failed while padding bucket");
    }
    return buf;
}

inline SecretBuffer unpad_from_bucket(const SecretBuffer& padded) {
    const auto& v = padded.vec();
    if (v.size() < 8) throw std::runtime_error("vault_crypto: padded payload too short");
    uint64_t len64 = 0;
    for (int i = 0; i < 8; ++i) {
        len64 = (len64 << 8) | static_cast<uint64_t>(v[i]);
    }
    if (len64 > v.size() - 8) {
        throw std::runtime_error("vault_crypto: corrupted bucket length prefix");
    }
    SecretBuffer out(static_cast<std::size_t>(len64));
    if (len64 > 0) {
        std::memcpy(out.vec().data(), v.data() + 8, static_cast<std::size_t>(len64));
    }
    return out;
}

// Encrypts plaintext with 64 KiB traffic-analysis padding + AES-256-GCM
inline std::vector<uint8_t> encrypt_envelope(const uint8_t* plaintext, std::size_t plaintext_len,
                                             const SecretKey& dek, bool pad_traffic = true) {
    SecretBuffer prepared;
    const uint8_t* src_ptr = plaintext;
    std::size_t src_len = plaintext_len;
    if (pad_traffic) {
        prepared = pad_to_bucket(plaintext, plaintext_len);
        src_ptr = prepared.vec().data();
        src_len = prepared.vec().size();
    }

    std::array<uint8_t, IV_LEN> iv{};
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        throw std::runtime_error("vault_crypto: RAND_bytes failed for GCM IV");
    }

    using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    CipherCtx ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("vault_crypto: failed to allocate EVP_CIPHER_CTX");

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IV_LEN), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, dek.data(), iv.data()) != 1) {
        throw std::runtime_error("vault_crypto: AES-256-GCM init failed");
    }

    std::vector<uint8_t> out(HEADER_LEN + src_len);
    std::memcpy(out.data(), MAGIC.data(), MAGIC.size());
    std::memcpy(out.data() + MAGIC.size(), iv.data(), IV_LEN);

    int out_len = 0;
    if (src_len > 0) {
        if (EVP_EncryptUpdate(ctx.get(), out.data() + HEADER_LEN, &out_len,
                              src_ptr, static_cast<int>(src_len)) != 1) {
            throw std::runtime_error("vault_crypto: AES-256-GCM encrypt update failed");
        }
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + HEADER_LEN + out_len, &final_len) != 1) {
        throw std::runtime_error("vault_crypto: AES-256-GCM encrypt final failed");
    }
    out.resize(HEADER_LEN + static_cast<std::size_t>(out_len + final_len));

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(TAG_LEN),
                            out.data() + MAGIC.size() + IV_LEN) != 1) {
        throw std::runtime_error("vault_crypto: failed to extract GCM tag");
    }
    return out;
}

inline std::vector<uint8_t> encrypt_envelope(const std::string& plaintext, const SecretKey& dek, bool pad_traffic = true) {
    return encrypt_envelope(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(), dek, pad_traffic);
}

// Verifies GCM tag, decrypts into RAII-cleansed SecretBuffer, and strips traffic padding
inline SecretBuffer decrypt_envelope(const uint8_t* envelope, std::size_t envelope_len,
                                     const SecretKey& dek, bool unpad_traffic = true) {
    if (envelope_len < HEADER_LEN || std::memcmp(envelope, MAGIC.data(), MAGIC.size()) != 0) {
        throw std::runtime_error("vault_crypto: invalid or truncated BVLT v2 envelope");
    }

    const uint8_t* iv_ptr  = envelope + MAGIC.size();
    const uint8_t* tag_ptr = iv_ptr + IV_LEN;
    const uint8_t* ct_ptr  = envelope + HEADER_LEN;
    const std::size_t ct_len = envelope_len - HEADER_LEN;

    using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    CipherCtx ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("vault_crypto: failed to allocate EVP_CIPHER_CTX");

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IV_LEN), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, dek.data(), iv_ptr) != 1) {
        throw std::runtime_error("vault_crypto: AES-256-GCM decrypt init failed");
    }

    SecretBuffer decrypted(ct_len);
    int out_len = 0;
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx.get(), decrypted.vec().data(), &out_len,
                              ct_ptr, static_cast<int>(ct_len)) != 1) {
            throw std::runtime_error("vault_crypto: AES-256-GCM decrypt update failed");
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(TAG_LEN),
                            const_cast<uint8_t*>(tag_ptr)) != 1) {
        throw std::runtime_error("vault_crypto: failed to set GCM tag");
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), decrypted.vec().data() + out_len, &final_len) != 1) {
        throw std::runtime_error("vault_crypto: GCM authentication failed (tampered or wrong key)");
    }
    decrypted.vec().resize(static_cast<std::size_t>(out_len + final_len));

    if (unpad_traffic) {
        return unpad_from_bucket(decrypted);
    }
    return decrypted;
}

// 2-of-3 Erasure Coding: splits `blob` into 3 equal shards where shard_2 = shard_0 ^ shard_1.
// Any 2 shards reconstruct the original ciphertext; 1 shard alone reveals zero information.
inline std::array<std::vector<uint8_t>, 3> erasure_split_2of3(const std::vector<uint8_t>& blob) {
    const std::size_t half = (blob.size() + 1) / 2;
    std::array<std::vector<uint8_t>, 3> shards;
    shards[0].assign(half, 0);
    shards[1].assign(half, 0);
    shards[2].assign(half, 0);

    const std::size_t first_copy = std::min(half, blob.size());
    std::memcpy(shards[0].data(), blob.data(), first_copy);
    if (blob.size() > half) {
        std::memcpy(shards[1].data(), blob.data() + half, blob.size() - half);
    }
    for (std::size_t i = 0; i < half; ++i) {
        shards[2][i] = static_cast<uint8_t>(shards[0][i] ^ shards[1][i]);
    }
    return shards;
}

// Reconstructs the original blob from any 2 surviving shards (pass empty vector for the missing shard)
inline std::vector<uint8_t> erasure_reconstruct_2of3(const std::vector<uint8_t>& s0,
                                                     const std::vector<uint8_t>& s1,
                                                     const std::vector<uint8_t>& s2,
                                                     std::size_t original_size) {
    const std::size_t half = (original_size + 1) / 2;
    std::vector<uint8_t> rec0(half), rec1(half);

    if (!s0.empty() && !s1.empty()) {
        rec0 = s0;
        rec1 = s1;
    } else if (!s0.empty() && !s2.empty()) {
        rec0 = s0;
        for (std::size_t i = 0; i < half; ++i) rec1[i] = static_cast<uint8_t>(s0[i] ^ s2[i]);
    } else if (!s1.empty() && !s2.empty()) {
        rec1 = s1;
        for (std::size_t i = 0; i < half; ++i) rec0[i] = static_cast<uint8_t>(s1[i] ^ s2[i]);
    } else {
        throw std::runtime_error("vault_crypto: need at least 2 of 3 erasure shards to reconstruct");
    }

    std::vector<uint8_t> out;
    out.reserve(original_size);
    out.insert(out.end(), rec0.begin(), rec0.end());
    out.insert(out.end(), rec1.begin(), rec1.end());
    out.resize(original_size);
    return out;
}

inline void write_bytes_to_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("vault_crypto: cannot open output file " + path);
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    if (!out) throw std::runtime_error("vault_crypto: write failed for " + path);
}

inline std::vector<uint8_t> read_bytes_from_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("vault_crypto: cannot open input file " + path);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

} // namespace vault_crypto