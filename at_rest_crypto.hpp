#pragma once
// Client-side zero-knowledge encryption (AES-256-GCM) for data at rest.
// Wire/Disk Envelope format:
//   [4 bytes: "BVLT"] [12 bytes: GCM IV] [16 bytes: GCM Auth Tag] [N bytes: Ciphertext]

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace vault_crypto {

inline constexpr std::array<uint8_t, 4> MAGIC = {'B', 'V', 'L', 'T'};
inline constexpr std::size_t KEY_LEN = 32; // 256-bit AES key
inline constexpr std::size_t IV_LEN  = 12; // 96-bit GCM nonce
inline constexpr std::size_t TAG_LEN = 16; // 128-bit GCM authentication tag
inline constexpr std::size_t HEADER_LEN = MAGIC.size() + IV_LEN + TAG_LEN; // 32 bytes

using Key = std::array<uint8_t, KEY_LEN>;

inline Key generate_key() {
    Key key{};
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        throw std::runtime_error("vault_crypto: RAND_bytes failed while generating AES-256 key");
    }
    return key;
}

inline std::string key_to_hex(const Key& key) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(KEY_LEN * 2);
    for (uint8_t b : key) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0F]);
    }
    return out;
}

inline Key hex_to_key(const std::string& hex_str) {
    if (hex_str.size() != KEY_LEN * 2) {
        throw std::runtime_error("vault_crypto: invalid AES key hex length");
    }
    auto nibble = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
        throw std::runtime_error("vault_crypto: invalid hex character in key");
    };
    Key key{};
    for (std::size_t i = 0; i < KEY_LEN; ++i) {
        key[i] = static_cast<uint8_t>((nibble(hex_str[i * 2]) << 4) | nibble(hex_str[i * 2 + 1]));
    }
    return key;
}

// Encrypts plaintext into the self-contained 32-byte header + ciphertext envelope
inline std::vector<uint8_t> encrypt_envelope(const uint8_t* plaintext, std::size_t plaintext_len, const Key& key) {
    std::array<uint8_t, IV_LEN> iv{};
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        throw std::runtime_error("vault_crypto: RAND_bytes failed for GCM IV");
    }

    using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    CipherCtx ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("vault_crypto: failed to allocate EVP_CIPHER_CTX");

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IV_LEN), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw std::runtime_error("vault_crypto: AES-256-GCM init failed");
    }

    std::vector<uint8_t> out(HEADER_LEN + plaintext_len);
    std::memcpy(out.data(), MAGIC.data(), MAGIC.size());
    std::memcpy(out.data() + MAGIC.size(), iv.data(), IV_LEN);

    int out_len = 0;
    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx.get(),
                              out.data() + HEADER_LEN, &out_len,
                              plaintext, static_cast<int>(plaintext_len)) != 1) {
            throw std::runtime_error("vault_crypto: AES-256-GCM encrypt update failed");
        }
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + HEADER_LEN + out_len, &final_len) != 1) {
        throw std::runtime_error("vault_crypto: AES-256-GCM encrypt final failed");
    }
    out.resize(HEADER_LEN + static_cast<std::size_t>(out_len + final_len));

    // Write the 16-byte authentication tag right after the IV
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(TAG_LEN),
                            out.data() + MAGIC.size() + IV_LEN) != 1) {
        throw std::runtime_error("vault_crypto: failed to extract GCM tag");
    }

    return out;
}

inline std::vector<uint8_t> encrypt_envelope(const std::string& plaintext, const Key& key) {
    return encrypt_envelope(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(), key);
}

// Verifies the GCM tag and decrypts the envelope back to plaintext
inline std::vector<uint8_t> decrypt_envelope(const uint8_t* envelope, std::size_t envelope_len, const Key& key) {
    if (envelope_len < HEADER_LEN || std::memcmp(envelope, MAGIC.data(), MAGIC.size()) != 0) {
        throw std::runtime_error("vault_crypto: invalid or truncated encrypted envelope");
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
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv_ptr) != 1) {
        throw std::runtime_error("vault_crypto: AES-256-GCM decrypt init failed");
    }

    std::vector<uint8_t> plaintext(ct_len);
    int out_len = 0;
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len, ct_ptr, static_cast<int>(ct_len)) != 1) {
            throw std::runtime_error("vault_crypto: AES-256-GCM decrypt update failed");
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(TAG_LEN),
                            const_cast<uint8_t*>(tag_ptr)) != 1) {
        throw std::runtime_error("vault_crypto: failed to set expected GCM tag");
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len, &final_len) != 1) {
        throw std::runtime_error("vault_crypto: GCM authentication failed (ciphertext tampered or wrong key)");
    }

    plaintext.resize(static_cast<std::size_t>(out_len + final_len));
    return plaintext;
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