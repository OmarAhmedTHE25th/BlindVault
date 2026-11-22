#include "at_rest_crypto.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace vault_crypto {

namespace {

std::array<uint8_t, IV_LEN> derive_chunk_iv(const std::array<uint8_t, IV_LEN>& base_iv, uint64_t idx) {
    std::array<uint8_t, IV_LEN> iv = base_iv;
    for (int j = 0; j < 8; ++j) {
        iv[4 + j] ^= static_cast<uint8_t>((idx >> (56 - j * 8)) & 0xFF);
    }
    return iv;
}

std::vector<uint8_t> build_chunk_aad(std::string_view blob_name, uint64_t idx, bool is_final) {
    std::vector<uint8_t> aad;
    aad.reserve(blob_name.size() + 9);
    aad.insert(aad.end(),
               reinterpret_cast<const uint8_t*>(blob_name.data()),
               reinterpret_cast<const uint8_t*>(blob_name.data()) + blob_name.size());
    for (int j = 0; j < 8; ++j) {
        aad.push_back(static_cast<uint8_t>((idx >> (56 - j * 8)) & 0xFF));
    }
    aad.push_back(is_final ? 0x01 : 0x00);
    return aad;
}

void put_u32_be(uint8_t* dst, uint32_t v) {
    dst[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    dst[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    dst[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    dst[3] = static_cast<uint8_t>(v & 0xFF);
}

uint32_t get_u32_be(const uint8_t* src) {
    return (static_cast<uint32_t>(src[0]) << 24) |
           (static_cast<uint32_t>(src[1]) << 16) |
           (static_cast<uint32_t>(src[2]) << 8) |
           static_cast<uint32_t>(src[3]);
}

} // namespace

void harden_process_memory() {
#ifndef _WIN32
    rlimit rl{0, 0};
    setrlimit(RLIMIT_CORE, &rl);
#endif
}

SecretKey generate_key() {
    SecretKey key;
    if (RAND_bytes(key.data(), SecretKey::size()) != 1) {
        throw std::runtime_error("vault_crypto: RAND_bytes failed");
    }
    return key;
}

std::string bytes_to_hex(const uint8_t* data, std::size_t len) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex_str) {
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

#ifndef _WIN32
namespace detail {

namespace {

int default_open_wrapper(const char* path, int flags, unsigned int mode) {
    return ::open(path, flags, static_cast<mode_t>(mode));
}

ssize_t default_write_wrapper(int fd, const void* buf, std::size_t count) {
    return ::write(fd, buf, count);
}

int default_fsync_wrapper(int fd) {
    return ::fsync(fd);
}

int default_close_wrapper(int fd) {
    return ::close(fd);
}

int default_rename_wrapper(const char* oldpath, const char* newpath) {
    return ::rename(oldpath, newpath);
}

int default_unlink_wrapper(const char* path) {
    return ::unlink(path);
}

std::string make_temp_secret_path(const std::filesystem::path& target_path) {
    std::array<uint8_t, 8> rnd{};
    if (RAND_bytes(rnd.data(), static_cast<int>(rnd.size())) != 1) {
        throw std::runtime_error("vault_crypto: RAND_bytes failed while creating temp filename");
    }
    const std::filesystem::path dir =
        target_path.parent_path().empty() ? std::filesystem::path(".") : target_path.parent_path();
    const std::string name =
        "." + target_path.filename().string() + ".tmp." + bytes_to_hex(rnd.data(), rnd.size());
    return (dir / name).string();
}

std::string format_errno_msg(const char* step, const std::string& path_str, int err_num) {
    return std::string("vault_crypto: write_secret_file_0600 ") + step + " failed for '" +
           path_str + "' (errno=" + std::to_string(err_num) + ": " + std::strerror(err_num) + ")";
}

} // namespace

PosixFileOps default_posix_file_ops() noexcept {
    return PosixFileOps{
        &default_open_wrapper,
        &default_write_wrapper,
        &default_fsync_wrapper,
        &default_close_wrapper,
        &default_rename_wrapper,
        &default_unlink_wrapper
    };
}

void write_secret_file_0600_posix(const std::filesystem::path& path,
                                  const std::string& content,
                                  const PosixFileOps& ops) {
    if (!ops.open_fn || !ops.write_fn || !ops.fsync_fn ||
        !ops.close_fn || !ops.rename_fn || !ops.unlink_fn) {
        throw std::invalid_argument("vault_crypto: PosixFileOps contains a null function pointer");
    }

    int create_flags = O_CREAT | O_EXCL | O_WRONLY;
#ifdef O_NOFOLLOW
    create_flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    create_flags |= O_CLOEXEC;
#endif

    // 1. Atomically create an exclusive temporary file with 0600 permissions at creation time.
    int fd = -1;
    std::string tmp_str;
    int open_err = 0;
    constexpr int kMaxCreateAttempts = 16;
    for (int attempt = 0; attempt < kMaxCreateAttempts; ++attempt) {
        tmp_str = make_temp_secret_path(path);
        fd = ops.open_fn(tmp_str.c_str(), create_flags, 0600u);
        if (fd >= 0) {
            open_err = 0;
            break;
        }
        open_err = errno;
        if (open_err == EEXIST || open_err == EINTR) {
            continue;
        }
        throw std::runtime_error(format_errno_msg("open(O_CREAT|O_EXCL, 0600)", tmp_str, open_err));
    }
    if (fd < 0) {
        throw std::runtime_error(format_errno_msg("open(O_CREAT|O_EXCL, 0600)", tmp_str, open_err));
    }

    auto cleanup_fd_and_tmp = [&](int& open_fd) noexcept {
        if (open_fd >= 0) {
            (void)ops.close_fn(open_fd);
            open_fd = -1;
        }
        (void)ops.unlink_fn(tmp_str.c_str());
    };

    // 2. Write complete buffer, handling partial writes and EINTR without clobbering errors.
    std::size_t total_written = 0;
    while (total_written < content.size()) {
        const ssize_t written = ops.write_fn(
            fd, content.data() + total_written, content.size() - total_written);
        if (written < 0) {
            const int write_err = errno;
            if (write_err == EINTR) {
                continue;
            }
            cleanup_fd_and_tmp(fd);
            throw std::runtime_error(format_errno_msg("write", tmp_str, write_err));
        }
        if (written == 0) {
            const int write_zero_err = EIO;
            cleanup_fd_and_tmp(fd);
            throw std::runtime_error(format_errno_msg("write (zero-byte progress)", tmp_str, write_zero_err));
        }
        total_written += static_cast<std::size_t>(written);
    }

    // 3. Flush file data & metadata to stable storage prior to closing and renaming.
    for (;;) {
        if (ops.fsync_fn(fd) == 0) {
            break;
        }
        const int fsync_err = errno;
        if (fsync_err == EINTR) {
            continue;
        }
        cleanup_fd_and_tmp(fd);
        throw std::runtime_error(format_errno_msg("fsync(file)", tmp_str, fsync_err));
    }

    // 4. Explicitly check close() before rename so deferred I/O errors are never lost.
    const int close_rc = ops.close_fn(fd);
    fd = -1;
    if (close_rc != 0) {
        const int close_err = errno;
        (void)ops.unlink_fn(tmp_str.c_str());
        throw std::runtime_error(format_errno_msg("close(file)", tmp_str, close_err));
    }

    // 5. Atomically replace target path via rename().
    const std::string target_str = path.string();
    if (ops.rename_fn(tmp_str.c_str(), target_str.c_str()) != 0) {
        const int rename_err = errno;
        (void)ops.unlink_fn(tmp_str.c_str());
        throw std::runtime_error(format_errno_msg("rename", target_str, rename_err));
    }

    // 6. fsync() the parent directory so the atomic directory entry update is durable.
    const std::filesystem::path parent =
        path.parent_path().empty() ? std::filesystem::path(".") : path.parent_path();
    const std::string dir_str = parent.string();
    int dir_flags = O_RDONLY;
#ifdef O_DIRECTORY
    dir_flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    dir_flags |= O_CLOEXEC;
#endif

    int dir_fd = -1;
    for (;;) {
        dir_fd = ops.open_fn(dir_str.c_str(), dir_flags, 0u);
        if (dir_fd >= 0) {
            break;
        }
        const int dir_open_err = errno;
        if (dir_open_err == EINTR) {
            continue;
        }
        throw std::runtime_error(format_errno_msg("open(parent_dir)", dir_str, dir_open_err));
    }

    for (;;) {
        if (ops.fsync_fn(dir_fd) == 0) {
            break;
        }
        const int dir_fsync_err = errno;
        if (dir_fsync_err == EINTR) {
            continue;
        }
        (void)ops.close_fn(dir_fd);
        throw std::runtime_error(format_errno_msg("fsync(parent_dir)", dir_str, dir_fsync_err));
    }

    if (ops.close_fn(dir_fd) != 0) {
        const int dir_close_err = errno;
        throw std::runtime_error(format_errno_msg("close(parent_dir)", dir_str, dir_close_err));
    }
}

} // namespace detail
#endif

void write_secret_file_0600(const std::filesystem::path& path, const std::string& content) {
#ifndef _WIN32
    detail::write_secret_file_0600_posix(path, content, detail::default_posix_file_ops());
#else
    std::array<uint8_t, 8> rnd{};
    if (RAND_bytes(rnd.data(), static_cast<int>(rnd.size())) != 1) {
        throw std::runtime_error("vault_crypto: RAND_bytes failed while creating temp filename");
    }
    const std::filesystem::path dir =
        path.parent_path().empty() ? std::filesystem::path(".") : path.parent_path();
    const std::filesystem::path tmp =
        dir / ("." + path.filename().string() + ".tmp." + bytes_to_hex(rnd.data(), rnd.size()));

    HANDLE h = CreateFileW(
        tmp.c_str(),
        GENERIC_WRITE,
        0, // Exclusive access (no sharing)
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD create_err = GetLastError();
        throw std::runtime_error(
            "vault_crypto: CreateFileW(CREATE_NEW) failed for '" + tmp.string() +
            "' (win32=" + std::to_string(create_err) + ")");
    }

    std::size_t total_written = 0;
    while (total_written < content.size()) {
        const DWORD chunk = static_cast<DWORD>(
            std::min<std::size_t>(content.size() - total_written, 0x7FFFFFFFu));
        DWORD written = 0;
        if (!WriteFile(h, content.data() + total_written, chunk, &written, nullptr) || written == 0) {
            const DWORD write_err = GetLastError();
            CloseHandle(h);
            DeleteFileW(tmp.c_str());
            throw std::runtime_error(
                "vault_crypto: WriteFile failed for '" + tmp.string() +
                "' (win32=" + std::to_string(write_err) + ")");
        }
        total_written += static_cast<std::size_t>(written);
    }

    if (!FlushFileBuffers(h)) {
        const DWORD flush_err = GetLastError();
        CloseHandle(h);
        DeleteFileW(tmp.c_str());
        throw std::runtime_error(
            "vault_crypto: FlushFileBuffers failed for '" + tmp.string() +
            "' (win32=" + std::to_string(flush_err) + ")");
    }

    if (!CloseHandle(h)) {
        const DWORD close_err = GetLastError();
        DeleteFileW(tmp.c_str());
        throw std::runtime_error(
            "vault_crypto: CloseHandle failed for '" + tmp.string() +
            "' (win32=" + std::to_string(close_err) + ")");
    }

    if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const DWORD move_err = GetLastError();
        DeleteFileW(tmp.c_str());
        throw std::runtime_error(
            "vault_crypto: MoveFileExW failed for '" + path.string() +
            "' (win32=" + std::to_string(move_err) + ")");
    }
#endif
}

std::string hmac_sha256_hex(const uint8_t* key, std::size_t key_len, std::string_view message) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(),
              key, static_cast<int>(key_len),
              reinterpret_cast<const unsigned char*>(message.data()), message.size(),
              digest, &len) || len != 32) {
        throw std::runtime_error("vault_crypto: HMAC-SHA256 failed");
    }
    return bytes_to_hex(digest, len);
}

SecretKey derive_subkey(const SecretKey& master_key, std::string_view context_label) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(),
              master_key.data(), SecretKey::size(),
              reinterpret_cast<const unsigned char*>(context_label.data()), context_label.size(),
              digest, &len) || len != KEY_LEN) {
        throw std::runtime_error("vault_crypto: derive_subkey HMAC-SHA256 failed");
    }
    SecretKey subkey;
    std::memcpy(subkey.data(), digest, KEY_LEN);
    OPENSSL_cleanse(digest, sizeof(digest));
    return subkey;
}

bool constant_time_hex_equal(const std::string& hex_a, const std::string& hex_b) {
    if (hex_a.size() != hex_b.size() || hex_a.empty()) return false;
    try {
        const auto bytes_a = hex_to_bytes(hex_a);
        const auto bytes_b = hex_to_bytes(hex_b);
        return bytes_a.size() == bytes_b.size() &&
               CRYPTO_memcmp(bytes_a.data(), bytes_b.data(), bytes_a.size()) == 0;
    } catch (...) {
        return false;
    }
}

std::string wrap_dek_hex(const SecretKey& dek, const SecretKey& master_kek) {
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

SecretKey unwrap_dek_hex(const std::string& wrapped_hex, const SecretKey& master_kek) {
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

SecretBuffer pad_to_bucket(const uint8_t* plaintext, std::size_t len, std::size_t align) {
    const std::size_t raw_total = 8 + len;
    const std::size_t rem = raw_total % align;
    const std::size_t padded_total = (rem == 0) ? raw_total : (raw_total + (align - rem));

    SecretBuffer buf(padded_total);
    auto& v = buf.vec();
    const auto len64 = static_cast<uint64_t>(len);
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

SecretBuffer unpad_from_bucket(const SecretBuffer& padded) {
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

std::vector<uint8_t> encrypt_envelope(const uint8_t* plaintext, std::size_t plaintext_len,
                                      const SecretKey& dek, bool pad_traffic,
                                      std::string_view aad) {
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
    if (!aad.empty()) {
        int aad_len = 0;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &aad_len,
                              reinterpret_cast<const uint8_t*>(aad.data()),
                              static_cast<int>(aad.size())) != 1) {
            throw std::runtime_error("vault_crypto: AES-256-GCM AAD update failed");
        }
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

std::vector<uint8_t> encrypt_envelope(const std::string& plaintext, const SecretKey& dek,
                                      bool pad_traffic, std::string_view aad) {
    return encrypt_envelope(reinterpret_cast<const uint8_t*>(plaintext.data()),
                            plaintext.size(), dek, pad_traffic, aad);
}

SecretBuffer decrypt_envelope(const uint8_t* envelope, std::size_t envelope_len,
                              const SecretKey& dek, bool unpad_traffic,
                              std::string_view aad) {
    if (envelope_len < HEADER_LEN || std::memcmp(envelope, MAGIC.data(), MAGIC.size()) != 0) {
        throw std::runtime_error("vault_crypto: invalid or truncated BVL2 envelope");
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
    if (!aad.empty()) {
        int aad_len = 0;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &aad_len,
                              reinterpret_cast<const uint8_t*>(aad.data()),
                              static_cast<int>(aad.size())) != 1) {
            throw std::runtime_error("vault_crypto: AES-256-GCM AAD update failed");
        }
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

// ---------------- BVL3 Streaming Chunked AEAD ----------------

Bvl3StreamEncryptor::Bvl3StreamEncryptor(std::ostream& out, const SecretKey& dek, std::string_view blob_name)
    : out_(out), blob_name_(blob_name), frame_buf_(BVL3_FRAME_BYTES) {
    std::memcpy(dek_.data(), dek.data(), KEY_LEN);
    pending_.vec().reserve(BVL3_MAX_CHUNK_PLAIN);
    if (RAND_bytes(base_iv_.data(), static_cast<int>(base_iv_.size())) != 1) {
        throw std::runtime_error("vault_crypto: RAND_bytes failed for BVL3 base IV");
    }

    std::array<uint8_t, BVL3_HEADER_LEN> hdr{};
    std::memcpy(hdr.data(), MAGIC_BVL3.data(), MAGIC_BVL3.size());
    std::memcpy(hdr.data() + 4, base_iv_.data(), IV_LEN);
    put_u32_be(hdr.data() + 16, static_cast<uint32_t>(BVL3_FRAME_BYTES));
    // bytes [20..31] reserved flags = 0
    out_.write(reinterpret_cast<const char*>(hdr.data()), static_cast<std::streamsize>(hdr.size()));
    if (!out_) throw std::runtime_error("vault_crypto: failed writing BVL3 header");
    total_written_ += hdr.size();
}

Bvl3StreamEncryptor::~Bvl3StreamEncryptor() {
    dek_.cleanse();
    pending_.cleanse();
    OPENSSL_cleanse(base_iv_.data(), base_iv_.size());
}

void Bvl3StreamEncryptor::write(const uint8_t* data, std::size_t len) {
    if (finalized_) throw std::runtime_error("vault_crypto: Bvl3StreamEncryptor already finalized");
    if (len == 0) return;

    std::size_t offset = 0;
    auto& pv = pending_.vec();
    while (offset < len) {
        // Only emit non-final frame once strictly MORE data arrives (or fills exact full chunk with more waiting)
        if (pv.size() == BVL3_MAX_CHUNK_PLAIN) {
            flush_frame(pv.data(), pv.size(), /*is_final=*/false);
            OPENSSL_cleanse(pv.data(), pv.size());
            pv.clear();
        }
        const std::size_t avail = BVL3_MAX_CHUNK_PLAIN - pv.size();
        const std::size_t take = std::min(avail, len - offset);
        pv.insert(pv.end(), data + offset, data + offset + take);
        offset += take;
    }
}

std::size_t Bvl3StreamEncryptor::finalize() {
    if (finalized_) return total_written_;
    finalized_ = true;

    auto& pv = pending_.vec();
    flush_frame(pv.data(), pv.size(), /*is_final=*/true);
    pending_.cleanse();
    pv.clear();
    out_.flush();
    if (!out_) throw std::runtime_error("vault_crypto: BVL3 stream flush failed");
    return total_written_;
}

void Bvl3StreamEncryptor::flush_frame(const uint8_t* chunk_data, std::size_t chunk_len, bool is_final) {
    if (chunk_len > BVL3_MAX_CHUNK_PLAIN) {
        throw std::runtime_error("vault_crypto: BVL3 chunk exceeds max plaintext size");
    }

    SecretBuffer plain_frame(BVL3_FRAME_CT_BYTES);
    auto& pf = plain_frame.vec();
    put_u32_be(pf.data(), static_cast<uint32_t>(chunk_len));
    if (chunk_len > 0) {
        std::memcpy(pf.data() + 4, chunk_data, chunk_len);
    }
    const std::size_t pad_len = BVL3_FRAME_CT_BYTES - (4 + chunk_len);
    if (pad_len > 0 && RAND_bytes(pf.data() + 4 + chunk_len, static_cast<int>(pad_len)) != 1) {
        throw std::runtime_error("vault_crypto: RAND_bytes failed padding BVL3 terminal chunk");
    }

    const auto iv = derive_chunk_iv(base_iv_, chunk_index_);
    const auto aad = build_chunk_aad(blob_name_, chunk_index_, is_final);

    using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    CipherCtx ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("vault_crypto: EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IV_LEN), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, dek_.data(), iv.data()) != 1) {
        throw std::runtime_error("vault_crypto: BVL3 GCM init failed");
    }

    int aad_out = 0;
    if (!aad.empty() &&
        EVP_EncryptUpdate(ctx.get(), nullptr, &aad_out, aad.data(), static_cast<int>(aad.size())) != 1) {
        throw std::runtime_error("vault_crypto: BVL3 GCM AAD failed");
    }

    int out_len = 0;
    if (EVP_EncryptUpdate(ctx.get(), frame_buf_.data(), &out_len,
                          pf.data(), static_cast<int>(pf.size())) != 1) {
        throw std::runtime_error("vault_crypto: BVL3 GCM update failed");
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), frame_buf_.data() + out_len, &final_len) != 1 ||
        static_cast<std::size_t>(out_len + final_len) != BVL3_FRAME_CT_BYTES) {
        throw std::runtime_error("vault_crypto: BVL3 GCM final failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(TAG_LEN),
                            frame_buf_.data() + BVL3_FRAME_CT_BYTES) != 1) {
        throw std::runtime_error("vault_crypto: BVL3 GCM GET_TAG failed");
    }

    out_.write(reinterpret_cast<const char*>(frame_buf_.data()), static_cast<std::streamsize>(frame_buf_.size()));
    if (!out_) throw std::runtime_error("vault_crypto: failed writing BVL3 frame");

    chunk_index_ += 1;
    total_written_ += frame_buf_.size();
}

Bvl3EncryptingStreamBuf::Bvl3EncryptingStreamBuf(std::ostream& out, const SecretKey& dek, std::string_view blob_name)
    : encryptor_(out, dek, blob_name) {}

std::size_t Bvl3EncryptingStreamBuf::finalize() {
    return encryptor_.finalize();
}

Bvl3EncryptingStreamBuf::int_type Bvl3EncryptingStreamBuf::overflow(int_type ch) {
    if (traits_type::eq_int_type(ch, traits_type::eof())) {
        return traits_type::not_eof(ch);
    }
    const uint8_t byte = static_cast<uint8_t>(traits_type::to_char_type(ch));
    encryptor_.write(&byte, 1);
    return ch;
}

std::streamsize Bvl3EncryptingStreamBuf::xsputn(const char* s, std::streamsize count) {
    if (count > 0) {
        encryptor_.write(reinterpret_cast<const uint8_t*>(s), static_cast<std::size_t>(count));
    }
    return count;
}

std::size_t encrypt_stream_bvl3(std::istream& in, std::ostream& out,
                                const SecretKey& dek, std::string_view blob_name) {
    Bvl3StreamEncryptor enc(out, dek, blob_name);
    SecretBuffer io_buf(BVL3_MAX_CHUNK_PLAIN);
    while (in) {
        in.read(reinterpret_cast<char*>(io_buf.vec().data()),
                static_cast<std::streamsize>(io_buf.vec().size()));
        const std::streamsize got = in.gcount();
        if (got > 0) {
            enc.write(io_buf.vec().data(), static_cast<std::size_t>(got));
        }
    }
    return enc.finalize();
}

void decrypt_stream_bvl3(std::istream& in, std::size_t total_len,
                         const SecretKey& dek, std::string_view blob_name,
                         const std::function<void(std::string_view)>& on_chunk) {
    if (total_len < BVL3_HEADER_LEN + BVL3_FRAME_BYTES ||
        ((total_len - BVL3_HEADER_LEN) % BVL3_FRAME_BYTES) != 0) {
        throw std::runtime_error("vault_crypto: truncated or non-aligned BVL3 container");
    }

    std::array<uint8_t, BVL3_HEADER_LEN> hdr{};
    in.read(reinterpret_cast<char*>(hdr.data()), static_cast<std::streamsize>(hdr.size()));
    if (in.gcount() != static_cast<std::streamsize>(hdr.size()) ||
        std::memcmp(hdr.data(), MAGIC_BVL3.data(), MAGIC_BVL3.size()) != 0) {
        throw std::runtime_error("vault_crypto: invalid BVL3 header");
    }

    std::array<uint8_t, IV_LEN> base_iv{};
    std::memcpy(base_iv.data(), hdr.data() + 4, IV_LEN);
    const uint32_t frame_sz = get_u32_be(hdr.data() + 16);
    if (frame_sz != BVL3_FRAME_BYTES) {
        throw std::runtime_error("vault_crypto: unsupported BVL3 frame size");
    }

    const std::size_t num_frames = (total_len - BVL3_HEADER_LEN) / BVL3_FRAME_BYTES;
    std::vector<uint8_t> frame(BVL3_FRAME_BYTES);
    SecretBuffer plain_frame(BVL3_FRAME_CT_BYTES);

    using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    for (std::size_t i = 0; i < num_frames; ++i) {
        const bool is_final = (i + 1 == num_frames);
        in.read(reinterpret_cast<char*>(frame.data()), static_cast<std::streamsize>(BVL3_FRAME_BYTES));
        if (in.gcount() != static_cast<std::streamsize>(BVL3_FRAME_BYTES)) {
            throw std::runtime_error("vault_crypto: unexpected EOF reading BVL3 frame");
        }

        const auto iv = derive_chunk_iv(base_iv, static_cast<uint64_t>(i));
        const auto aad = build_chunk_aad(blob_name, static_cast<uint64_t>(i), is_final);

        CipherCtx ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
        if (!ctx) throw std::runtime_error("vault_crypto: EVP_CIPHER_CTX_new failed");

        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IV_LEN), nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, dek.data(), iv.data()) != 1) {
            throw std::runtime_error("vault_crypto: BVL3 GCM decrypt init failed");
        }

        int aad_out = 0;
        if (!aad.empty() &&
            EVP_DecryptUpdate(ctx.get(), nullptr, &aad_out, aad.data(), static_cast<int>(aad.size())) != 1) {
            throw std::runtime_error("vault_crypto: BVL3 GCM AAD update failed");
        }

        int out_len = 0;
        if (EVP_DecryptUpdate(ctx.get(), plain_frame.vec().data(), &out_len,
                              frame.data(), static_cast<int>(BVL3_FRAME_CT_BYTES)) != 1) {
            throw std::runtime_error("vault_crypto: BVL3 GCM decrypt update failed");
        }

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(TAG_LEN),
                                frame.data() + BVL3_FRAME_CT_BYTES) != 1) {
            throw std::runtime_error("vault_crypto: BVL3 failed setting GCM tag");
        }

        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx.get(), plain_frame.vec().data() + out_len, &final_len) != 1 ||
            static_cast<std::size_t>(out_len + final_len) != BVL3_FRAME_CT_BYTES) {
            throw std::runtime_error("vault_crypto: BVL3 GCM authentication failed (tampered/reordered/wrong key)");
        }

        const uint32_t chunk_len = get_u32_be(plain_frame.vec().data());
        if (chunk_len > BVL3_MAX_CHUNK_PLAIN) {
            throw std::runtime_error("vault_crypto: corrupted BVL3 chunk length");
        }
        if (chunk_len > 0) {
            on_chunk(std::string_view(
                reinterpret_cast<const char*>(plain_frame.vec().data() + 4),
                chunk_len));
        }
        plain_frame.cleanse();
    }
    OPENSSL_cleanse(base_iv.data(), base_iv.size());
}

void decrypt_stream_auto(std::istream& in, std::size_t total_len,
                         const SecretKey& dek, std::string_view blob_name,
                         const std::function<void(std::string_view)>& on_chunk) {
    if (total_len < 4) {
        throw std::runtime_error("vault_crypto: truncated encrypted envelope");
    }
    std::array<char, 4> magic{};
    const auto start_pos = in.tellg();
    in.read(magic.data(), 4);
    if (in.gcount() != 4) {
        throw std::runtime_error("vault_crypto: failed reading magic bytes");
    }
    in.clear();
    in.seekg(start_pos);

    if (std::memcmp(magic.data(), MAGIC_BVL3.data(), 4) == 0) {
        decrypt_stream_bvl3(in, total_len, dek, blob_name, on_chunk);
        return;
    }

    if (std::memcmp(magic.data(), MAGIC.data(), 4) == 0) {
        std::vector<uint8_t> raw(total_len);
        in.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(total_len));
        if (static_cast<std::size_t>(in.gcount()) != total_len) {
            throw std::runtime_error("vault_crypto: truncated BVL2 stream");
        }
        SecretBuffer dec = decrypt_envelope(raw.data(), raw.size(), dek, /*unpad_traffic=*/true, blob_name);
        if (!dec.vec().empty()) {
            on_chunk(std::string_view(
                reinterpret_cast<const char*>(dec.vec().data()), dec.vec().size()));
        }
        return;
    }

    throw std::runtime_error("vault_crypto: unrecognized envelope magic (expected BVL3 or BVL2)");
}

std::array<std::vector<uint8_t>, 3> erasure_split_2of3(const std::vector<uint8_t>& blob) {
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

std::vector<uint8_t> erasure_reconstruct_2of3(const std::vector<uint8_t>& s0,
                                              const std::vector<uint8_t>& s1,
                                              const std::vector<uint8_t>& s2,
                                              std::size_t original_size) {
    const std::size_t half = (original_size + 1) / 2;
    std::vector<uint8_t> rec0(half), rec1(half);

    if (!s0.empty() && !s1.empty()) {
        if (s0.size() != half || s1.size() != half) {
            throw std::runtime_error("vault_crypto: shard size mismatch");
        }
        rec0 = s0;
        rec1 = s1;
    } else if (!s0.empty() && !s2.empty()) {
        if (s0.size() != half || s2.size() != half) {
            throw std::runtime_error("vault_crypto: shard size mismatch");
        }
        rec0 = s0;
        for (std::size_t i = 0; i < half; ++i) rec1[i] = static_cast<uint8_t>(s0[i] ^ s2[i]);
    } else if (!s1.empty() && !s2.empty()) {
        if (s1.size() != half || s2.size() != half) {
            throw std::runtime_error("vault_crypto: shard size mismatch");
        }
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

void write_bytes_to_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("vault_crypto: cannot open output file " + path);
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    if (!out) throw std::runtime_error("vault_crypto: write failed for " + path);
}

std::vector<uint8_t> read_bytes_from_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("vault_crypto: cannot open input file " + path);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

} // namespace vault_crypto
