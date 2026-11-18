#pragma once
// Hardware Security Module (PKCS#11) & KMS Abstraction:
//   - KEK never enters GatewayEngine process memory when backed by Pkcs11HsmProvider.
//   - Supports any FIPS 140-3 HSM or SoftHSMv2 module via standard PKCS#11 CKM_AES_KEY_WRAP & CKM_SHA256_HMAC.

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include "at_rest_crypto.hpp"

#ifndef _WIN32
#include <dlfcn.h>
#endif

namespace vault_kms {

// Abstract boundary: callers never see or hold the Master KEK.
class KeyManagementProvider {
public:
    virtual ~KeyManagementProvider() = default;

    // Wraps a 32-byte DEK inside the HSM/KMS -> returns 80-char RFC 3394 hex
    [[nodiscard]] virtual std::string wrap_dek_hex(const vault_crypto::SecretKey& dek) const = 0;

    // Unwraps an 80-char RFC 3394 hex DEK inside the HSM/KMS -> returns transient SecretKey
    [[nodiscard]] virtual vault_crypto::SecretKey unwrap_dek_hex(const std::string& wrapped_hex) const = 0;

    // Domain-separated HMAC-SHA256 performed inside the HSM/KMS (key never leaves hardware)
    [[nodiscard]] virtual std::string hmac_index_hex(std::string_view canonical_index_body) const = 0;
    [[nodiscard]] virtual std::string hmac_audit_hex(std::string_view canonical_audit_body) const = 0;
    [[nodiscard]] virtual std::array<uint8_t, 32> derive_tokenizer_pepper() const = 0;
    [[nodiscard]] virtual bool can_rotate_master_kek_in_app() const = 0;
    virtual void rotate_master_kek(const vault_crypto::SecretKey& new_master_kek) = 0;

    [[nodiscard]] virtual std::string backend_description() const = 0;
};

// Local fallback provider for laptops/CI without a PKCS#11 HSM daemon attached
class LocalSoftwareKmsProvider final : public KeyManagementProvider {
public:
    explicit LocalSoftwareKmsProvider(const std::filesystem::path& kek_path)
        : master_kek_(load_or_create_kek(kek_path)),
          index_key_(vault_crypto::derive_subkey(master_kek_, "blindvault:index-auth:v1")),
          audit_key_(vault_crypto::derive_subkey(master_kek_, "blindvault:audit-auth:v1")),
          pepper_(vault_crypto::derive_subkey(master_kek_, "blindvault:pepper:v1")),
          kek_path_(kek_path) {}

    [[nodiscard]] std::string wrap_dek_hex(const vault_crypto::SecretKey& dek) const override {
        return vault_crypto::wrap_dek_hex(dek, master_kek_);
    }

    [[nodiscard]] vault_crypto::SecretKey unwrap_dek_hex(const std::string& wrapped_hex) const override {
        return vault_crypto::unwrap_dek_hex(wrapped_hex, master_kek_);
    }

    [[nodiscard]] std::string hmac_index_hex(std::string_view body) const override {
        return vault_crypto::hmac_sha256_hex(index_key_.data(), vault_crypto::SecretKey::size(), body);
    }

    [[nodiscard]] std::string hmac_audit_hex(std::string_view body) const override {
        return vault_crypto::hmac_sha256_hex(audit_key_.data(), vault_crypto::SecretKey::size(), body);
    }

    [[nodiscard]] std::array<uint8_t, 32> derive_tokenizer_pepper() const override {
        return pepper_.bytes;
    }

    [[nodiscard]] bool can_rotate_master_kek_in_app() const override {
        return true;
    }

    void rotate_master_kek(const vault_crypto::SecretKey& new_master_kek) override {
        std::memcpy(
            master_kek_.data(),
            new_master_kek.data(),
            vault_crypto::KEY_LEN);
        index_key_ = vault_crypto::derive_subkey(master_kek_, "blindvault:index-auth:v1");
        audit_key_ = vault_crypto::derive_subkey(master_kek_, "blindvault:audit-auth:v1");
        pepper_ = vault_crypto::derive_subkey(master_kek_, "blindvault:pepper:v1");
        vault_crypto::write_secret_file_0600(
            kek_path_,
            vault_crypto::bytes_to_hex(master_kek_.data(), vault_crypto::SecretKey::size()) + "\n");
    }

    [[nodiscard]] std::string backend_description() const override {
        return "Software-KMS-Fallback (0600 local KEK; set BLINDVAULT_PKCS11_MODULE for hardware HSM)";
    }

private:
    static vault_crypto::SecretKey load_or_create_kek(const std::filesystem::path& kek_path) {
        std::filesystem::create_directories(kek_path.parent_path());
        if (std::filesystem::exists(kek_path)) {
            std::ifstream in(kek_path, std::ios::binary);
            std::string hex_str;
            std::getline(in, hex_str);
            const auto raw = vault_crypto::hex_to_bytes(hex_str);
            if (raw.size() != vault_crypto::KEY_LEN) {
                throw std::runtime_error("LocalSoftwareKmsProvider: corrupted master KEK");
            }
            vault_crypto::SecretKey kek;
            std::memcpy(kek.data(), raw.data(), vault_crypto::KEY_LEN);
            return kek;
        }
        vault_crypto::SecretKey kek = vault_crypto::generate_key();
        vault_crypto::write_secret_file_0600(
            kek_path, vault_crypto::bytes_to_hex(kek.data(), vault_crypto::SecretKey::size()) + "\n");
        return kek;
    }

    vault_crypto::SecretKey master_kek_;
    vault_crypto::SecretKey index_key_;
    vault_crypto::SecretKey audit_key_;
    vault_crypto::SecretKey pepper_;
    std::filesystem::path kek_path_;
};

#ifndef _WIN32
// Minimal self-contained PKCS#11 v2.40 ABI definitions (zero external SDK header dependency)
namespace pkcs11_abi {
    using CK_ULONG         = unsigned long;
    using CK_RV            = CK_ULONG;
    using CK_SLOT_ID       = CK_ULONG;
    using CK_SESSION_HANDLE= CK_ULONG;
    using CK_OBJECT_HANDLE = CK_ULONG;
    using CK_FLAGS         = CK_ULONG;
    using CK_USER_TYPE     = CK_ULONG;
    using CK_MECHANISM_TYPE= CK_ULONG;
    using CK_ATTRIBUTE_TYPE= CK_ULONG;
    using CK_BYTE          = unsigned char;
    using CK_UTF8CHAR      = unsigned char;
    using CK_BBOOL         = unsigned char;

    constexpr CK_RV CKR_OK                        = 0x00000000UL;
    constexpr CK_FLAGS CKF_SERIAL_SESSION         = 0x00000004UL;
    constexpr CK_FLAGS CKF_RW_SESSION             = 0x00000002UL;
    constexpr CK_USER_TYPE CKU_USER               = 1UL;
    constexpr CK_MECHANISM_TYPE CKM_AES_KEY_WRAP  = 0x00002109UL; // RFC 3394
    constexpr CK_MECHANISM_TYPE CKM_SHA256_HMAC   = 0x00000251UL;
    constexpr CK_ATTRIBUTE_TYPE CKA_CLASS         = 0x00000000UL;
    constexpr CK_ATTRIBUTE_TYPE CKA_KEY_TYPE      = 0x00000100UL;
    constexpr CK_ATTRIBUTE_TYPE CKA_LABEL         = 0x00000003UL;
    constexpr CK_ATTRIBUTE_TYPE CKA_VALUE         = 0x00000011UL;
    constexpr CK_ATTRIBUTE_TYPE CKA_VALUE_LEN     = 0x00000161UL;
    constexpr CK_ATTRIBUTE_TYPE CKA_EXTRACTABLE   = 0x00000162UL;
    constexpr CK_ULONG CKO_SECRET_KEY             = 0x00000004UL;
    constexpr CK_ULONG CKK_AES                    = 0x0000001FUL;
    constexpr CK_ULONG CKK_GENERIC_SECRET         = 0x00000010UL;

    struct CK_MECHANISM {
        CK_MECHANISM_TYPE mechanism;
        void* pParameter;
        CK_ULONG ulParameterLen;
    };

    struct CK_ATTRIBUTE {
        CK_ATTRIBUTE_TYPE type;
        void* pValue;
        CK_ULONG ulValueLen;
    };

    struct CK_FUNCTION_LIST {
        unsigned char version[2];
        CK_RV (*C_Initialize)(void*);
        CK_RV (*C_Finalize)(void*);
        void* C_GetInfo;
        void* C_GetFunctionList;
        CK_RV (*C_GetSlotList)(CK_BBOOL, CK_SLOT_ID*, CK_ULONG*);
        void* C_GetSlotInfo;
        void* C_GetTokenInfo;
        void* C_GetMechanismList;
        void* C_GetMechanismInfo;
        void* C_InitToken;
        void* C_InitPIN;
        void* C_SetPIN;
        CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
        CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
        void* C_CloseAllSessions;
        void* C_GetSessionInfo;
        void* C_GetOperationState;
        void* C_SetOperationState;
        CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR*, CK_ULONG);
        CK_RV (*C_Logout)(CK_SESSION_HANDLE);
        CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
        void* C_CopyObject;
        CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
        void* C_GetObjectSize;
        CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
        void* C_SetAttributeValue;
        CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
        CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
        CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
        void* C_EncryptInit;
        void* C_Encrypt;
        void* C_EncryptUpdate;
        void* C_EncryptFinal;
        void* C_DecryptInit;
        void* C_Decrypt;
        void* C_DecryptUpdate;
        void* C_DecryptFinal;
        void* C_DigestInit;
        void* C_Digest;
        void* C_DigestUpdate;
        void* C_DigestKey;
        void* C_DigestFinal;
        CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
        CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
        void* C_SignUpdate;
        void* C_SignFinal;
        void* C_SignRecoverInit;
        void* C_SignRecover;
        void* C_VerifyInit;
        void* C_Verify;
        void* C_VerifyUpdate;
        void* C_VerifyFinal;
        void* C_VerifyRecoverInit;
        void* C_VerifyRecover;
        void* C_DigestEncryptUpdate;
        void* C_DecryptDigestUpdate;
        void* C_SignEncryptUpdate;
        void* C_DecryptVerifyUpdate;
        void* C_GenerateKey;
        void* C_GenerateKeyPair;
        CK_RV (*C_WrapKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE*, CK_ULONG*);
        CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_BYTE*, CK_ULONG, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
    };
} // namespace pkcs11_abi

// Hardware HSM Provider via PKCS#11 (SoftHSMv2, AWS CloudHSM, Thales Luna, Utimaco):
//   - Master KEK, Index HMAC key, and Audit HMAC key live strictly inside HSM hardware (CKA_EXTRACTABLE=FALSE).
//   - Zero Master KEK bytes ever enter BlindVault's process memory.
class Pkcs11HsmProvider final : public KeyManagementProvider {
public:
    Pkcs11HsmProvider(const std::string& module_path,
                      const std::string& user_pin,
                      const std::string& kek_label   = "blindvault-master-kek",
                      const std::string& index_label = "blindvault-index-hmac",
                      const std::string& audit_label = "blindvault-audit-hmac")
        : module_path_(module_path) {
        using namespace pkcs11_abi;
        dl_handle_ = dlopen(module_path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!dl_handle_) {
            throw std::runtime_error("Pkcs11HsmProvider: dlopen failed: " + std::string(dlerror()));
        }
        using GetFnList = CK_RV (*)(CK_FUNCTION_LIST**);
        auto get_list = reinterpret_cast<GetFnList>(dlsym(dl_handle_, "C_GetFunctionList"));
        if (!get_list || get_list(&fn_) != CKR_OK || !fn_) {
            throw std::runtime_error("Pkcs11HsmProvider: C_GetFunctionList failed");
        }
        if (fn_->C_Initialize(nullptr) != CKR_OK) {
            throw std::runtime_error("Pkcs11HsmProvider: C_Initialize failed");
        }
        initialized_ = true;

        CK_ULONG slot_count = 0;
        if (fn_->C_GetSlotList(1, nullptr, &slot_count) != CKR_OK || slot_count == 0) {
            throw std::runtime_error("Pkcs11HsmProvider: no initialized PKCS#11 token slots found");
        }
        pkcs11_abi::CK_SLOT_ID first_slot = 0;
        fn_->C_GetSlotList(1, &first_slot, &slot_count);
        if (slot_count == 0) {
            throw std::runtime_error("Pkcs11HsmProvider: no PKCS#11 token slots available");
        }

        if (fn_->C_OpenSession(first_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               nullptr, nullptr, &session_) != CKR_OK) {
            throw std::runtime_error("Pkcs11HsmProvider: C_OpenSession failed");
        }
        if (fn_->C_Login(session_, CKU_USER,
                         reinterpret_cast<CK_UTF8CHAR*>(const_cast<char*>(user_pin.data())),
                         static_cast<CK_ULONG>(user_pin.size())) != CKR_OK) {
            throw std::runtime_error("Pkcs11HsmProvider: HSM C_Login failed (invalid PIN)");
        }

        kek_handle_   = find_key_by_label(kek_label);
        index_handle_ = find_key_by_label(index_label);
        audit_handle_ = find_key_by_label(audit_label);
    }

    ~Pkcs11HsmProvider() override {
        if (session_ && fn_) {
            fn_->C_Logout(session_);
            fn_->C_CloseSession(session_);
        }
        if (initialized_ && fn_) {
            fn_->C_Finalize(nullptr);
        }
        if (dl_handle_) {
            dlclose(dl_handle_);
        }
    }

    [[nodiscard]] std::string wrap_dek_hex(const vault_crypto::SecretKey& dek) const override {
        using namespace pkcs11_abi;
        // Import transient DEK handle into HSM session, wrap with non-extractable Master KEK, destroy session handle
        CK_ULONG obj_class = CKO_SECRET_KEY;
        CK_ULONG key_type  = CKK_AES;
        CK_BBOOL ck_true   = 1;
        CK_BBOOL ck_false  = 0;
        CK_ATTRIBUTE tmpl[] = {
            {CKA_CLASS,       &obj_class, sizeof(obj_class)},
            {CKA_KEY_TYPE,    &key_type,  sizeof(key_type)},
            {CKA_EXTRACTABLE, &ck_true,   sizeof(ck_true)},
            {CKA_VALUE,       const_cast<uint8_t*>(dek.data()), (vault_crypto::SecretKey::size())}
        };
        CK_OBJECT_HANDLE dek_obj = 0;
        if (fn_->C_CreateObject(session_, tmpl, 4, &dek_obj) != CKR_OK) {
            throw std::runtime_error("Pkcs11HsmProvider: failed to stage DEK in HSM");
        }

        CK_MECHANISM mech{CKM_AES_KEY_WRAP, nullptr, 0};
        CK_BYTE wrapped[vault_crypto::WRAPPED_KEY_LEN]{};
        CK_ULONG wrapped_len = sizeof(wrapped);
        const CK_RV rv = fn_->C_WrapKey(session_, &mech, kek_handle_, dek_obj, wrapped, &wrapped_len);
        fn_->C_DestroyObject(session_, dek_obj);
        (void)ck_false;

        if (rv != CKR_OK || wrapped_len != vault_crypto::WRAPPED_KEY_LEN) {
            throw std::runtime_error("Pkcs11HsmProvider: HSM C_WrapKey (RFC 3394) failed");
        }
        return vault_crypto::bytes_to_hex(wrapped, wrapped_len);
    }

    [[nodiscard]] vault_crypto::SecretKey unwrap_dek_hex(const std::string& wrapped_hex) const override {
        using namespace pkcs11_abi;
        const auto wrapped = vault_crypto::hex_to_bytes(wrapped_hex);
        if (wrapped.size() != vault_crypto::WRAPPED_KEY_LEN) {
            throw std::runtime_error("Pkcs11HsmProvider: invalid wrapped DEK length");
        }

        CK_ULONG obj_class = CKO_SECRET_KEY;
        CK_ULONG key_type  = CKK_AES;
        CK_BBOOL ck_true   = 1;
        CK_ATTRIBUTE unwrap_tmpl[] = {
            {CKA_CLASS,       &obj_class, sizeof(obj_class)},
            {CKA_KEY_TYPE,    &key_type,  sizeof(key_type)},
            {CKA_EXTRACTABLE, &ck_true,   sizeof(ck_true)}
        };

        CK_MECHANISM mech{CKM_AES_KEY_WRAP, nullptr, 0};
        CK_OBJECT_HANDLE dek_obj = 0;
        if (fn_->C_UnwrapKey(session_, &mech, kek_handle_,
                             const_cast<CK_BYTE*>(wrapped.data()), static_cast<CK_ULONG>(wrapped.size()),
                             unwrap_tmpl, 3, &dek_obj) != CKR_OK) {
            throw std::runtime_error("Pkcs11HsmProvider: HSM C_UnwrapKey failed");
        }

        vault_crypto::SecretKey dek;
        CK_ATTRIBUTE val_attr{CKA_VALUE, dek.data(), (vault_crypto::SecretKey::size())};
        const CK_RV rv = fn_->C_GetAttributeValue(session_, dek_obj, &val_attr, 1);
        fn_->C_DestroyObject(session_, dek_obj);
        if (rv != CKR_OK) {
            throw std::runtime_error("Pkcs11HsmProvider: failed to read unwrapped session DEK");
        }
        return dek;
    }

    [[nodiscard]] std::string hmac_index_hex(std::string_view body) const override {
        return sign_hmac_in_hsm(index_handle_, body);
    }

    [[nodiscard]] std::string hmac_audit_hex(std::string_view body) const override {
        return sign_hmac_in_hsm(audit_handle_, body);
    }

    [[nodiscard]] std::array<uint8_t, 32> derive_tokenizer_pepper() const override {
        const std::string mac = sign_hmac_in_hsm(kek_handle_, "blindvault:pepper:v1");
        const auto raw = vault_crypto::hex_to_bytes(mac);
        std::array<uint8_t, 32> pepper{};
        if (raw.size() != pepper.size()) {
            throw std::runtime_error("Pkcs11HsmProvider: invalid derived tokenizer pepper");
        }
        std::copy(raw.begin(), raw.end(), pepper.begin());
        return pepper;
    }

    [[nodiscard]] bool can_rotate_master_kek_in_app() const override {
        return false;
    }

    void rotate_master_kek(const vault_crypto::SecretKey&) override {
        throw std::runtime_error("Pkcs11HsmProvider: rotate_master_kek must be performed through HSM administration");
    }

    [[nodiscard]] std::string backend_description() const override {
        return "Hardware-HSM-PKCS11 (" + module_path_ + ", KEK non-extractable in hardware)";
    }

private:
    [[nodiscard]] pkcs11_abi::CK_OBJECT_HANDLE find_key_by_label(const std::string& label) const {
        using namespace pkcs11_abi;
        CK_ATTRIBUTE search_attr{
            CKA_LABEL,
            const_cast<char*>(label.data()),
            static_cast<CK_ULONG>(label.size())
        };
        if (fn_->C_FindObjectsInit(session_, &search_attr, 1) != CKR_OK) {
            throw std::runtime_error("Pkcs11HsmProvider: C_FindObjectsInit failed");
        }
        CK_OBJECT_HANDLE obj = 0;
        CK_ULONG found = 0;
        fn_->C_FindObjects(session_, &obj, 1, &found);
        fn_->C_FindObjectsFinal(session_);
        if (found == 0) {
            throw std::runtime_error("Pkcs11HsmProvider: HSM key label not found: " + label);
        }
        return obj;
    }

    [[nodiscard]] std::string sign_hmac_in_hsm(pkcs11_abi::CK_OBJECT_HANDLE key_handle, std::string_view body) const {
        using namespace pkcs11_abi;
        CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
        if (fn_->C_SignInit(session_, &mech, key_handle) != CKR_OK) {
            throw std::runtime_error("Pkcs11HsmProvider: C_SignInit failed");
        }
        CK_BYTE mac[32]{};
        CK_ULONG mac_len = sizeof(mac);
        if (fn_->C_Sign(session_,
                        reinterpret_cast<CK_BYTE*>(const_cast<char*>(body.data())),
                        static_cast<CK_ULONG>(body.size()),
                        mac, &mac_len) != CKR_OK || mac_len != 32) {
            throw std::runtime_error("Pkcs11HsmProvider: HSM C_Sign HMAC-SHA256 failed");
        }
        return vault_crypto::bytes_to_hex(mac, mac_len);
    }

    std::string module_path_;
    void* dl_handle_ = nullptr;
    pkcs11_abi::CK_FUNCTION_LIST* fn_ = nullptr;
    pkcs11_abi::CK_SESSION_HANDLE session_ = 0;
    pkcs11_abi::CK_OBJECT_HANDLE kek_handle_ = 0;
    pkcs11_abi::CK_OBJECT_HANDLE index_handle_ = 0;
    pkcs11_abi::CK_OBJECT_HANDLE audit_handle_ = 0;
    bool initialized_ = false;
};
#endif

// Factory: automatically connects to PKCS#11 HSM when BLINDVAULT_PKCS11_MODULE is set,
// otherwise falls back cleanly to LocalSoftwareKmsProvider.
inline std::shared_ptr<KeyManagementProvider> create_default_kms(const std::filesystem::path& state_dir) {
#ifndef _WIN32
    if (const char* mod = std::getenv("BLINDVAULT_PKCS11_MODULE"); mod && *mod) {
        const char* pin = std::getenv("BLINDVAULT_PKCS11_PIN");
        if (!pin || !*pin) {
            throw std::runtime_error("BLINDVAULT_PKCS11_MODULE is set, but BLINDVAULT_PKCS11_PIN is missing");
        }
        return std::make_shared<Pkcs11HsmProvider>(mod, pin);
    }
#endif
    return std::make_shared<LocalSoftwareKmsProvider>(state_dir / "hsm_master.kek");
}

} // namespace vault_kms