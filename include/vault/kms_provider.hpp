#pragma once
// Hardware Security Module (PKCS#11) & KMS Abstraction:
//   - KEK never enters GatewayEngine process memory when backed by Pkcs11HsmProvider.
//   - Supports any FIPS 140-3 HSM or SoftHSMv2 module via standard PKCS#11 CKM_AES_KEY_WRAP & CKM_SHA256_HMAC.

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include "at_rest_crypto.hpp"

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
    explicit LocalSoftwareKmsProvider(const std::filesystem::path& kek_path);

    [[nodiscard]] std::string wrap_dek_hex(const vault_crypto::SecretKey& dek) const override;
    [[nodiscard]] vault_crypto::SecretKey unwrap_dek_hex(const std::string& wrapped_hex) const override;
    [[nodiscard]] std::string hmac_index_hex(std::string_view body) const override;
    [[nodiscard]] std::string hmac_audit_hex(std::string_view body) const override;
    [[nodiscard]] std::array<uint8_t, 32> derive_tokenizer_pepper() const override;
    [[nodiscard]] bool can_rotate_master_kek_in_app() const override { return true; }
    void rotate_master_kek(const vault_crypto::SecretKey& new_master_kek) override;
    [[nodiscard]] std::string backend_description() const override;

private:
    static vault_crypto::SecretKey load_or_create_kek(const std::filesystem::path& kek_path);

    mutable std::mutex mutex_;
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
    constexpr CK_RV CKR_USER_ALREADY_LOGGED_IN    = 0x00000100UL;
    constexpr CK_RV CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191UL;
    constexpr CK_FLAGS CKF_SERIAL_SESSION         = 0x00000004UL;
    constexpr CK_FLAGS CKF_RW_SESSION             = 0x00000002UL;
    constexpr CK_USER_TYPE CKU_USER               = 1UL;
    constexpr CK_MECHANISM_TYPE CKM_AES_KEY_WRAP  = 0x00002109UL; // RFC 3394
    constexpr CK_MECHANISM_TYPE CKM_SHA256_HMAC   = 0x00000251UL;
    constexpr CK_ATTRIBUTE_TYPE CKA_CLASS         = 0x00000000UL;
    constexpr CK_ATTRIBUTE_TYPE CKA_TOKEN         = 0x00000001UL;
    constexpr CK_ATTRIBUTE_TYPE CKA_KEY_TYPE      = 0x00000100UL;
    constexpr CK_ATTRIBUTE_TYPE CKA_SENSITIVE     = 0x00000103UL;
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
                      const std::string& audit_label = "blindvault-audit-hmac");

    ~Pkcs11HsmProvider() override;

    Pkcs11HsmProvider(const Pkcs11HsmProvider&) = delete;
    Pkcs11HsmProvider& operator=(const Pkcs11HsmProvider&) = delete;

    [[nodiscard]] std::string wrap_dek_hex(const vault_crypto::SecretKey& dek) const override;
    [[nodiscard]] vault_crypto::SecretKey unwrap_dek_hex(const std::string& wrapped_hex) const override;
    [[nodiscard]] std::string hmac_index_hex(std::string_view body) const override;
    [[nodiscard]] std::string hmac_audit_hex(std::string_view body) const override;
    [[nodiscard]] std::array<uint8_t, 32> derive_tokenizer_pepper() const override;
    [[nodiscard]] bool can_rotate_master_kek_in_app() const override { return false; }
    void rotate_master_kek(const vault_crypto::SecretKey&) override;
    [[nodiscard]] std::string backend_description() const override;

    // Verifies Master KEK inside HSM reports CKA_EXTRACTABLE=FALSE and refuses raw key export
    [[nodiscard]] bool is_master_kek_non_extractable() const;

private:
    [[nodiscard]] pkcs11_abi::CK_OBJECT_HANDLE find_key_by_label(const std::string& label) const;
    [[nodiscard]] std::string sign_hmac_in_hsm(pkcs11_abi::CK_OBJECT_HANDLE key_handle, std::string_view body) const;

    std::string module_path_;
    mutable std::mutex pkcs11_mutex_;
    void* dl_handle_ = nullptr;
    pkcs11_abi::CK_FUNCTION_LIST* fn_ = nullptr;
    pkcs11_abi::CK_SESSION_HANDLE session_ = 0;
    pkcs11_abi::CK_OBJECT_HANDLE kek_handle_ = 0;
    pkcs11_abi::CK_OBJECT_HANDLE index_handle_ = 0;
    pkcs11_abi::CK_OBJECT_HANDLE audit_handle_ = 0;
    bool initialized_ = false;
    bool we_initialized_ = false;
    bool we_logged_in_ = false;
};
#endif

// Factory: automatically connects to PKCS#11 HSM when BLINDVAULT_PKCS11_MODULE is set,
// otherwise falls back cleanly to LocalSoftwareKmsProvider.
std::shared_ptr<KeyManagementProvider> create_default_kms(const std::filesystem::path& state_dir);

} // namespace vault_kms
