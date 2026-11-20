#include "kms_provider.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <vector>
#include <openssl/crypto.h>

#ifndef _WIN32
#include <dlfcn.h>
#endif

namespace vault_kms {

// ---------------- LocalSoftwareKmsProvider ----------------

LocalSoftwareKmsProvider::LocalSoftwareKmsProvider(const std::filesystem::path& kek_path)
    : master_kek_(load_or_create_kek(kek_path)),
      index_key_(vault_crypto::derive_subkey(master_kek_, "blindvault:index-auth:v1")),
      audit_key_(vault_crypto::derive_subkey(master_kek_, "blindvault:audit-auth:v1")),
      pepper_(vault_crypto::derive_subkey(master_kek_, "blindvault:pepper:v1")),
      kek_path_(kek_path) {}

std::string LocalSoftwareKmsProvider::wrap_dek_hex(const vault_crypto::SecretKey& dek) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return vault_crypto::wrap_dek_hex(dek, master_kek_);
}

vault_crypto::SecretKey LocalSoftwareKmsProvider::unwrap_dek_hex(const std::string& wrapped_hex) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return vault_crypto::unwrap_dek_hex(wrapped_hex, master_kek_);
}

std::string LocalSoftwareKmsProvider::hmac_index_hex(std::string_view body) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return vault_crypto::hmac_sha256_hex(index_key_.data(), vault_crypto::SecretKey::size(), body);
}

std::string LocalSoftwareKmsProvider::hmac_audit_hex(std::string_view body) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return vault_crypto::hmac_sha256_hex(audit_key_.data(), vault_crypto::SecretKey::size(), body);
}

std::array<uint8_t, 32> LocalSoftwareKmsProvider::derive_tokenizer_pepper() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pepper_.bytes;
}

void LocalSoftwareKmsProvider::rotate_master_kek(const vault_crypto::SecretKey& new_master_kek) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::memcpy(master_kek_.data(), new_master_kek.data(), vault_crypto::KEY_LEN);
    index_key_ = vault_crypto::derive_subkey(master_kek_, "blindvault:index-auth:v1");
    audit_key_ = vault_crypto::derive_subkey(master_kek_, "blindvault:audit-auth:v1");
    pepper_ = vault_crypto::derive_subkey(master_kek_, "blindvault:pepper:v1");
    vault_crypto::write_secret_file_0600(
        kek_path_,
        vault_crypto::bytes_to_hex(master_kek_.data(), vault_crypto::SecretKey::size()) + "\n");
}

std::string LocalSoftwareKmsProvider::backend_description() const {
    return "Software-KMS-Fallback (0600 local KEK; set BLINDVAULT_PKCS11_MODULE for hardware HSM)";
}

vault_crypto::SecretKey LocalSoftwareKmsProvider::load_or_create_kek(const std::filesystem::path& kek_path) {
    if (kek_path.has_parent_path()) {
        std::filesystem::create_directories(kek_path.parent_path());
    }
    if (std::filesystem::exists(kek_path)) {
        std::ifstream in(kek_path, std::ios::binary);
        std::string hex_str;
        std::getline(in, hex_str);
        if (!hex_str.empty() && hex_str.back() == '\r') hex_str.pop_back();
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

#ifndef _WIN32
// ---------------- Pkcs11HsmProvider ----------------

Pkcs11HsmProvider::Pkcs11HsmProvider(const std::string& module_path,
                                     const std::string& user_pin,
                                     const std::string& kek_label,
                                     const std::string& index_label,
                                     const std::string& audit_label)
    : module_path_(module_path) {
    using namespace pkcs11_abi;
    std::lock_guard<std::mutex> lock(pkcs11_mutex_);

    dl_handle_ = dlopen(module_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!dl_handle_) {
        throw std::runtime_error("Pkcs11HsmProvider: dlopen failed: " + std::string(dlerror()));
    }
    using GetFnList = CK_RV (*)(CK_FUNCTION_LIST**);
    auto get_list = reinterpret_cast<GetFnList>(dlsym(dl_handle_, "C_GetFunctionList"));
    if (!get_list || get_list(&fn_) != CKR_OK || !fn_) {
        dlclose(dl_handle_);
        dl_handle_ = nullptr;
        throw std::runtime_error("Pkcs11HsmProvider: C_GetFunctionList failed");
    }

    const CK_RV init_rv = fn_->C_Initialize(nullptr);
    if (init_rv == CKR_OK) {
        we_initialized_ = true;
        initialized_ = true;
    } else if (init_rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        we_initialized_ = false;
        initialized_ = true;
    } else {
        dlclose(dl_handle_);
        dl_handle_ = nullptr;
        throw std::runtime_error("Pkcs11HsmProvider: C_Initialize failed (rv=" + std::to_string(init_rv) + ")");
    }

    CK_ULONG slot_count = 0;
    if (fn_->C_GetSlotList(1, nullptr, &slot_count) != CKR_OK || slot_count == 0) {
        throw std::runtime_error("Pkcs11HsmProvider: no initialized PKCS#11 token slots found");
    }
    std::vector<CK_SLOT_ID> slots(slot_count, 0);
    if (fn_->C_GetSlotList(1, slots.data(), &slot_count) != CKR_OK || slot_count == 0) {
        throw std::runtime_error("Pkcs11HsmProvider: no PKCS#11 token slots available");
    }

    bool logged_in = false;
    std::string slot_errors;
    for (CK_ULONG i = 0; i < slot_count; ++i) {
        CK_SESSION_HANDLE cand = 0;
        const CK_RV open_rv = fn_->C_OpenSession(
            slots[i], CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &cand);
        if (open_rv != CKR_OK) {
            slot_errors += "[slot " + std::to_string(slots[i]) +
                           ": C_OpenSession rv=" + std::to_string(open_rv) + "] ";
            continue;
        }
        const CK_RV login_rv = fn_->C_Login(
            cand, CKU_USER,
            reinterpret_cast<CK_UTF8CHAR*>(const_cast<char*>(user_pin.data())),
            static_cast<CK_ULONG>(user_pin.size()));
        bool cand_logged_in = false;
        if (login_rv == CKR_OK) {
            cand_logged_in = true;
        } else if (login_rv == CKR_USER_ALREADY_LOGGED_IN) {
            cand_logged_in = false;
        } else {
            fn_->C_CloseSession(cand);
            slot_errors += "[slot " + std::to_string(slots[i]) +
                           ": C_Login rv=" + std::to_string(login_rv) + "] ";
            continue;
        }

        session_ = cand;
        try {
            kek_handle_   = find_key_by_label(kek_label);
            index_handle_ = find_key_by_label(index_label);
            audit_handle_ = find_key_by_label(audit_label);
            we_logged_in_ = cand_logged_in;
            logged_in = true;
            break;
        } catch (const std::exception& exc) {
            if (cand_logged_in) fn_->C_Logout(session_);
            fn_->C_CloseSession(session_);
            session_ = 0;
            slot_errors += "[slot " + std::to_string(slots[i]) + ": " + exc.what() + "] ";
        }
    }

    if (!logged_in) {
        if (we_initialized_ && fn_) {
            fn_->C_Finalize(nullptr);
            we_initialized_ = false;
        }
        if (dl_handle_) {
            dlclose(dl_handle_);
            dl_handle_ = nullptr;
        }
        throw std::runtime_error("Pkcs11HsmProvider: " +
                                 (slot_errors.empty() ? std::string("no usable PKCS#11 slot") : slot_errors));
    }
}

Pkcs11HsmProvider::~Pkcs11HsmProvider() {
    std::lock_guard<std::mutex> lock(pkcs11_mutex_);
    if (session_ && fn_) {
        if (we_logged_in_) {
            fn_->C_Logout(session_);
            we_logged_in_ = false;
        }
        fn_->C_CloseSession(session_);
        session_ = 0;
    }
    if (we_initialized_ && fn_) {
        fn_->C_Finalize(nullptr);
        we_initialized_ = false;
    }
    if (dl_handle_) {
        dlclose(dl_handle_);
        dl_handle_ = nullptr;
    }
}

std::string Pkcs11HsmProvider::wrap_dek_hex(const vault_crypto::SecretKey& dek) const {
    using namespace pkcs11_abi;
    std::lock_guard<std::mutex> lock(pkcs11_mutex_);

    CK_ULONG obj_class = CKO_SECRET_KEY;
    CK_ULONG key_type  = CKK_AES;
    CK_BBOOL ck_true   = 1;
    CK_BBOOL ck_false  = 0;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS,       &obj_class, sizeof(obj_class)},
        {CKA_KEY_TYPE,    &key_type,  sizeof(key_type)},
        {CKA_TOKEN,       &ck_false,  sizeof(ck_false)},
        {CKA_SENSITIVE,   &ck_false,  sizeof(ck_false)},
        {CKA_EXTRACTABLE, &ck_true,   sizeof(ck_true)},
        {CKA_VALUE,       const_cast<uint8_t*>(dek.data()), static_cast<CK_ULONG>(vault_crypto::SecretKey::size())}
    };
    CK_OBJECT_HANDLE dek_obj = 0;
    const CK_RV create_rv = fn_->C_CreateObject(session_, tmpl, 6, &dek_obj);
    if (create_rv != CKR_OK) {
        throw std::runtime_error("Pkcs11HsmProvider: failed to stage DEK in HSM (rv=" + std::to_string(create_rv) + ")");
    }

    CK_MECHANISM mech{CKM_AES_KEY_WRAP, nullptr, 0};
    CK_BYTE wrapped[vault_crypto::WRAPPED_KEY_LEN]{};
    CK_ULONG wrapped_len = sizeof(wrapped);
    const CK_RV rv = fn_->C_WrapKey(session_, &mech, kek_handle_, dek_obj, wrapped, &wrapped_len);
    fn_->C_DestroyObject(session_, dek_obj);

    if (rv != CKR_OK || wrapped_len != vault_crypto::WRAPPED_KEY_LEN) {
        throw std::runtime_error("Pkcs11HsmProvider: HSM C_WrapKey (RFC 3394) failed (rv=" + std::to_string(rv) + ")");
    }
    return vault_crypto::bytes_to_hex(wrapped, wrapped_len);
}

vault_crypto::SecretKey Pkcs11HsmProvider::unwrap_dek_hex(const std::string& wrapped_hex) const {
    using namespace pkcs11_abi;
    const auto wrapped = vault_crypto::hex_to_bytes(wrapped_hex);
    if (wrapped.size() != vault_crypto::WRAPPED_KEY_LEN) {
        throw std::runtime_error("Pkcs11HsmProvider: invalid wrapped DEK length");
    }

    std::lock_guard<std::mutex> lock(pkcs11_mutex_);

    CK_ULONG obj_class = CKO_SECRET_KEY;
    CK_ULONG key_type  = CKK_AES;
    CK_BBOOL ck_true   = 1;
    CK_BBOOL ck_false  = 0;
    CK_ATTRIBUTE unwrap_tmpl[] = {
        {CKA_CLASS,       &obj_class, sizeof(obj_class)},
        {CKA_KEY_TYPE,    &key_type,  sizeof(key_type)},
        {CKA_TOKEN,       &ck_false,  sizeof(ck_false)},
        {CKA_SENSITIVE,   &ck_false,  sizeof(ck_false)},
        {CKA_EXTRACTABLE, &ck_true,   sizeof(ck_true)}
    };

    CK_MECHANISM mech{CKM_AES_KEY_WRAP, nullptr, 0};
    CK_OBJECT_HANDLE dek_obj = 0;
    const CK_RV unwrap_rv = fn_->C_UnwrapKey(
        session_, &mech, kek_handle_,
        const_cast<CK_BYTE*>(wrapped.data()), static_cast<CK_ULONG>(wrapped.size()),
        unwrap_tmpl, 5, &dek_obj);
    if (unwrap_rv != CKR_OK) {
        throw std::runtime_error("Pkcs11HsmProvider: HSM C_UnwrapKey failed (rv=" + std::to_string(unwrap_rv) + ")");
    }

    vault_crypto::SecretKey dek;
    CK_ATTRIBUTE val_attr{CKA_VALUE, dek.data(), static_cast<CK_ULONG>(vault_crypto::SecretKey::size())};
    const CK_RV rv = fn_->C_GetAttributeValue(session_, dek_obj, &val_attr, 1);
    fn_->C_DestroyObject(session_, dek_obj);
    if (rv != CKR_OK) {
        dek.cleanse();
        throw std::runtime_error("Pkcs11HsmProvider: failed to read unwrapped session DEK (rv=" + std::to_string(rv) + ")");
    }
    return dek;
}

std::string Pkcs11HsmProvider::hmac_index_hex(std::string_view body) const {
    return sign_hmac_in_hsm(index_handle_, body);
}

std::string Pkcs11HsmProvider::hmac_audit_hex(std::string_view body) const {
    return sign_hmac_in_hsm(audit_handle_, body);
}

std::array<uint8_t, 32> Pkcs11HsmProvider::derive_tokenizer_pepper() const {
    // Use the HSM-resident generic-secret HMAC key (CKM_SHA256_HMAC is invalid on CKK_AES keys)
    const std::string mac = sign_hmac_in_hsm(index_handle_, "blindvault:pepper:v1");
    const auto raw = vault_crypto::hex_to_bytes(mac);
    std::array<uint8_t, 32> pepper{};
    if (raw.size() != pepper.size()) {
        throw std::runtime_error("Pkcs11HsmProvider: invalid derived tokenizer pepper");
    }
    std::copy(raw.begin(), raw.end(), pepper.begin());
    return pepper;
}

void Pkcs11HsmProvider::rotate_master_kek(const vault_crypto::SecretKey&) {
    throw std::runtime_error("Pkcs11HsmProvider: rotate_master_kek must be performed through HSM administration");
}

std::string Pkcs11HsmProvider::backend_description() const {
    return "Hardware-HSM-PKCS11 (" + module_path_ + ", KEK non-extractable in hardware)";
}

bool Pkcs11HsmProvider::is_master_kek_non_extractable() const {
    using namespace pkcs11_abi;
    std::lock_guard<std::mutex> lock(pkcs11_mutex_);
    CK_BBOOL extractable = 1;
    CK_ATTRIBUTE attr{CKA_EXTRACTABLE, &extractable, sizeof(extractable)};
    if (fn_->C_GetAttributeValue(session_, kek_handle_, &attr, 1) != CKR_OK || extractable != 0) {
        return false;
    }
    uint8_t leak_buf[32]{};
    CK_ATTRIBUTE val_attr{CKA_VALUE, leak_buf, sizeof(leak_buf)};
    const CK_RV rv = fn_->C_GetAttributeValue(session_, kek_handle_, &val_attr, 1);
    OPENSSL_cleanse(leak_buf, sizeof(leak_buf));
    return rv != CKR_OK;
}

pkcs11_abi::CK_OBJECT_HANDLE Pkcs11HsmProvider::find_key_by_label(const std::string& label) const {
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

std::string Pkcs11HsmProvider::sign_hmac_in_hsm(pkcs11_abi::CK_OBJECT_HANDLE key_handle,
                                                std::string_view body) const {
    using namespace pkcs11_abi;
    std::lock_guard<std::mutex> lock(pkcs11_mutex_);
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
#endif

std::shared_ptr<KeyManagementProvider> create_default_kms(const std::filesystem::path& state_dir) {
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
