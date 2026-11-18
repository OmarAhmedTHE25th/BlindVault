# BlindVault — Hardened Zero-Knowledge RegTech Storage Gateway

A high-throughput, zero-knowledge storage gateway and secure transfer engine written in C++20 with Boost.Asio, OpenSSL 3, and Qt 6. Designed for banking and RegTech compliance, **BlindVault** sits between a bank's core transaction perimeter and low-cost commodity cloud storage—stripping PII, masking internal/client IP addresses, padding payloads to fixed 64 KiB buckets, encrypting at rest with **AES-256-GCM (`BVL2`)** bound to blob-name AAD, wrapping batch keys under a Master KEK via **RFC 3394** (backed by PKCS#11 HSM or local software KMS), and streaming blobs over **mutual TLS 1.3** with strict certificate fingerprint pinning.

Even if the remote storage server is compromised or inspected by an untrusted administrator, the cloud node holds zero customer identities, zero IP metadata, zero batch-size signals, and zero decryption keys. Inside the bank perimeter, unmasking customer PII requires **2-of-3 Compliance Officer Quorum** cryptographic sign-off bound to the target token and blob.

## Contents

* [Architecture & Hardened RegTech Pipeline](#architecture--hardened-regtech-pipeline)
* [Core & Hardening Features](#core--hardening-features)
* [Quick Start](#quick-start)
* [Hardware HSM Configuration (PKCS#11)](#hardware-hsm-configuration-pkcs11)
* [Opening the Qt 6 Desktop Console](#opening-the-qt-6-desktop-console)
* [CLI Usage](#cli-usage)
* [How It Works](#how-it-works)
* [Threat Model](#threat-model)
* [Known Limitations](#known-limitations)
* [Testing & Fuzzing](#testing--fuzzing)
* [Project Structure](#project-structure)
* [License](#license)

## Architecture & Hardened RegTech Pipeline

BlindVault separates **identity, key custody, and quorum governance** (strictly inside the bank's perimeter) from **bulk encrypted storage** (offloaded to low-cost commodity object/disk storage):

```mermaid
flowchart LR
    subgraph Bank["Bank On-Premise Perimeter (Trusted)"]
        Core["Core Banking Batch (CSV)"] --> Tok["TokenVault (tokenizer.hpp)<br/>HMAC-SHA256 PII & IP Scrubbing + BVTK"]
        Tok --> Enc["At-Rest Crypto (at_rest_crypto.hpp)<br/>64 KiB Pad + AES-256-GCM (BVL2 + AAD)"]
        Enc --> KMS["KMS / PKCS#11 HSM (kms_provider.hpp)<br/>RFC 3394 KEK Wrap + Non-Extractable KEK"]
        KMS --> Idx["MetadataIndex & Quorum (vault_index.hpp)<br/>Data-Bound 2-of-3 Quorum + Chained Audit"]
        Enc --> Shards["2-of-3 XOR Erasure Shards"]
    end

    Enc --> Client["ClientNode (client_node.hpp)<br/>Mutual TLS 1.3 + SHA-256 Stream"]
    Client -->|"64 KiB-Padded .enc Blob Only"| Cloud["Cloud Vault Node (ServerNode)<br/>Zero-Knowledge Storage"]
```

1. **Pre-Egress Sanitization & Encrypted Token Vault (`tokenizer.hpp`):** Parses RFC 4180 transaction records in memory, replaces customer names, National IDs, and IBANs with deterministic `TOK_<16-hex>` HMAC-SHA256 tokens using a KMS-derived pepper, and redacts source IP addresses (`REDACTED_IP`). Persists bidirectional mappings atomically in `vault_tokens.enc` (`BVTK` AES-256-GCM envelope with a KMS-wrapped DEK and `0600` permissions).
2. **Traffic-Analysis Padding & AAD-Bound Encryption at Rest (`at_rest_crypto.hpp`):** Pads the scrubbed payload with CSPRNG noise to an exact multiple of **64 KiB** (`65,536` bytes) to defeat file-size traffic analysis, then seals it in a binary `BVL2` envelope using **AES-256-GCM** (96-bit IV, 128-bit authentication tag, and the blob filename bound as Additional Authenticated Data to block blob-swap attacks).
3. **PKCS#11 HSM / KMS Key Wrapping, Memory Cleansing & Erasure Sharding (`kms_provider.hpp`, `at_rest_crypto.hpp`):** Wraps each batch's Data Encryption Key (DEK) under a Master Key Encryption Key (KEK) via **RFC 3394 (`CKM_AES_KEY_WRAP` / `EVP_aes_256_wrap`)** so zero plaintext keys ever touch disk, wipes plaintext keys and decrypted buffers from RAM via move-only RAII `OPENSSL_cleanse` (`RLIMIT_CORE=0`), and splits blobs into **2-of-3 XOR erasure shards**.
4. **Zero-Trust Transport (`client_node.hpp` & `tls_trust.hpp`):** Streams `.enc` blobs over **TLS 1.3** with mutual certificate fingerprint verification and end-to-end **SHA-256** integrity checks.
5. **Data-Bound M-of-N Quorum Auditor Re-Hydration (`vault_index.hpp` & `vault_gateway.hpp`):** Authorized auditors query by customer name, National ID, IBAN, or `TOK_...` identifier only after collecting constant-time HMAC approvals from at least **2 of 3 Compliance Officers** cryptographically bound to `(target_token, blob_name, wrapped_dek_hex)`. The gateway unwraps the DEK, decrypts in memory, filters exact PII columns, re-hydrates tokens, cleanses RAM, and appends an entry to the HMAC hash-chained `regtech_audit.log`.

## Core & Hardening Features

* **Zero-Knowledge Cloud Offloading:** Remote storage nodes only receive 64 KiB-padded `BVL2` AES-256-GCM ciphertext blobs—never plaintext PII, internal IP addresses, batch size signatures, or AES keys.
* **PKCS#11 Hardware HSM & Software KMS (`kms_provider.hpp`):** Pluggable `KeyManagementProvider` supporting FIPS 140-3 PKCS#11 v2.40 HSMs (SoftHSMv2, AWS CloudHSM, Thales Luna, Utimaco) where the Master KEK never enters process memory (`CKA_EXTRACTABLE=FALSE`), with seamless local `0600` KEK fallback and full Master KEK rotation (`rotate_master_kek`).
* **RFC 3394 Envelope Key Wrapping & Blob-Swap Protection:** Per-batch DEKs are wrapped with a 256-bit Master KEK before persisting to `vault_index.tsv`; blob filenames are authenticated via GCM AAD so ciphertext blobs cannot be swapped across index records.
* **Data-Bound 2-of-3 Compliance Officer Quorum Gate:** Enforces multi-custody constant-time (`CRYPTO_memcmp`) HMAC authorization bound to the specific token, blob name, and wrapped DEK before `detokenize()` unmasks customer PII.
* **Tamper-Evident Index & Hash-Chained Audit Log:** `vault_index.tsv` is authenticated with a domain-separated HMAC-SHA256 MAC (`blindvault:index-auth:v1`), and `regtech_audit.log` links every sequence entry to the previous entry's HMAC (`blindvault:audit-auth:v1`).
* **RAII Memory Zeroization & Core-Dump Lock:** Move-only `SecretKey` and `SecretBuffer` types scrub sensitive material from RAM with `OPENSSL_cleanse()` on move and destruction, paired with `RLIMIT_CORE=0` process hardening.
* **2-of-3 XOR Erasure Coding:** Generates 3 parity/data shards per encrypted batch so any 2 storage providers reconstruct the full ciphertext while 1 compromised or offline provider reveals nothing.
* **Encrypted Bidirectional Token Vault (`BVTK`):** In-memory O(1) `TokenVault` backed by KMS-derived HMAC-SHA256 peppers and atomic AES-256-GCM disk persistence (`vault_tokens.enc`).
* **Mutual TLS 1.3 with Per-Node Identities:** Only TLS 1.3 is accepted. Each node generates an EC P-256 keypair and self-signed certificate (with optional AES-256-CBC private key passphrase encryption), authenticating peers strictly via SHA-256 certificate fingerprints (`trusted_peers.txt`).
* **Disk Exhaustion Protection & Atomic Staging (`disk_budget.hpp`, `validation.hpp`):** Concurrent uploads reserve space from a shared mutex-protected budget keeping a 100 MiB safety margin, write to `.part` files, and rename atomically only after SHA-256 verification.

## Quick Start

Tested on Ubuntu 24.04 (including WSL) with GCC 13 and Clang 18.

```bash
# 1. Install dependencies (Debian/Ubuntu)
sudo apt update
sudo apt install -y build-essential cmake ninja-build libboost-dev libboost-system-dev libssl-dev

# 2. Clone and build
git clone https://github.com/OmarAhmedTHE25th/CipherVault.git
cd CipherVault
cmake -S . -B build -G Ninja
cmake --build build
```

## Hardware HSM Configuration (PKCS#11)

By default, BlindVault uses `LocalSoftwareKmsProvider` (storing `hsm_master.kek` with `0600` permissions). On Linux/POSIX systems, set two environment variables to bind directly to any PKCS#11 v2.40 HSM (e.g., SoftHSMv2, AWS CloudHSM, Thales Luna) with zero external SDK headers required:

```bash
export BLINDVAULT_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export BLINDVAULT_PKCS11_PIN=1234
```

The HSM token must contain three non-extractable secret keys labeled `blindvault-master-kek` (`CKK_AES`), `blindvault-index-hmac` (`CKK_GENERIC_SECRET`), and `blindvault-audit-hmac` (`CKK_GENERIC_SECRET`).

## Opening the Qt 6 Desktop Console

The desktop application provides a three-tab RegTech operations and audit console:

1. **Bank Egress Gateway:** Generate synthetic Egyptian banking transaction batches (`10,000` records) or load a CSV, scrub PII/IPs, pad to 64 KiB, wrap DEKs via RFC 3394, generate 2-of-3 erasure shards, inspect live `records/sec` throughput telemetry, and stream `.enc` blobs to the cloud node.
2. **Quorum Auditor & Cloud Proof:** Toggle **2-of-3 Compliance Officer** cryptographic sign-offs, query records by Customer Name, National ID, IBAN, or `TOK_...` token to inspect the decrypted/re-hydrated bank table alongside a raw hex dump proving what resides on the cloud disk.
3. **Cloud Vault & Node Trust:** Start the local cloud storage receiver node and manage pinned SHA-256 node fingerprints.

```bash
# Install Qt 6 development packages
sudo apt install -y qt6-base-dev libgl1-mesa-dev

# Configure and build the GUI
cmake -S . -B build-gui -G Ninja -DP2P_BUILD_GUI=ON -DP2P_BUILD_TESTS=OFF
cmake --build build-gui --target BlindVault_GUI

# Launch
./build-gui/BlindVault_GUI
```

## CLI Usage

The underlying transport binary supports headless CLI transfers, bidirectional P2P sessions, and node identity management:

```text
BlindVault receive <port> [save_folder]
BlindVault send <host> <port> <file>
BlindVault p2p <port> [save_folder]

BlindVault init [--force] [name]
BlindVault fingerprint
BlindVault trust add <fingerprint> <name>
BlindVault trust list
BlindVault trust remove <name|fingerprint>
```

### Setting Up Two Nodes Locally

```bash
cd build
mkdir bank_gateway cloud_vault

# 1. Generate EC P-256 identities
(cd bank_gateway && ../BlindVault init bank_gateway < /dev/null)
(cd cloud_vault  && ../BlindVault init cloud_vault < /dev/null)

# 2. Exchange and pin certificate fingerprints
(cd bank_gateway && ../BlindVault trust add "$(cd ../cloud_vault && ../BlindVault fingerprint | sed 's/^Your fingerprint: //')" cloud_vault)
(cd cloud_vault  && ../BlindVault trust add "$(cd ../bank_gateway && ../BlindVault fingerprint | sed 's/^Your fingerprint: //')" bank_gateway)

# 3. Start Cloud Vault listener (Terminal 1)
(cd cloud_vault && ../BlindVault receive 8080)

# 4. Send an encrypted blob from Bank Gateway (Terminal 2)
(cd bank_gateway && ../BlindVault send localhost 8080 payload.enc)
```

## How It Works

### Wire Protocol (`protocol.hpp`)

Every control message uses a packed **47-byte big-endian header**:

| Offset | Size | Field | Meaning |
| -----: | ---: | ----- | ------- |
| 0 | 1 | `msg_type` | `0x01` METADATA, `0x02` CHUNK (reserved), `0x03` END_OF_FILE, `0x04` ACK |
| 1 | 4 | `payload_len` | Bytes following the header (filename length for METADATA) |
| 5 | 8 | `total_file_size` | Total payload size in bytes |
| 13 | 2 | `filename_len` | Filename byte length |
| 15 | 32 | `file_hash` | SHA-256 digest of the complete file |

### At-Rest Encrypted Envelope (`at_rest_crypto.hpp` — `BVL2`)

Every `.enc` object offloaded to cloud storage uses a 32-byte binary header followed by 64 KiB-aligned AES-256-GCM ciphertext (with `blob_name` authenticated as GCM AAD):

| Offset | Size | Field | Meaning |
| -----: | ---: | ----- | ------- |
| 0 | 4 | `magic` | ASCII `BVL2` (`0x42 0x56 0x4C 0x32`) |
| 4 | 12 | `iv` | 96-bit CSPRNG nonce (`RAND_bytes`) |
| 16 | 16 | `auth_tag` | 128-bit AES-GCM integrity tag |
| 32 | *64 KiB × k* | `ciphertext` | AES-256-GCM encrypted `[8B real_len \| tokenized CSV \| CSPRNG padding]` |

### Encrypted Token Vault Envelope (`tokenizer.hpp` — `BVTK`)

The bidirectional PII lookup table (`vault_tokens.enc`) is stored at rest using an 84-byte prefix followed by an unpadded `BVL2` AES-256-GCM ciphertext (with `"BVTK:v1"` authenticated as GCM AAD):

| Offset | Size | Field | Meaning |
| -----: | ---: | ----- | ------- |
| 0 | 4 | `magic` | ASCII `BVTK` (`0x42 0x56 0x54 0x4B`) |
| 4 | 80 | `wrapped_dek_hex` | 40-byte RFC 3394 KMS/HSM-wrapped DEK encoded as 80 hex characters |
| 84 | *variable* | `bvl2_envelope` | AES-256-GCM encrypted `token\traw_value` mappings |

## Threat Model

| Threat | Mitigation | Verification |
| ------ | ---------- | ------------ |
| Cloud breach or rogue cloud admin | Client-side AES-256-GCM (`BVL2`) + HMAC-SHA256 PII tokenization prior to egress; keys never leave bank | Unit tests (`test_vault_core.cpp`) |
| IP-based tracking or topology leakage | Source/internal IP fields redacted (`REDACTED_IP`) before packaging; nodes authenticate via SHA-256 cert fingerprints | Unit tests (`test_vault_core.cpp`) |
| Rogue insider bulk PII scraping | **Data-bound 2-of-3 Compliance Officer Quorum Gate** requiring multi-officer constant-time HMAC sign-offs bound to `(token, blob_name, wrapped_dek_hex)` | Unit tests (`VaultHardening.EndToEndTokenSearchExactColumnMatchTamperIndexAndChainedAudit`) |
| Index tampering, blob swapping, or audit log deletion | HMAC-authenticated `vault_index.tsv`, blob-name GCM AAD binding, and HMAC hash-chained `regtech_audit.log` | Unit tests (`VaultCrypto.RejectsBlobNameSwapViaAad`, `test_vault_core.cpp`) |
| Host disk compromise / key scraping | **PKCS#11 HSM** or **RFC 3394 AES-256 Key Wrapping** (no raw DEKs on disk; `BVTK`-encrypted token map) + RAII `OPENSSL_cleanse` + `RLIMIT_CORE=0` | Unit tests (`VaultHardening.Rfc3394KeyWrapAnd64KiBTrafficPadding`, `Tokenizer.PersistsAcrossReloadsEncryptedAtRest`) |
| Cloud file-size / traffic inference | Fixed-bucket **64 KiB CSPRNG padding** on every `BVL2` envelope | Unit tests (`VaultHardening.Rfc3394KeyWrapAnd64KiBTrafficPadding`) |
| Single-cloud outage or ransomware | **2-of-3 XOR Erasure Sharding** reconstructing full ciphertext from any 2 surviving shards | Unit tests (`VaultHardening.TwoOfThreeErasureCodingSurvivesCloudNodeLoss`) |
| Eavesdropping or MITM in transit | Mutual TLS 1.3 only (TLS 1.2 refused) with strict SHA-256 fingerprint allowlisting on both ends | Unit & E2E tests (`test_e2e_trust.cpp`, `e2e_test.sh`) |
| Path traversal & parser corruption | Cross-OS strict filename/header validation + continuous libFuzzer + ASan/UBSan CI builds | GitHub Actions CI (`fuzz_validation`) |

## Known Limitations

* **PKCS#11 Platform Scope:** `Pkcs11HsmProvider` targets POSIX/Linux (`dlopen`); Windows deployments default to `LocalSoftwareKmsProvider`.
* **No Resume for Interrupted Streams:** Partial `.part` files are discarded on timeout or disconnect and must be re-sent from byte 0.
* **Global Connection Cap:** The 64-connection ceiling (`ServerNode::MAX_CONNECTIONS`) is global rather than per-IP rate-limited.

## Testing & Fuzzing

```bash
# Build and run all GoogleTest unit tests + end-to-end TLS script
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure < /dev/null

# Run with AddressSanitizer + UndefinedBehaviorSanitizer
cmake -S . -B build-san -G Ninja -DCMAKE_BUILD_TYPE=Debug -DP2P_SANITIZE=ON
cmake --build build-san
ctest --test-dir build-san --output-on-failure < /dev/null

# Run libFuzzer on header & filename validation (requires Clang)
cmake -S . -B build-fuzz -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DP2P_BUILD_TESTS=OFF -DP2P_BUILD_FUZZERS=ON
cmake --build build-fuzz --target fuzz_validation
mkdir -p corpus-work
./build-fuzz/fuzz_validation corpus-work fuzz/seeds -max_total_time=60
```

## Project Structure

```text
src/main.cpp          CLI entry point and argument parsing
include/
  vault/              Bank-side RegTech engine (at_rest_crypto, kms_provider, tokenizer, vault_index, vault_gateway)
  transport/
    client/           Outgoing transfer and P2P client headers
    server/           Cloud receiver and transfer session headers
    common/           Wire protocol, streaming, and shared events
  security/           mTLS, identities, allowlists, and input/disk guards
gui/                  Qt 6 desktop application and Boost.Asio thread bridge
tests/                GoogleTest unit & integration test suites
fuzz/                 libFuzzer target and seed corpus
scripts/              End-to-end TLS test harness and certificate helpers
.github/workflows/    CI (GCC/Clang, ASan/UBSan, libFuzzer) and Linux/Windows Release pipelines
```

## License

MIT — see [LICENSE](LICENSE).