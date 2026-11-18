#include "network_bridge.hpp"
#include "tls_trust.hpp"
#include "identity.hpp"
#include <QStandardPaths>
#include <QDir>
#include <QStringList>
#include <filesystem>
#include <iostream>
#include <sstream>
#include "client_node.hpp"
#include "events.hpp"

namespace {
std::filesystem::path getIdentityDirectory() {
    const QString qPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (const QDir dir(qPath); !dir.exists() && !dir.mkpath(".")) {
        throw std::runtime_error("cannot create identity directory: " + qPath.toStdString());
    }
#ifdef _WIN32
    return std::filesystem::path(qPath.toStdWString());
#else
    return {qPath.toStdString()};
#endif
}
} // namespace

NetworkBridge::NetworkBridge(QObject* parent)
    : QObject(parent),
      work_guard_(boost::asio::make_work_guard(io_ctx_)),
      trust_store_(std::make_shared<trust::TrustStore>(getIdentityDirectory() / identity::TRUST_FILE)),
      gateway_engine_(std::make_unique<vault_gateway::GatewayEngine>(getIdentityDirectory(), /*quorum_threshold=*/2)) {
    worker_thread_ = std::thread([this]() {
        io_ctx_.run();
    });
    auto forward = [this](const std::string& line) {
        emit logMessage(QString::fromStdString(line));
    };
    cout_fwd_ = std::make_unique<LineForwardBuf>(std::cout, forward);
    cerr_fwd_ = std::make_unique<LineForwardBuf>(std::cerr, forward);
}

NetworkBridge::~NetworkBridge() {
    work_guard_.reset();
    io_ctx_.stop();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void NetworkBridge::setIdentityPassphrase(const QString& passphrase) {
    identity_passphrase_ = passphrase.toStdString();
}

void NetworkBridge::startServer(uint16_t port, const QString& saveDir) {
    boost::asio::post(io_ctx_, [this, port, saveDir]() {
        try {
            server_ssl_ctx_ = std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv13_server);

            auto cert_file = getIdentityDirectory() / identity::CERT_FILE;
            auto key_file  = getIdentityDirectory() / identity::KEY_FILE;
            tls_trust::configure_server(*server_ssl_ctx_, trust_store_, cert_file, key_file, identity_passphrase_);

            TransferEvents events;
            events.on_finished = [this](bool ok, const std::string& msg) {
                emit receiveFinished(ok, QString::fromStdString(msg));
            };
            events.on_progress = [this](uint64_t done, uint64_t total) {
                const int pct = total ? static_cast<int>((done * 100) / total) : 100;
                emit receiveProgress(pct, done, total);
            };

            std::filesystem::path save_path = saveDir.toStdString();
            server_node_ = std::make_shared<ServerNode>(io_ctx_, *server_ssl_ctx_, port, save_path, trust_store_, std::move(events));
            server_node_->start();

            emit serverStatus(true, QString("Cloud Vault Node active on port %1 (storing BVLT v2 ciphertext in '%2')")
                                        .arg(port).arg(saveDir));
        } catch (const std::exception& e) {
            emit logMessage(QString("[CLOUD NODE ERROR] %1").arg(e.what()));
            emit serverStatus(false, QString::fromStdString(e.what()));
        }
    });
}

void NetworkBridge::sendFile(const QString& host, uint16_t port, const QString& filePath) {
    boost::asio::post(io_ctx_, [this, host, port, filePath]() {
        try {
            client_ssl_ctx_ = std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv13_client);

            auto cert_file = getIdentityDirectory() / identity::CERT_FILE;
            auto key_file  = getIdentityDirectory() / identity::KEY_FILE;
            tls_trust::configure_client(*client_ssl_ctx_, trust_store_, cert_file, key_file, identity_passphrase_);

            TransferEvents events;
            events.on_progress = [this](uint64_t done, uint64_t total) {
                const int pct = total ? static_cast<int>((done * 100) / total) : 100;
                emit transferProgress(pct, done, total);
            };
            events.on_finished = [this](bool ok, const std::string& message) {
                emit transferCompleted(ok, QString::fromStdString(message));
            };
            events.on_peer = [this](const std::string& name, const std::string& fp) {
                emit peerAuthenticated(QString::fromStdString(name), QString::fromStdString(fp));
            };

            auto client = std::make_shared<ClientNode>(io_ctx_, *client_ssl_ctx_, std::move(events), trust_store_);
            emit logMessage(QString("[GATEWAY] Streaming 64KiB-padded BVLT v2 blob %1 to Cloud Node %2:%3...")
                                .arg(filePath, host).arg(port));
            client->send_file(std::to_string(port), host.toStdString(), filePath.toStdString());
        } catch (const std::exception& e) {
            emit logMessage(QString("[GATEWAY ERROR] %1").arg(e.what()));
            emit transferCompleted(false, QString::fromStdString(e.what()));
        }
    });
}

void NetworkBridge::generateSyntheticBatch(quint64 rowCount) {
    boost::asio::post(io_ctx_, [this, rowCount]() {
        try {
            emit logMessage(QString("[GATEWAY] Generating %1 synthetic Egyptian banking transactions...").arg(rowCount));
            const auto path = gateway_engine_->generate_synthetic_cbe_batch(static_cast<std::size_t>(rowCount));
            emit logMessage(QString("[GATEWAY] Synthetic batch ready: %1").arg(QString::fromStdString(path.string())));
            emit syntheticBatchReady(QString::fromStdString(path.string()));
        } catch (const std::exception& e) {
            emit logMessage(QString("[GATEWAY ERROR] %1").arg(e.what()));
        }
    });
}

void NetworkBridge::ingestAndOffloadCsv(const QString& host, uint16_t port, const QString& csvPath) {
    boost::asio::post(io_ctx_, [this, host, port, csvPath]() {
        try {
            emit logMessage("[GATEWAY] Hardened Egress: Tokenizing PII -> 64KiB Traffic Padding -> AES-256-GCM -> RFC 3394 DEK Wrap -> 2-of-3 Erasure Shards...");
            const auto artifact = gateway_engine_->prepare_encrypted_offload(csvPath.toStdString());

            emit logMessage(QString("[GATEWAY] Processed %1 records (%2 PII tokenized, %3 IPs masked) in %4 ms (%5 rec/s)")
                                .arg(artifact.stats.records_processed)
                                .arg(artifact.stats.pii_fields_tokenized)
                                .arg(artifact.stats.ips_masked)
                                .arg(artifact.elapsed_ms, 0, 'f', 2)
                                .arg(artifact.records_per_sec, 0, 'f', 0));
            emit logMessage(QString("[HARDENING] Padded Envelope: %1 bytes | 3x Erasure Shards (%2 bytes each) | DEK Wrapped & Cleansed from RAM")
                                .arg(artifact.padded_size_bytes)
                                .arg(artifact.erasure_shard_bytes));

            emit offloadTelemetryReady(
                artifact.stats.records_processed,
                artifact.stats.pii_fields_tokenized,
                artifact.stats.ips_masked,
                artifact.padded_size_bytes,
                artifact.erasure_shard_bytes,
                artifact.elapsed_ms,
                artifact.records_per_sec,
                QString::fromStdString(artifact.blob_name));

            sendFile(host, port, QString::fromStdString(artifact.encrypted_file_path.string()));
        } catch (const std::exception& e) {
            emit logMessage(QString("[GATEWAY ERROR] %1").arg(e.what()));
            emit transferCompleted(false, QString::fromStdString(e.what()));
        }
    });
}

void NetworkBridge::importOfficerPublicKey(const QString& pubKeyPath) {
    boost::asio::post(io_ctx_, [this, pubKeyPath]() {
        try {
            const std::filesystem::path src(pubKeyPath.toStdString());
            if (!std::filesystem::exists(src) || src.extension() != ".pub") {
                throw std::runtime_error("Select a valid officer Ed25519 public key file (*.pub)");
            }
            const auto dest = gateway_engine_->officer_pubkey_directory() / src.filename();
            std::filesystem::copy_file(src, dest, std::filesystem::copy_options::overwrite_existing);
            gateway_engine_->quorum_gate().reload_public_keys();

            const auto officers = gateway_engine_->quorum_gate().registered_officers();
            QStringList names;
            for (const auto& o : officers) names << QString::fromStdString(o);
            const QString summary = QString("Installed '%1' | Registered Officers (%2): %3")
                                        .arg(QString::fromStdString(src.stem().string()))
                                        .arg(officers.size())
                                        .arg(names.join(", "));
            emit logMessage("[QUORUM] " + summary);
            emit officerPublicKeyImported(summary);
        } catch (const std::exception& e) {
            emit logMessage(QString("[QUORUM ERROR] %1").arg(e.what()));
            emit officerPublicKeyImported(QString("Error: %1").arg(e.what()));
        }
    });
}

void NetworkBridge::prepareReleaseChallenge(const QString& identifier) {
    boost::asio::post(io_ctx_, [this, identifier]() {
        try {
            const auto challenge = gateway_engine_->prepare_release_challenge(identifier.toStdString());
            QStringList officerNames;
            for (const auto& id : challenge.registered_officers) {
                officerNames << QString::fromStdString(id);
            }
            const QString officersStr = officerNames.isEmpty()
                ? QString("None registered yet (import *.pub keys in %1)")
                      .arg(QString::fromStdString(gateway_engine_->officer_pubkey_directory().string()))
                : officerNames.join(", ");

            std::ostringstream ss;
            ss << "Target Token: " << challenge.target_token << "\n";
            if (challenge.candidate_blobs.empty()) {
                ss << "Candidate Blobs: None matched (sign against blob_name=NONE, wrapped_dek_hex=NONE)\n"
                   << "CLI: BlindVault officer-sign <officer.priv> <officer_id> "
                   << challenge.target_token << " NONE NONE";
            } else {
                for (const auto& blob : challenge.candidate_blobs) {
                    ss << "Blob: " << blob.blob_name << "\n"
                       << "Wrapped DEK: " << blob.wrapped_dek_hex << "\n"
                       << "Offline Sign Command:\n"
                       << "  BlindVault officer-sign <officer.priv> <officer_id> "
                       << challenge.target_token << " " << blob.blob_name << " " << blob.wrapped_dek_hex << "\n";
                }
            }

            emit logMessage(QString("[QUORUM] Prepared signing challenge for token %1 (%2 candidate blob(s))")
                                .arg(QString::fromStdString(challenge.target_token))
                                .arg(challenge.candidate_blobs.size()));
            emit releaseChallengeReady(
                QString::fromStdString(challenge.target_token),
                QString::fromStdString(ss.str()),
                officersStr);
        } catch (const std::exception& e) {
            emit logMessage(QString("[QUORUM ERROR] %1").arg(e.what()));
        }
    });
}

void NetworkBridge::queryAuditorRecords(const QString& identifier,
                                        const QString& cloudDir,
                                        const QList<QPair<QString, QString>>& detachedApprovals) {
    boost::asio::post(io_ctx_, [this, identifier, cloudDir, detachedApprovals]() {
        try {
            std::vector<vault_index::OfficerApproval> approvals;
            approvals.reserve(static_cast<std::size_t>(detachedApprovals.size()));
            for (const auto& pair : detachedApprovals) {
                const std::string id = pair.first.trimmed().toStdString();
                const std::string sig = pair.second.trimmed().toStdString();
                if (!id.empty() && !sig.empty()) {
                    approvals.push_back(vault_index::OfficerApproval{id, sig});
                }
            }

            const auto res = gateway_engine_->auditor_query(
                identifier.toStdString(), cloudDir.toStdString(), approvals);
            if (!res.authorized) {
                emit logMessage(QString("[SECURITY BLOCK] %1").arg(QString::fromStdString(res.denial_reason)));
                emit auditorQueryCompleted(false, false, QString::fromStdString(res.denial_reason), "", "");
                return;
            }

            if (res.found) {
                emit logMessage(QString("[AUDITOR] Ed25519 Quorum Verified! Unwrapped DEK via RFC 3394 & re-hydrated %1.")
                                    .arg(QString::fromStdString(res.matched_token)));
            } else {
                emit logMessage(QString("[AUDITOR] Ed25519 Quorum Verified, no archived blobs matched '%1' (token: %2).")
                                    .arg(identifier, QString::fromStdString(res.matched_token)));
            }

            emit auditorQueryCompleted(
                true,
                res.found,
                QString::fromStdString(res.matched_token),
                QString::fromStdString(res.restored_csv),
                QString::fromStdString(res.raw_cloud_hex_preview));
        } catch (const std::exception& e) {
            emit logMessage(QString("[AUDITOR ERROR] %1").arg(e.what()));
        }
    });
}
