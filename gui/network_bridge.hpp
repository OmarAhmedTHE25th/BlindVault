#pragma once
#include <QObject>
#include <QString>
#include <QList>
#include <QPair>
#include <thread>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "trust_store.hpp"
#include "server_node.hpp"
#include "client_node.hpp"
#include "vault_gateway.hpp"
#include "log_redirect.hpp"

class NetworkBridge : public QObject {
    Q_OBJECT
public:
    explicit NetworkBridge(QObject* parent = nullptr);
    ~NetworkBridge() override;

    void setIdentityPassphrase(const QString& passphrase);
    void startServer(uint16_t port, const QString& saveDir);
    void sendFile(const QString& host, uint16_t port, const QString& filePath);

    // BlindVault Hardened RegTech Pipeline Methods
    void generateSyntheticBatch(quint64 rowCount);
    void ingestAndOffloadCsv(const QString& host, uint16_t port, const QString& csvPath);
    void prepareReleaseChallenge(const QString& identifier);
    void importOfficerPublicKey(const QString& pubKeyPath);
    void queryAuditorRecords(const QString& identifier,
                             const QString& cloudDir,
                             const QList<QPair<QString, QString>>& detachedApprovals);

signals:
    void logMessage(const QString& msg);
    void transferProgress(int percentage, quint64 transferred, quint64 total);
    void transferCompleted(bool success, const QString& status);
    void peerAuthenticated(const QString& name, const QString& fingerprint);
    void serverStatus(bool ok, const QString& message);
    void receiveProgress(int percentage, quint64 received, quint64 total);
    void receiveFinished(bool ok, const QString& message);

    // BlindVault Hardened RegTech Signals
    void syntheticBatchReady(const QString& csvPath);
    void offloadTelemetryReady(quint64 records, quint64 piiTokenized, quint64 ipsMasked,
                               quint64 paddedBytes, quint64 shardBytes,
                               double elapsedMs, double recordsPerSec, const QString& blobName);
    void releaseChallengeReady(const QString& targetToken,
                               const QString& challengeSummary,
                               const QString& registeredOfficersSummary);
    void officerPublicKeyImported(const QString& statusMessage);
    void auditorQueryCompleted(bool authorized, bool found, const QString& statusOrToken,
                               const QString& restoredCsv, const QString& rawCloudHex);

private:
    boost::asio::io_context io_ctx_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    std::thread worker_thread_;

    std::shared_ptr<trust::TrustStore> trust_store_;
    std::unique_ptr<vault_gateway::GatewayEngine> gateway_engine_;
    std::string identity_passphrase_;
    std::unique_ptr<boost::asio::ssl::context> server_ssl_ctx_;
    std::unique_ptr<boost::asio::ssl::context> client_ssl_ctx_;
    std::shared_ptr<ServerNode> server_node_;
    std::unique_ptr<LineForwardBuf> cout_fwd_;
    std::unique_ptr<LineForwardBuf> cerr_fwd_;
};
