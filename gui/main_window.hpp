#pragma once

#include <QMainWindow>
#include <QLineEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QTextEdit>
#include <QTableWidget>
#include <QLabel>
#include <QFrame>
#include <QCheckBox>
#include "network_bridge.hpp"

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void onBrowseFile();
    void onBrowseSaveDir();
    void onCopyFingerprint() const;
    void onClearLog() const;
    void onGenerateSynthetic();
    void onOffloadCsv();
    void onStartServer();
    void onAuditorSearch();
    void onAddPeer();
    void onRemovePeer();

    void onLogMessage(const QString& msg) const;
    void onTransferProgress(int percentage, quint64 transferred, quint64 total) const;
    void onTransferCompleted(bool success, const QString& status) const;
    void onSyntheticBatchReady(const QString& csvPath);
    void onOffloadTelemetryReady(quint64 records, quint64 piiTokenized, quint64 ipsMasked,
                                 quint64 paddedBytes, quint64 shardBytes,
                                 double elapsedMs, double recordsPerSec, const QString& blobName);
    void onAuditorQueryCompleted(bool authorized, bool found, const QString& statusOrToken,
                                 const QString& restoredCsv, const QString& rawCloudHex);

    void refreshPeerList() const;
    void onServerStatus(bool ok, const QString& message);
    void onReceiveProgress(int percentage, quint64 received, quint64 total);
    void onReceiveFinished(bool ok, const QString& message) const;

private:
    void setupUi();
    bool initializeIdentity();
    QWidget* createEgressGatewayTab();
    QWidget* createAuditorTab();
    QWidget* createCloudAndTrustTab();

    NetworkBridge* bridge_ = nullptr;

    // Identity widgets
    QString raw_fingerprint_;
    QLabel* fp_label_ = nullptr;
    QPushButton* copy_fp_btn_ = nullptr;

    // Tab 1: Bank Egress Gateway widgets
    QLineEdit* host_input_ = nullptr;
    QLineEdit* port_input_ = nullptr;
    QLineEdit* file_path_input_ = nullptr;
    QPushButton* gen_synth_btn_ = nullptr;
    QPushButton* send_btn_ = nullptr;
    QProgressBar* progress_bar_ = nullptr;
    QLabel* transfer_status_lbl_ = nullptr;
    QLabel* telemetry_lbl_ = nullptr;
    QLabel* hardening_lbl_ = nullptr;

    // Tab 2: Auditor Re-Hydration & Cloud Proof widgets
    QLineEdit* auditor_query_input_ = nullptr;
    QPushButton* auditor_search_btn_ = nullptr;
    QCheckBox* officer1_chk_ = nullptr;
    QCheckBox* officer2_chk_ = nullptr;
    QCheckBox* officer3_chk_ = nullptr;
    QLabel* auditor_token_lbl_ = nullptr;
    QTableWidget* auditor_table_ = nullptr;
    QTextEdit* cloud_hex_view_ = nullptr;

    // Tab 3: Untrusted Cloud Vault & Peer Trust widgets
    QLineEdit* server_port_input_ = nullptr;
    QLineEdit* save_dir_input_ = nullptr;
    QPushButton* server_toggle_btn_ = nullptr;
    QLabel* server_status_lbl_ = nullptr;
    QProgressBar* recv_progress_bar_ = nullptr;
    QTableWidget* peer_table_ = nullptr;
    QLineEdit* peer_name_input_ = nullptr;
    QLineEdit* peer_fp_input_ = nullptr;

    // Activity log
    QTextEdit* log_pane_ = nullptr;
};