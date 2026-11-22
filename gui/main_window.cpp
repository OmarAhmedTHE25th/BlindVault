#include "main_window.hpp"
#include <QHBoxLayout>
#include <QGridLayout>
#include <QFormLayout>
#include <QTabWidget>
#include <QFileDialog>
#include <QHeaderView>
#include <QMessageBox>
#include <QGuiApplication>
#include <QClipboard>
#include <QTimer>
#include <QStandardPaths>
#include <QDir>
#include <QPixmap>
#include <QScrollArea>
#include <QSplitter>
#include <QScreen>
#include <algorithm>
#include <filesystem>
#include "identity.hpp"
#include "trust_store.hpp"
#include "tokenizer.hpp"

namespace {
QScrollArea* wrapInScrollArea(QWidget* content) {
    auto* scroll = new QScrollArea();
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scroll->setWidget(content);
    return scroll;
}

std::filesystem::path getIdentityDirectory() {
    QString qPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(qPath);
    if (!dir.exists() && !dir.mkpath(".")) {
        throw std::runtime_error("cannot create identity directory: " + qPath.toStdString());
    }
#ifdef _WIN32
    return std::filesystem::path(qPath.toStdWString());
#else
    return {qPath.toStdString()};
#endif
}
} // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), bridge_(new NetworkBridge(this)) {
    setMinimumSize(1040, 700);
    QSize targetSize(1380, 900);
    if (const auto* screen = QGuiApplication::primaryScreen()) {
        const QRect avail = screen->availableGeometry();
        targetSize.setWidth(std::min(targetSize.width(), std::max(1040, avail.width() - 40)));
        targetSize.setHeight(std::min(targetSize.height(), std::max(700, avail.height() - 40)));
    }
    resize(targetSize);
    setupUi();
    if (!initializeIdentity()) {
        QTimer::singleShot(0, this, &QWidget::close);
        return;
    }

    connect(bridge_, &NetworkBridge::logMessage, this, &MainWindow::onLogMessage);
    connect(bridge_, &NetworkBridge::transferProgress, this, &MainWindow::onTransferProgress);
    connect(bridge_, &NetworkBridge::transferCompleted, this, &MainWindow::onTransferCompleted);
    connect(bridge_, &NetworkBridge::syntheticBatchReady, this, &MainWindow::onSyntheticBatchReady);
    connect(bridge_, &NetworkBridge::offloadTelemetryReady, this, &MainWindow::onOffloadTelemetryReady);
    connect(bridge_, &NetworkBridge::releaseChallengeReady, this, &MainWindow::onReleaseChallengeReady);
    connect(bridge_, &NetworkBridge::officerPublicKeyImported, this, &MainWindow::onOfficerPublicKeyImported);
    connect(bridge_, &NetworkBridge::auditorQueryCompleted, this, &MainWindow::onAuditorQueryCompleted);
    connect(bridge_, &NetworkBridge::serverStatus, this, &MainWindow::onServerStatus);
    connect(bridge_, &NetworkBridge::receiveProgress, this, &MainWindow::onReceiveProgress);
    connect(bridge_, &NetworkBridge::receiveFinished, this, &MainWindow::onReceiveFinished);
    refreshPeerList();
}

bool MainWindow::initializeIdentity() {
    const auto keyPath = getIdentityDirectory() / identity::KEY_FILE;
    const auto certPath = getIdentityDirectory() / identity::CERT_FILE;
    auto keyTempPath = keyPath;
    auto certTempPath = certPath;
    keyTempPath += ".tmp";
    certTempPath += ".tmp";

    auto readPrivateKey = [&keyPath](const QString& passphrase) {
        return identity::private_key_loads(keyPath, passphrase.toStdString());
    };

    const bool keyExists = std::filesystem::exists(keyPath);
    const bool certExists = std::filesystem::exists(certPath);
    std::error_code tempCleanupError;
    std::filesystem::remove(keyTempPath, tempCleanupError);
    std::filesystem::remove(certTempPath, tempCleanupError);
    if (keyExists != certExists) {
        std::error_code ec;
        if (keyExists) std::filesystem::remove(keyPath, ec);
        if (certExists) std::filesystem::remove(certPath, ec);
    }

    QString passphrase;
    if (!std::filesystem::exists(keyPath)) {
        QDialog dialog(this);
        dialog.setWindowTitle("Create BlindVault Node Identity");
        dialog.setModal(true);
        dialog.setMinimumWidth(440);

        auto* form = new QFormLayout(&dialog);
        form->setContentsMargins(24, 20, 24, 20);
        form->setSpacing(12);
        auto* aliasInput = new QLineEdit(&dialog);
        auto* passInput = new QLineEdit(&dialog);
        auto* confirmInput = new QLineEdit(&dialog);
        aliasInput->setMinimumHeight(36);
        passInput->setMinimumHeight(36);
        confirmInput->setMinimumHeight(36);
        passInput->setEchoMode(QLineEdit::Password);
        confirmInput->setEchoMode(QLineEdit::Password);
        aliasInput->setPlaceholderText("e.g. CBE-Gateway-Cairo");
        form->addRow("Gateway / Node Alias:", aliasInput);
        form->addRow("Passphrase:", passInput);
        form->addRow("Confirm Passphrase:", confirmInput);

        auto* generateButton = new QPushButton("Generate Identity", &dialog);
        generateButton->setObjectName("primaryBtn");
        generateButton->setMinimumHeight(38);
        form->addRow(generateButton);
        connect(generateButton, &QPushButton::clicked, &dialog, [&]() {
            const QString alias = aliasInput->text().trimmed();
            const QString first = passInput->text();
            if (alias.isEmpty()) {
                QMessageBox::warning(&dialog, "Identity", "Please enter a node alias.");
                return;
            }
            if (first != confirmInput->text()) {
                QMessageBox::warning(&dialog, "Identity", "Passphrases do not match.");
                return;
            }
            try {
                identity::generate(certPath, keyPath, alias.toStdString(), first.toStdString());
                passphrase = first;
                dialog.accept();
            } catch (const std::exception& error) {
                QMessageBox::critical(&dialog, "Identity Generation Failed", error.what());
            }
        });

        if (dialog.exec() != QDialog::Accepted) return false;
    } else if (!readPrivateKey(QString())) {
        QDialog dialog(this);
        dialog.setWindowTitle("Unlock BlindVault Identity");
        dialog.setModal(true);
        dialog.setMinimumWidth(440);
        auto* form = new QFormLayout(&dialog);
        form->setContentsMargins(24, 20, 24, 20);
        form->setSpacing(12);
        auto* passInput = new QLineEdit(&dialog);
        passInput->setMinimumHeight(36);
        passInput->setEchoMode(QLineEdit::Password);
        form->addRow("Passphrase:", passInput);
        auto* unlockButton = new QPushButton("Unlock", &dialog);
        unlockButton->setObjectName("primaryBtn");
        unlockButton->setMinimumHeight(38);
        form->addRow(unlockButton);
        connect(unlockButton, &QPushButton::clicked, &dialog, [&]() {
            if (!readPrivateKey(passInput->text())) {
                QMessageBox::warning(&dialog, "Unlock Failed", "Incorrect passphrase.");
                return;
            }
            passphrase = passInput->text();
            dialog.accept();
        });
        if (dialog.exec() != QDialog::Accepted) return false;
    }

    try {
        raw_fingerprint_ = QString::fromStdString(identity::fingerprint_of_file(certPath));
        fp_label_->setText(QString::fromStdString(trust::display_fingerprint(raw_fingerprint_.toStdString())));
        bridge_->setIdentityPassphrase(passphrase);
        return true;
    } catch (const std::exception& error) {
        QMessageBox::critical(this, "Identity Error", error.what());
        return false;
    }
}

void MainWindow::setupUi() {
    setWindowTitle("BlindVault — Hardened Zero-Knowledge RegTech Storage Gateway");

    auto* centralWidget = new QWidget(this);
    auto* mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(20, 18, 20, 18);
    mainLayout->setSpacing(16);

    // Header Identity Card
    auto* idCard = new QFrame(centralWidget);
    idCard->setObjectName("card");
    auto* idLayout = new QVBoxLayout(idCard);
    idLayout->setContentsMargins(22, 16, 22, 16);
    idLayout->setSpacing(12);

    auto* idHeaderLayout = new QHBoxLayout();
    auto* logoLabel = new QLabel(centralWidget);
    logoLabel->setFixedSize(34, 34);
    logoLabel->setAlignment(Qt::AlignCenter);
    logoLabel->setStyleSheet("background: transparent;");
    const QPixmap logoPix(":/icons/blindvault_icon_64.png");
    if (!logoPix.isNull()) {
        logoLabel->setPixmap(logoPix.scaled(32, 32, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    }
    auto* appTitle = new QLabel("BlindVault — Hardened Zero-Knowledge RegTech Gateway", centralWidget);
    appTitle->setObjectName("appTitle");
    auto* badge = new QLabel("RFC 3394 KEK + Ed25519 2-of-3 Quorum + AES-256-GCM + mTLS 1.3", centralWidget);
    badge->setObjectName("badge");
    idHeaderLayout->setSpacing(10);
    idHeaderLayout->addWidget(logoLabel);
    idHeaderLayout->addWidget(appTitle);
    idHeaderLayout->addStretch();
    idHeaderLayout->addWidget(badge);
    idLayout->addLayout(idHeaderLayout);

    auto* fpRowLayout = new QHBoxLayout();
    fpRowLayout->setSpacing(10);
    auto* fpTitle = new QLabel("Node Fingerprint:", centralWidget);
    fpTitle->setObjectName("subheading");
    fp_label_ = new QLabel("Loading...", centralWidget);
    fp_label_->setObjectName("monoBox");
    fp_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    copy_fp_btn_ = new QPushButton("Copy", centralWidget);
    copy_fp_btn_->setObjectName("secondaryBtn");
    copy_fp_btn_->setMinimumWidth(84);
    copy_fp_btn_->setMinimumHeight(36);
    connect(copy_fp_btn_, &QPushButton::clicked, this, &MainWindow::onCopyFingerprint);

    fpRowLayout->addWidget(fpTitle);
    fpRowLayout->addWidget(fp_label_, 1);
    fpRowLayout->addWidget(copy_fp_btn_);
    idLayout->addLayout(fpRowLayout);
    mainLayout->addWidget(idCard);

    auto* splitter = new QSplitter(Qt::Horizontal, centralWidget);
    splitter->setChildrenCollapsible(false);
    splitter->setHandleWidth(12);

    auto* tabs = new QTabWidget(splitter);
    tabs->addTab(createEgressGatewayTab(), "1. Bank Egress Gateway");
    tabs->addTab(createAuditorTab(), "2. Quorum Auditor && Cloud Proof");
    tabs->addTab(createCloudAndTrustTab(), "3. Cloud Vault && Node Trust");
    splitter->addWidget(tabs);

    // Right Column: Live Compliance & Telemetry Log
    auto* logCard = new QFrame(splitter);
    logCard->setObjectName("card");
    logCard->setMinimumWidth(300);
    auto* logLayout = new QVBoxLayout(logCard);
    logLayout->setContentsMargins(20, 18, 20, 18);
    logLayout->setSpacing(12);

    auto* logHeaderLayout = new QHBoxLayout();
    auto* logTitle = new QLabel("RegTech Telemetry & Security Audit Log", logCard);
    logTitle->setObjectName("cardTitle");
    auto* clearLogBtn = new QPushButton("Clear", logCard);
    clearLogBtn->setObjectName("secondaryBtn");
    clearLogBtn->setMinimumHeight(34);
    connect(clearLogBtn, &QPushButton::clicked, this, &MainWindow::onClearLog);
    logHeaderLayout->addWidget(logTitle);
    logHeaderLayout->addStretch();
    logHeaderLayout->addWidget(clearLogBtn);
    logLayout->addLayout(logHeaderLayout);

    log_pane_ = new QTextEdit(this);
    log_pane_->setReadOnly(true);
    log_pane_->setStyleSheet("font-size: 13px;");
    logLayout->addWidget(log_pane_, 1);

    splitter->addWidget(logCard);
    splitter->setStretchFactor(0, 68);
    splitter->setStretchFactor(1, 32);
    splitter->setSizes({920, 420});
    mainLayout->addWidget(splitter, 1);

    setCentralWidget(centralWidget);
}

QWidget* MainWindow::createEgressGatewayTab() {
    auto* tab = new QWidget();
    auto* layout = new QVBoxLayout(tab);
    layout->setContentsMargins(2, 8, 10, 14);
    layout->setSpacing(16);

    // Target Cloud Storage Card
    auto* targetCard = new QFrame(tab);
    targetCard->setObjectName("card");
    auto* targetLayout = new QVBoxLayout(targetCard);
    targetLayout->setContentsMargins(22, 18, 22, 18);
    targetLayout->setSpacing(12);

    auto* targetTitle = new QLabel("Untrusted Cloud Vault Endpoint", targetCard);
    targetTitle->setObjectName("cardTitle");
    targetLayout->addWidget(targetTitle);

    auto* grid = new QGridLayout();
    grid->setHorizontalSpacing(12);
    grid->setVerticalSpacing(8);
    grid->setColumnStretch(0, 1);
    auto* hostLbl = new QLabel("Cloud Endpoint Host:", targetCard);
    hostLbl->setObjectName("inputLabel");
    host_input_ = new QLineEdit("127.0.0.1", targetCard);
    host_input_->setMinimumHeight(38);

    auto* portLbl = new QLabel("Port:", targetCard);
    portLbl->setObjectName("inputLabel");
    port_input_ = new QLineEdit("8080", targetCard);
    port_input_->setFixedWidth(96);
    port_input_->setMinimumHeight(38);

    grid->addWidget(hostLbl, 0, 0);
    grid->addWidget(portLbl, 0, 1);
    grid->addWidget(host_input_, 1, 0);
    grid->addWidget(port_input_, 1, 1);
    targetLayout->addLayout(grid);
    layout->addWidget(targetCard);

    // Transaction Batch Card
    auto* batchCard = new QFrame(tab);
    batchCard->setObjectName("card");
    auto* batchLayout = new QVBoxLayout(batchCard);
    batchLayout->setContentsMargins(22, 18, 22, 18);
    batchLayout->setSpacing(12);

    auto* batchHeader = new QHBoxLayout();
    auto* batchTitle = new QLabel("Core Banking Transaction Batch (CSV)", batchCard);
    batchTitle->setObjectName("cardTitle");

    gen_synth_btn_ = new QPushButton("Generate 10,000 CBE Records", batchCard);
    gen_synth_btn_->setObjectName("secondaryBtn");
    gen_synth_btn_->setMinimumHeight(36);
    connect(gen_synth_btn_, &QPushButton::clicked, this, &MainWindow::onGenerateSynthetic);

    batchHeader->addWidget(batchTitle);
    batchHeader->addStretch();
    batchHeader->addWidget(gen_synth_btn_);
    batchLayout->addLayout(batchHeader);

    auto* fileRow = new QHBoxLayout();
    fileRow->setSpacing(10);
    file_path_input_ = new QLineEdit(batchCard);
    file_path_input_->setPlaceholderText("Select raw banking transaction CSV or click Generate...");
    file_path_input_->setMinimumHeight(38);

    auto* browseBtn = new QPushButton("Browse...", batchCard);
    browseBtn->setObjectName("secondaryBtn");
    browseBtn->setMinimumHeight(38);
    connect(browseBtn, &QPushButton::clicked, this, &MainWindow::onBrowseFile);

    fileRow->addWidget(file_path_input_, 1);
    fileRow->addWidget(browseBtn);
    batchLayout->addLayout(fileRow);
    layout->addWidget(batchCard);

    // Action & Hardened Telemetry Card
    auto* actionCard = new QFrame(tab);
    actionCard->setObjectName("card");
    auto* actionLayout = new QVBoxLayout(actionCard);
    actionLayout->setContentsMargins(22, 18, 22, 18);
    actionLayout->setSpacing(12);

    send_btn_ = new QPushButton("Sanitize PII, Pad 64 KiB, Wrap DEK && Offload", actionCard);
    send_btn_->setObjectName("primaryBtn");
    send_btn_->setMinimumHeight(42);
    connect(send_btn_, &QPushButton::clicked, this, &MainWindow::onOffloadCsv);
    actionLayout->addWidget(send_btn_);

    progress_bar_ = new QProgressBar(actionCard);
    progress_bar_->setValue(0);
    progress_bar_->setFixedHeight(20);
    actionLayout->addWidget(progress_bar_);

    telemetry_lbl_ = new QLabel("Throughput: Ready | Zero PII & Zero Internal IPs Leave Bank Perimeter", actionCard);
    telemetry_lbl_->setObjectName("monoBox");
    telemetry_lbl_->setAlignment(Qt::AlignCenter);
    telemetry_lbl_->setWordWrap(true);
    actionLayout->addWidget(telemetry_lbl_);

    hardening_lbl_ = new QLabel("Hardening: RFC 3394 KEK Wrap | 64 KiB Traffic Padding | 2-of-3 Erasure Shards | RLIMIT_CORE=0", actionCard);
    hardening_lbl_->setObjectName("monoBox");
    hardening_lbl_->setAlignment(Qt::AlignCenter);
    hardening_lbl_->setWordWrap(true);
    actionLayout->addWidget(hardening_lbl_);

    transfer_status_lbl_ = new QLabel("Awaiting batch offload", actionCard);
    transfer_status_lbl_->setObjectName("subheading");
    transfer_status_lbl_->setAlignment(Qt::AlignCenter);
    actionLayout->addWidget(transfer_status_lbl_);

    layout->addWidget(actionCard);
    layout->addStretch();
    return wrapInScrollArea(tab);
}

QWidget* MainWindow::createAuditorTab() {
    auto* tab = new QWidget();
    auto* layout = new QVBoxLayout(tab);
    layout->setContentsMargins(2, 8, 10, 14);
    layout->setSpacing(16);

    // Asymmetric Ed25519 M-of-N Compliance Quorum & Challenge Card
    auto* searchCard = new QFrame(tab);
    searchCard->setObjectName("card");
    auto* searchLayout = new QVBoxLayout(searchCard);
    searchLayout->setContentsMargins(22, 18, 22, 18);
    searchLayout->setSpacing(12);

    auto* headerRow = new QHBoxLayout();
    headerRow->setSpacing(12);
    auto* searchTitle = new QLabel("Asymmetric Ed25519 Quorum Gate (Public-Key-Only Gateway)", searchCard);
    searchTitle->setObjectName("cardTitle");
    import_officer_pub_btn_ = new QPushButton("Import Officer .pub Key...", searchCard);
    import_officer_pub_btn_->setObjectName("secondaryBtn");
    import_officer_pub_btn_->setMinimumHeight(36);
    connect(import_officer_pub_btn_, &QPushButton::clicked, this, &MainWindow::onImportOfficerPubKey);
    headerRow->addWidget(searchTitle);
    headerRow->addStretch();
    headerRow->addWidget(import_officer_pub_btn_);
    searchLayout->addLayout(headerRow);

    auto* queryRow = new QHBoxLayout();
    queryRow->setSpacing(10);
    auditor_query_input_ = new QLineEdit(searchCard);
    auditor_query_input_->setPlaceholderText("Customer Name (e.g. Ahmed Hassan), National ID, IBAN, or TOK_...");
    auditor_query_input_->setMinimumHeight(38);

    prep_challenge_btn_ = new QPushButton("1. Prepare Signing Challenge", searchCard);
    prep_challenge_btn_->setObjectName("secondaryBtn");
    prep_challenge_btn_->setMinimumHeight(38);
    connect(prep_challenge_btn_, &QPushButton::clicked, this, &MainWindow::onPrepareChallenge);

    queryRow->addWidget(auditor_query_input_, 1);
    queryRow->addWidget(prep_challenge_btn_);
    searchLayout->addLayout(queryRow);

    challenge_view_ = new QTextEdit(searchCard);
    challenge_view_->setReadOnly(true);
    challenge_view_->setMinimumHeight(92);
    challenge_view_->setMaximumHeight(120);
    challenge_view_->setStyleSheet("font-size: 12px;");
    challenge_view_->setPlaceholderText("Click '1. Prepare Signing Challenge' to get the blob challenge tuple for offline Ed25519 officer signing...");
    searchLayout->addWidget(challenge_view_);

    auto* sig1Row = new QHBoxLayout();
    sig1Row->setSpacing(10);
    officer1_id_input_ = new QLineEdit("CBE-Officer-1", searchCard);
    officer1_id_input_->setFixedWidth(150);
    officer1_id_input_->setMinimumHeight(38);
    officer1_sig_input_ = new QLineEdit(searchCard);
    officer1_sig_input_->setPlaceholderText("Officer 1 detached 128-hex Ed25519 signature...");
    officer1_sig_input_->setMinimumHeight(38);
    sig1Row->addWidget(officer1_id_input_);
    sig1Row->addWidget(officer1_sig_input_, 1);
    searchLayout->addLayout(sig1Row);

    auto* sig2Row = new QHBoxLayout();
    sig2Row->setSpacing(10);
    officer2_id_input_ = new QLineEdit("CBE-Officer-2", searchCard);
    officer2_id_input_->setFixedWidth(150);
    officer2_id_input_->setMinimumHeight(38);
    officer2_sig_input_ = new QLineEdit(searchCard);
    officer2_sig_input_->setPlaceholderText("Officer 2 detached 128-hex Ed25519 signature...");
    officer2_sig_input_->setMinimumHeight(38);
    sig2Row->addWidget(officer2_id_input_);
    sig2Row->addWidget(officer2_sig_input_, 1);
    searchLayout->addLayout(sig2Row);

    auditor_search_btn_ = new QPushButton("2. Verify && Re-Hydrate", searchCard);
    auditor_search_btn_->setObjectName("primaryBtn");
    auditor_search_btn_->setMinimumHeight(42);
    connect(auditor_search_btn_, &QPushButton::clicked, this, &MainWindow::onAuditorSearch);
    searchLayout->addWidget(auditor_search_btn_);

    auditor_token_lbl_ = new QLabel("Quorum Status: Gateway holds ONLY officer public keys (*.pub)", searchCard);
    auditor_token_lbl_->setObjectName("subheading");
    auditor_token_lbl_->setWordWrap(true);
    searchLayout->addWidget(auditor_token_lbl_);
    layout->addWidget(searchCard);

    // Restored Bank View Table
    auto* restoredCard = new QFrame(tab);
    restoredCard->setObjectName("card");
    auto* restoredLayout = new QVBoxLayout(restoredCard);
    restoredLayout->setContentsMargins(22, 18, 22, 18);
    restoredLayout->setSpacing(10);

    auto* restoredTitle = new QLabel("Bank Perimeter View (Unwrapped DEK -> Decrypted -> RAM Cleansed After Render)", restoredCard);
    restoredTitle->setObjectName("cardTitle");
    restoredLayout->addWidget(restoredTitle);

    auditor_table_ = new QTableWidget(0, 6, restoredCard);
    auditor_table_->setHorizontalHeaderLabels({"Tx ID", "Timestamp", "Customer", "National ID", "Amount (EGP)", "Merchant"});
    auditor_table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    auditor_table_->verticalHeader()->setVisible(false);
    auditor_table_->verticalHeader()->setDefaultSectionSize(34);
    auditor_table_->setAlternatingRowColors(true);
    auditor_table_->setMinimumHeight(190);
    restoredLayout->addWidget(auditor_table_);
    layout->addWidget(restoredCard);

    // Untrusted Cloud Hex Proof Card
    auto* cloudCard = new QFrame(tab);
    cloudCard->setObjectName("card");
    auto* cloudLayout = new QVBoxLayout(cloudCard);
    cloudLayout->setContentsMargins(22, 18, 22, 18);
    cloudLayout->setSpacing(10);

    auto* cloudTitle = new QLabel("Untrusted Cloud Storage View (64 KiB-Padded BVL3/BVL2 AES-256-GCM Ciphertext)", cloudCard);
    cloudTitle->setObjectName("cardTitle");
    cloudLayout->addWidget(cloudTitle);

    cloud_hex_view_ = new QTextEdit(cloudCard);
    cloud_hex_view_->setReadOnly(true);
    cloud_hex_view_->setMinimumHeight(120);
    cloud_hex_view_->setMaximumHeight(170);
    cloud_hex_view_->setStyleSheet("font-size: 12px;");
    cloud_hex_view_->setPlaceholderText("Run an authorized Ed25519 quorum query to inspect the raw padded ciphertext stored on the cloud node...");
    cloudLayout->addWidget(cloud_hex_view_);
    layout->addWidget(cloudCard);

    layout->addStretch();
    return wrapInScrollArea(tab);
}

QWidget* MainWindow::createCloudAndTrustTab() {
    auto* tab = new QWidget();
    auto* layout = new QVBoxLayout(tab);
    layout->setContentsMargins(2, 8, 10, 14);
    layout->setSpacing(16);

    // Cloud Storage Listener Card
    auto* srvCard = new QFrame(tab);
    srvCard->setObjectName("card");
    auto* srvLayout = new QVBoxLayout(srvCard);
    srvLayout->setContentsMargins(22, 18, 22, 18);
    srvLayout->setSpacing(12);

    auto* srvTitle = new QLabel("Local Untrusted Cloud Storage Simulator (Vault Receiver)", srvCard);
    srvTitle->setObjectName("cardTitle");
    srvLayout->addWidget(srvTitle);

    auto* srvGrid = new QGridLayout();
    srvGrid->setHorizontalSpacing(12);
    srvGrid->setVerticalSpacing(8);
    srvGrid->setColumnStretch(1, 1);

    auto* pLbl = new QLabel("Listen Port:", srvCard);
    pLbl->setObjectName("inputLabel");
    server_port_input_ = new QLineEdit("8080", srvCard);
    server_port_input_->setFixedWidth(96);
    server_port_input_->setMinimumHeight(38);

    auto* dLbl = new QLabel("Cloud Object Bucket Folder:", srvCard);
    dLbl->setObjectName("inputLabel");
    auto* dirRow = new QHBoxLayout();
    dirRow->setSpacing(10);
    save_dir_input_ = new QLineEdit(
        QStandardPaths::writableLocation(QStandardPaths::DownloadLocation) + "/BlindVault_CloudBucket", srvCard);
    save_dir_input_->setMinimumHeight(38);
    auto* browseDirBtn = new QPushButton("Browse...", srvCard);
    browseDirBtn->setObjectName("secondaryBtn");
    browseDirBtn->setMinimumHeight(38);
    connect(browseDirBtn, &QPushButton::clicked, this, &MainWindow::onBrowseSaveDir);
    dirRow->addWidget(save_dir_input_, 1);
    dirRow->addWidget(browseDirBtn);

    srvGrid->addWidget(pLbl, 0, 0);
    srvGrid->addWidget(dLbl, 0, 1);
    srvGrid->addWidget(server_port_input_, 1, 0);
    srvGrid->addLayout(dirRow, 1, 1);
    srvLayout->addLayout(srvGrid);

    server_toggle_btn_ = new QPushButton("Start Cloud Storage Node", srvCard);
    server_toggle_btn_->setObjectName("primaryBtn");
    server_toggle_btn_->setMinimumHeight(42);
    connect(server_toggle_btn_, &QPushButton::clicked, this, &MainWindow::onStartServer);
    srvLayout->addWidget(server_toggle_btn_);

    server_status_lbl_ = new QLabel("Cloud listener inactive", srvCard);
    server_status_lbl_->setObjectName("subheading");
    server_status_lbl_->setAlignment(Qt::AlignCenter);
    srvLayout->addWidget(server_status_lbl_);

    recv_progress_bar_ = new QProgressBar(srvCard);
    recv_progress_bar_->setValue(0);
    recv_progress_bar_->setFixedHeight(18);
    srvLayout->addWidget(recv_progress_bar_);
    layout->addWidget(srvCard);

    // Zero-Trust Mutual TLS Allowlist Card
    auto* trustCard = new QFrame(tab);
    trustCard->setObjectName("card");
    auto* trustLayout = new QVBoxLayout(trustCard);
    trustLayout->setContentsMargins(22, 18, 22, 18);
    trustLayout->setSpacing(12);

    auto* tHeader = new QHBoxLayout();
    tHeader->setSpacing(12);
    auto* tTitle = new QLabel("Zero-Trust Node Allowlist (Mutual TLS 1.3 Fingerprints)", trustCard);
    tTitle->setObjectName("cardTitle");
    auto* remBtn = new QPushButton("Revoke Selected", trustCard);
    remBtn->setObjectName("dangerBtn");
    remBtn->setMinimumHeight(34);
    connect(remBtn, &QPushButton::clicked, this, &MainWindow::onRemovePeer);
    tHeader->addWidget(tTitle);
    tHeader->addStretch();
    tHeader->addWidget(remBtn);
    trustLayout->addLayout(tHeader);

    peer_table_ = new QTableWidget(0, 2, trustCard);
    peer_table_->setHorizontalHeaderLabels({"Node Alias", "Pinned SHA-256 Fingerprint"});
    peer_table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    peer_table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    peer_table_->verticalHeader()->setVisible(false);
    peer_table_->verticalHeader()->setDefaultSectionSize(34);
    peer_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    peer_table_->setSelectionMode(QAbstractItemView::SingleSelection);
    peer_table_->setMinimumHeight(185);
    trustLayout->addWidget(peer_table_);

    auto* addRow = new QHBoxLayout();
    addRow->setSpacing(10);
    peer_name_input_ = new QLineEdit(trustCard);
    peer_name_input_->setPlaceholderText("Alias (e.g. CloudVault-EG)");
    peer_name_input_->setMinimumHeight(38);
    peer_fp_input_ = new QLineEdit(trustCard);
    peer_fp_input_->setPlaceholderText("64-hex SHA-256 Certificate Fingerprint");
    peer_fp_input_->setMinimumHeight(38);
    auto* addBtn = new QPushButton("Pin Node", trustCard);
    addBtn->setObjectName("primaryBtn");
    addBtn->setMinimumHeight(38);
    connect(addBtn, &QPushButton::clicked, this, &MainWindow::onAddPeer);
    addRow->addWidget(peer_name_input_, 1);
    addRow->addWidget(peer_fp_input_, 2);
    addRow->addWidget(addBtn);
    trustLayout->addLayout(addRow);

    layout->addWidget(trustCard);
    layout->addStretch();
    return wrapInScrollArea(tab);
}

void MainWindow::onBrowseFile() {
    QString file = QFileDialog::getOpenFileName(this, "Select Banking Transaction CSV", "", "CSV Files (*.csv);;All Files (*)");
    if (!file.isEmpty()) file_path_input_->setText(file);
}

void MainWindow::onBrowseSaveDir() {
    QString dir = QFileDialog::getExistingDirectory(this, "Select Cloud Object Storage Folder");
    if (!dir.isEmpty()) save_dir_input_->setText(dir);
}

void MainWindow::onCopyFingerprint() const {
    if (!raw_fingerprint_.isEmpty()) {
        QGuiApplication::clipboard()->setText(raw_fingerprint_);
        copy_fp_btn_->setText("Copied!");
        QTimer::singleShot(2000, this, [this]() {
            if (copy_fp_btn_) copy_fp_btn_->setText("Copy");
        });
    }
}

void MainWindow::onClearLog() const {
    log_pane_->clear();
}

void MainWindow::onGenerateSynthetic() {
    gen_synth_btn_->setEnabled(false);
    bridge_->generateSyntheticBatch(10000);
}

void MainWindow::onSyntheticBatchReady(const QString& csvPath) {
    gen_synth_btn_->setEnabled(true);
    file_path_input_->setText(csvPath);
}

void MainWindow::onOffloadCsv() {
    const QString host = host_input_->text().trimmed();
    const uint16_t port = port_input_->text().toUShort();
    const QString path = file_path_input_->text().trimmed();

    if (host.isEmpty() || port == 0 || path.isEmpty()) {
        QMessageBox::warning(this, "Validation", "Please provide a valid Cloud Host, Port, and CSV path.");
        return;
    }
    send_btn_->setEnabled(false);
    progress_bar_->setValue(0);
    transfer_status_lbl_->setText("Tokenizing PII, padding to 64KiB, wrapping DEK via RFC 3394, and streaming...");
    bridge_->ingestAndOffloadCsv(host, port, path);
}

void MainWindow::onOffloadTelemetryReady(quint64 records, quint64 piiTokenized, quint64 ipsMasked,
                                         quint64 paddedBytes, quint64 shardBytes,
                                         double elapsedMs, double recordsPerSec, const QString& blobName) {
    telemetry_lbl_->setText(QString("Blob: %1 | %2 tx | %3 PII tokenized | %4 IPs masked | %5 ms (%6 rec/s)")
                                .arg(blobName)
                                .arg(records)
                                .arg(piiTokenized)
                                .arg(ipsMasked)
                                .arg(elapsedMs, 0, 'f', 1)
                                .arg(recordsPerSec, 0, 'f', 0));
    hardening_lbl_->setText(QString("Padded Envelope: %1 B (64KiB aligned) | 3x Erasure Shards: %2 B each | DEK Wrapped & Cleansed")
                                .arg(paddedBytes)
                                .arg(shardBytes));
}

void MainWindow::onImportOfficerPubKey() {
    const QString file = QFileDialog::getOpenFileName(
        this, "Select Officer Ed25519 Public Key (*.pub)", "", "Ed25519 Public Keys (*.pub);;All Files (*)");
    if (!file.isEmpty()) {
        bridge_->importOfficerPublicKey(file);
    }
}

void MainWindow::onOfficerPublicKeyImported(const QString& statusMessage) {
    auditor_token_lbl_->setText(statusMessage);
}

void MainWindow::onPrepareChallenge() {
    const QString query = auditor_query_input_->text().trimmed();
    if (query.isEmpty()) {
        QMessageBox::warning(this, "Signing Challenge", "Enter a Customer Name, National ID, IBAN, or TOK_... first.");
        return;
    }
    bridge_->prepareReleaseChallenge(query);
}

void MainWindow::onReleaseChallengeReady(const QString& targetToken,
                                         const QString& challengeNonce,
                                         const QString& expiresUtc,
                                         const QString& challengeSummary,
                                         const QString& registeredOfficersSummary) {
    active_challenge_nonce_ = challengeNonce;
    active_challenge_expires_ = expiresUtc;
    challenge_view_->setPlainText(challengeSummary);
    auditor_token_lbl_->setText("Token: " + targetToken + " | Expires: " + expiresUtc +
                                " | Registered Officers: " + registeredOfficersSummary);
}

void MainWindow::onAuditorSearch() {
    const QString query = auditor_query_input_->text().trimmed();
    if (query.isEmpty()) {
        QMessageBox::warning(this, "Auditor Query", "Enter a Customer Name, National ID, IBAN, or TOK_...");
        return;
    }

    QList<QPair<QString, QString>> approvals;
    approvals.append({officer1_id_input_->text().trimmed(), officer1_sig_input_->text().trimmed()});
    approvals.append({officer2_id_input_->text().trimmed(), officer2_sig_input_->text().trimmed()});

    bridge_->queryAuditorRecords(query, save_dir_input_->text().trimmed(), approvals,
                                active_challenge_nonce_, active_challenge_expires_);
}

void MainWindow::onAuditorQueryCompleted(bool authorized, bool found, const QString& statusOrToken,
                                         const QString& restoredCsv, const QString& rawCloudHex) {
    auditor_table_->setRowCount(0);
    cloud_hex_view_->setPlainText(rawCloudHex);

    if (!authorized) {
        auditor_token_lbl_->setText("ACCESS BLOCKED: " + statusOrToken);
        QMessageBox::warning(this, "Compliance Quorum Denied", statusOrToken);
        return;
    }

    auditor_token_lbl_->setText("Ed25519 Quorum Verified (2-of-3) | Resolved Token: " + statusOrToken);

    if (!found) {
        QMessageBox::information(this, "No Records", "No archived encrypted blobs matched that identifier.");
        return;
    }

    const QStringList lines = restoredCsv.split('\n', Qt::SkipEmptyParts);
    for (int i = 1; i < lines.size(); ++i) {
        const auto cols = vault_token::parse_csv_row(lines[i].toStdString());
        if (cols.size() < 8) continue;
        const int row = auditor_table_->rowCount();
        auditor_table_->insertRow(row);
        auditor_table_->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(cols[0])));
        auditor_table_->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(cols[1])));
        auditor_table_->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(cols[2])));
        auditor_table_->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(cols[3])));
        auditor_table_->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(cols[6])));
        auditor_table_->setItem(row, 5, new QTableWidgetItem(QString::fromStdString(cols[7])));
    }
}

void MainWindow::onStartServer() {
    const uint16_t port = server_port_input_->text().toUShort();
    const QString saveDir = save_dir_input_->text().trimmed();
    if (port == 0 || saveDir.isEmpty()) {
        QMessageBox::warning(this, "Validation", "Invalid cloud port or storage directory.");
        return;
    }
    server_toggle_btn_->setEnabled(false);
    bridge_->startServer(port, saveDir);
}

void MainWindow::onAddPeer() {
    const QString name = peer_name_input_->text().trimmed();
    const QString fp = peer_fp_input_->text().trimmed();
    if (name.isEmpty() || fp.isEmpty()) return;

    trust::TrustStore store(getIdentityDirectory() / identity::TRUST_FILE);
    const std::string err = store.add(fp.toStdString(), name.toStdString());
    if (!err.empty()) {
        QMessageBox::critical(this, "Trust Error", QString::fromStdString(err));
        return;
    }
    peer_name_input_->clear();
    peer_fp_input_->clear();
    refreshPeerList();
}

void MainWindow::onRemovePeer() {
    const int row = peer_table_->currentRow();
    if (row < 0) return;
    const QString name = peer_table_->item(row, 0)->text();
    trust::TrustStore store(getIdentityDirectory() / identity::TRUST_FILE);
    store.remove(name.toStdString());
    refreshPeerList();
}

void MainWindow::refreshPeerList() const {
    peer_table_->setRowCount(0);
    trust::TrustStore store(getIdentityDirectory() / identity::TRUST_FILE);
    for (const auto& entry : store.list()) {
        const int row = peer_table_->rowCount();
        peer_table_->insertRow(row);
        peer_table_->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(entry.name)));
        peer_table_->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(trust::display_fingerprint(entry.fingerprint))));
    }
}

void MainWindow::onLogMessage(const QString& msg) const {
    log_pane_->append(msg);
}

void MainWindow::onTransferProgress(int percentage, quint64 transferred, quint64 total) const {
    progress_bar_->setValue(percentage);
    if (total > 0) {
        const double transMb = static_cast<double>(transferred) / (1024.0 * 1024.0);
        const double totalMb = static_cast<double>(total) / (1024.0 * 1024.0);
        transfer_status_lbl_->setText(QString("Mutual TLS 1.3 Stream: %1% (%2 MB / %3 MB)")
                                          .arg(percentage)
                                          .arg(transMb, 0, 'f', 2)
                                          .arg(totalMb, 0, 'f', 2));
    }
}

void MainWindow::onTransferCompleted(bool success, const QString& status) const {
    send_btn_->setEnabled(true);
    if (success) {
        progress_bar_->setValue(100);
        transfer_status_lbl_->setText("64KiB-aligned BVL3 encrypted blob verified and stored on Cloud Node!");
    } else {
        transfer_status_lbl_->setText("Offload failed: " + status);
    }
}

void MainWindow::onServerStatus(bool ok, const QString& message) {
    if (ok) {
        server_toggle_btn_->setText("Cloud Vault Active");
        server_status_lbl_->setText(message);
    } else {
        server_toggle_btn_->setEnabled(true);
        server_toggle_btn_->setText("Start Cloud Storage Node");
        server_status_lbl_->setText("Error: " + message);
    }
}

void MainWindow::onReceiveProgress(int percentage, quint64 received, quint64 total) {
    recv_progress_bar_->setValue(percentage);
    const double recvMb = static_cast<double>(received) / (1024.0 * 1024.0);
    const double totalMb = static_cast<double>(total) / (1024.0 * 1024.0);
    server_status_lbl_->setText(QString("Receiving Encrypted Blob: %1% (%2 MB / %3 MB)")
                                    .arg(percentage)
                                    .arg(recvMb, 0, 'f', 2)
                                    .arg(totalMb, 0, 'f', 2));
}

void MainWindow::onReceiveFinished(bool ok, const QString& message) const {
    if (ok) {
        recv_progress_bar_->setValue(100);
        server_status_lbl_->setText("Stored BVLT v2 Ciphertext: " + message);
    } else {
        recv_progress_bar_->setValue(0);
        server_status_lbl_->setText("Cloud Write Failed: " + message);
    }
}
