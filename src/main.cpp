#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "client_node.hpp"
#include "server_node.hpp"
#include "p2p_node.hpp"
#include "control_client.hpp"
#include "cli_identity.hpp"
#include "tls_trust.hpp"
#include "vault_gateway.hpp"
#include "vault_index.hpp"
#include "cli_benchmark.hpp"

namespace fs = std::filesystem;
namespace net = boost::asio;

namespace {

// Every mode needs an identity of its own; an empty trust list is legal but means nobody gets in
void check_ready(const trust::TrustStore& store) {
    if (!fs::exists(identity::CERT_FILE) || !fs::exists(identity::KEY_FILE)) {
        throw std::runtime_error(std::string("No identity found in this folder. Create one with:  ") +
                                 "BlindVault init");
    }
    if (store.list().empty()) {
        std::cerr << "[WARNING] Your trust list (" << identity::TRUST_FILE << ") is empty, so you will not "
                  << "accept anyone yet. Add a peer with:  BlindVault trust add <fingerprint> <name>\n";
    }
}

uint16_t parse_port(const std::string& text) {
    int value = 0;
    try {
        std::size_t used = 0;
        value = std::stoi(text, &used);
        if (used != text.size()) throw std::invalid_argument("trailing characters");
    } catch (const std::exception&) {
        throw std::runtime_error("Invalid port: " + text);
    }
    if (value < 1 || value > 65535) {
        throw std::runtime_error("Port must be between 1 and 65535");
    }
    return static_cast<uint16_t>(value);
}

std::size_t parse_size_arg(const std::string& text, const std::string& label) {
    std::size_t used = 0;
    const unsigned long long v = std::stoull(text, &used);
    if (used != text.size()) throw std::runtime_error("Invalid " + label + ": " + text);
    return static_cast<std::size_t>(v);
}

control_plane::EndpointHint parse_advertise_hint(const std::string& spec) {
    const std::size_t colon = spec.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= spec.size()) {
        throw std::runtime_error("Invalid --advertise host:port value: " + spec);
    }
    std::string host = spec.substr(0, colon);
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    return control_plane::EndpointHint{host, parse_port(spec.substr(colon + 1)), "tcp"};
}

bool contains_flag(int argc, char* argv[], const std::string& flag) {
    for (int i = 2; i < argc; ++i) {
        if (argv[i] == flag) return true;
    }
    return false;
}

struct ControlOptions {
    std::string control_url;
    bool invite = false;
    std::string claim_code;
    bool force_relay = false;
    std::string ca_file;
    std::string passphrase;
    std::vector<control_plane::EndpointHint> advertise;
    std::vector<std::string> positional;
};

ControlOptions parse_control_options(int argc, char* argv[]) {
    ControlOptions opts;
    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        auto need_val = [&](const std::string& flag) -> std::string {
            if (i + 1 >= argc) throw std::runtime_error("Missing value after " + flag);
            return argv[++i];
        };
        if (arg == "--control") {
            opts.control_url = need_val(arg);
        } else if (arg == "--invite") {
            opts.invite = true;
        } else if (arg == "--claim") {
            opts.claim_code = need_val(arg);
        } else if (arg == "--force-relay") {
            opts.force_relay = true;
        } else if (arg == "--advertise") {
            opts.advertise.push_back(parse_advertise_hint(need_val(arg)));
        } else if (arg == "--ca-file") {
            opts.ca_file = need_val(arg);
        } else if (arg == "--passphrase") {
            opts.passphrase = need_val(arg);
        } else {
            opts.positional.push_back(arg);
        }
    }
    if (!opts.invite && opts.claim_code.empty()) {
        opts.invite = true;
    }
    return opts;
}

int handle_vault_command(int argc, char* argv[]) {
    if (argc < 3) {
        throw std::runtime_error(
            "Missing vault subcommand (offload, challenge, query, rotate-kek)");
    }
    const std::string sub = argv[2];
    fs::path state_dir = "./blindvault_state";
    fs::path cloud_dir;
    std::int64_t ttl_seconds = vault_index::DEFAULT_CHALLENGE_TTL_SECONDS;
    std::string nonce_hex;
    std::string expires_utc;
    std::string auditor_id = "CLI-Auditor";
    std::vector<vault_index::OfficerApproval> approvals;
    std::vector<std::string> pos;

    for (int i = 3; i < argc; ++i) {
        const std::string arg = argv[i];
        auto need_val = [&](const std::string& flag) -> std::string {
            if (i + 1 >= argc) throw std::runtime_error("Missing value after " + flag);
            return argv[++i];
        };
        if (arg == "--state-dir") {
            state_dir = need_val(arg);
        } else if (arg == "--cloud-dir") {
            cloud_dir = need_val(arg);
        } else if (arg == "--ttl") {
            ttl_seconds = std::stoll(need_val(arg));
        } else if (arg == "--nonce") {
            nonce_hex = need_val(arg);
        } else if (arg == "--expires") {
            expires_utc = need_val(arg);
        } else if (arg == "--auditor") {
            auditor_id = need_val(arg);
        } else if (arg == "--approval") {
            const std::string val = need_val(arg);
            const std::size_t sep = val.find(':');
            if (sep == std::string::npos || sep == 0 || sep + 1 >= val.size()) {
                throw std::runtime_error(
                    "Invalid --approval format (expected <officer_id>:<signature_hex>)");
            }
            approvals.push_back(vault_index::OfficerApproval{
                val.substr(0, sep), val.substr(sep + 1)
            });
        } else {
            pos.push_back(arg);
        }
    }

    vault_gateway::GatewayEngine engine(state_dir, /*quorum_threshold=*/2);

    if (sub == "offload") {
        if (pos.size() != 1) {
            throw std::runtime_error("Usage: BlindVault vault offload <raw_csv> [--state-dir DIR] [--cloud-dir DIR]");
        }
        const auto artifact = engine.prepare_encrypted_offload(pos[0]);
        if (!cloud_dir.empty()) {
            fs::create_directories(cloud_dir);
            fs::copy_file(
                artifact.encrypted_file_path,
                cloud_dir / artifact.blob_name,
                fs::copy_options::overwrite_existing);
        }
        std::cout << "Offload complete:\n"
                  << "  blob_name=" << artifact.blob_name << '\n'
                  << "  encrypted_file=" << artifact.encrypted_file_path.string() << '\n'
                  << "  padded_bytes=" << artifact.padded_size_bytes << '\n'
                  << "  erasure_shard_bytes=" << artifact.erasure_shard_bytes << '\n'
                  << "  records=" << artifact.stats.records_processed << '\n'
                  << "  pii_tokenized=" << artifact.stats.pii_fields_tokenized << '\n'
                  << "  ips_masked=" << artifact.stats.ips_masked << '\n'
                  << "  elapsed_ms=" << std::fixed << std::setprecision(2) << artifact.elapsed_ms << '\n';
        return 0;
    }

    if (sub == "challenge") {
        if (pos.size() != 1) {
            throw std::runtime_error("Usage: BlindVault vault challenge <identifier> [--state-dir DIR] [--ttl SEC]");
        }
        const auto chal = engine.prepare_release_challenge(pos[0], ttl_seconds);
        std::cout << "target_token=" << chal.target_token << '\n'
                  << "challenge_nonce_hex=" << chal.challenge_nonce_hex << '\n'
                  << "expires_utc=" << chal.expires_utc << '\n'
                  << "quorum_threshold=" << chal.quorum_threshold << '\n'
                  << "candidate_blobs=" << chal.candidate_blobs.size() << '\n';
        for (const auto& blob : chal.candidate_blobs) {
            std::cout << "blob_name=" << blob.blob_name << '\n'
                      << "wrapped_dek_hex=" << blob.wrapped_dek_hex << '\n'
                      << "sign_cmd=BlindVault officer-sign <priv.pem> <officer_id> "
                      << chal.target_token << ' ' << blob.blob_name << ' ' << blob.wrapped_dek_hex
                      << ' ' << chal.challenge_nonce_hex << ' ' << chal.expires_utc << '\n';
        }
        return 0;
    }

    if (sub == "query") {
        if (pos.size() != 2 || nonce_hex.empty() || expires_utc.empty() || approvals.empty()) {
            throw std::runtime_error(
                "Usage: BlindVault vault query <identifier> <cloud_dir> --nonce <hex> --expires <iso> "
                "--approval <officer_id>:<sig_hex> [--approval ...] [--state-dir DIR] [--auditor ID]");
        }
        const auto res = engine.auditor_query(
            pos[0], pos[1], approvals, nonce_hex, expires_utc, auditor_id);
        if (!res.authorized) {
            std::cerr << "[DENIED] " << res.denial_reason << '\n';
            return 1;
        }
        if (res.recovered_from_shards) {
            std::cerr << "[RECOVERY] Reconstructed blob via 2-of-3 erasure shards (SHARD_RECOVERY logged).\n";
        }
        if (!res.found) {
            std::cerr << "[INFO] Quorum verified, no records matched token " << res.matched_token << '\n';
        }
        std::cout << res.restored_csv;
        return 0;
    }

    if (sub == "rotate-kek") {
        engine.rotate_master_kek(vault_crypto::generate_key(), cloud_dir);
        const bool verified = engine.metadata_index().verify_audit_chain();
        std::cout << "Master KEK rotation complete. Audit hash chain: "
                  << (verified ? "VERIFIED" : "FAILED") << '\n';
        return verified ? 0 : 1;
    }

    throw std::runtime_error("Unknown vault subcommand: " + sub);
}

void print_usage(const char* program) {
    std::cerr << "Usage:\n"
              << "  " << program << " receive <port> [save_folder] [--control <url> --invite|--claim <code>]\n"
              << "  " << program << " send <host> <port> <file>\n"
              << "  " << program << " send <file> --control <url> (--invite|--claim <code>) [--force-relay]\n"
              << "  " << program << " p2p <port> [save_folder] [--control <url> --invite|--claim <code>]\n\n"
              << "RegTech Vault Gateway & Benchmark Commands:\n"
              << "  " << program << " vault offload <raw_csv> [--state-dir DIR] [--cloud-dir DIR]\n"
              << "  " << program << " vault challenge <identifier> [--state-dir DIR] [--ttl SEC]\n"
              << "  " << program << " vault query <identifier> <cloud_dir> --nonce <hex> --expires <iso> --approval <id>:<sig>...\n"
              << "  " << program << " vault rotate-kek [--state-dir DIR] [--cloud-dir DIR]\n"
              << "  " << program << " bench [rows]\n\n"
              << "Compliance Officer Offline Quorum Commands (run on officer workstation):\n"
              << "  " << program << " officer-keygen <officer_id> [out_dir]\n"
              << "  " << program << " officer-sign <priv_key.pem> <officer_id> <token> <blob_name> <wrapped_dek_hex> <challenge_nonce_hex> <expires_utc>\n\n";
    cli::print_identity_usage(program);
}

} // namespace

int main(int argc, char* argv[]) {
#ifndef _WIN32
    // Write each log line immediately, even when output is redirected to a file or pipe
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
#endif
    try {
        if (argc < 2) { print_usage(argv[0]); return 1; }
        const std::string mode = argv[1];

        // Offline Compliance Officer Ed25519 key generation and detached challenge signing
        if (mode == "officer-keygen" && (argc == 3 || argc == 4)) {
            const std::string officer_id = argv[2];
            if (!trust::valid_name(officer_id)) {
                throw std::runtime_error("Invalid officer_id (use letters, digits, '.', '_' or '-')");
            }
            const fs::path out_dir = (argc == 4) ? fs::path(argv[3]) : fs::current_path();
            fs::create_directories(out_dir);
            const auto priv_path = out_dir / (officer_id + ".priv");
            const auto pub_path  = out_dir / (officer_id + ".pub");
            vault_index::generate_officer_ed25519_keypair(priv_path, pub_path);
            std::cout << "Generated Ed25519 keypair for '" << officer_id << "':\n"
                      << "  Private key (keep on officer device): " << priv_path.string() << "\n"
                      << "  Public key  (install on gateway):     " << pub_path.string() << "\n";
            return 0;
        }

        if (mode == "officer-sign" && argc == 9) {
            const std::string sig_hex = vault_index::sign_blob_release_offline(
                argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8]);
            std::cout << sig_hex << '\n';
            return 0;
        }

        if (mode == "vault") {
            return handle_vault_command(argc, argv);
        }

        if (mode == "bench" && (argc == 2 || argc == 3)) {
            const std::size_t rows = (argc == 3) ? parse_size_arg(argv[2], "rows") : 10000;
            return cli_bench::run(rows);
        }

        // init, fingerprint and trust: manage your identity and who you trust
        const int identity_result = cli::handle_identity_command(
            std::vector<std::string>(argv + 1, argv + argc), "BlindVault");
        if (identity_result >= 0) return identity_result;

        net::io_context io_ctx;

        if (mode == "p2p" && argc >= 3) {
            if (contains_flag(argc, argv, "--control")) {
                const auto opts = parse_control_options(argc, argv);
                if (opts.positional.empty()) throw std::runtime_error("p2p requires <port>");
                const uint16_t port = parse_port(opts.positional[0]);
                const fs::path save_dir = (opts.positional.size() >= 2)
                    ? fs::path(opts.positional[1]) : fs::path("received");

                auto trust_store = std::make_shared<trust::TrustStore>(identity::TRUST_FILE);
                check_ready(*trust_store);

                net::ssl::context server_ctx(net::ssl::context::tlsv13_server);
                tls_trust::configure_server(server_ctx, trust_store,
                                            identity::CERT_FILE, identity::KEY_FILE, opts.passphrase);
                net::ssl::context client_ctx(net::ssl::context::tlsv13_client);
                tls_trust::configure_client(client_ctx, trust_store,
                                            identity::CERT_FILE, identity::KEY_FILE, opts.passphrase);

                auto node = std::make_shared<P2PNode>(io_ctx, server_ctx, client_ctx, port, save_dir, trust_store);
                node->start();

                control_plane::ControlClient ctrl(
                    opts.control_url, identity::KEY_FILE, opts.passphrase, opts.ca_file);
                const auto info = ctrl.fetch_server_info();
                const auto reflected = ctrl.probe_udp_endpoint(info);
                ctrl.connect_and_authenticate(reflected);

                std::vector<control_plane::EndpointHint> hints = opts.advertise;
                if (!opts.force_relay && hints.empty()) {
                    if (reflected) hints.push_back({reflected->ip, port, "tcp"});
                    hints.push_back({"127.0.0.1", port, "tcp"});
                }

                control_plane::PeerMatch match;
                if (!opts.claim_code.empty()) {
                    match = ctrl.claim_invite(opts.claim_code, hints);
                } else {
                    const auto inv = ctrl.create_invite(hints);
                    std::cout << "INVITE_CODE: " << inv.code << '\n';
                    match = ctrl.wait_for_peer_match();
                }
                std::cout << "PAIRED_PEER: " << match.peer_fingerprint
                          << " role=" << match.role << '\n';
                if (!match.endpoints.empty()) {
                    node->add_peer(match.peer_fingerprint.substr(0, 12),
                                   match.endpoints[0].host,
                                   std::to_string(match.endpoints[0].port));
                }

                std::atomic<bool> stop_relay{false};
                std::thread relay_thread([&]() {
                    try {
                        while (!stop_relay.load()) {
                            const auto inv = ctrl.wait_for_relay_invite(std::chrono::seconds(300));
                            control_plane::RelayTcpBridge::bridge_to_local_server(
                                opts.control_url, inv.session_id, inv.token, port, opts.ca_file);
                        }
                    } catch (...) {
                    }
                });

                std::thread input_thread([&]() {
                    std::string cmd;
                    while (true) {
                        std::cout << "> ";
                        if (!(std::cin >> cmd)) break;
                        if (cmd == "send") {
                            std::string host, p, file;
                            std::cin >> host >> p >> std::quoted(file);
                            node->send_file_to_addr(host, p, file);
                        } else if (cmd == "add") {
                            std::string name, host, p;
                            std::cin >> name >> host >> p;
                            node->add_peer(name, host, p);
                        } else if (cmd == "send_to") {
                            std::string name, file;
                            std::cin >> name >> file;
                            node->send_file(name, file);
                        } else if (cmd == "exit") {
                            io_ctx.stop();
                            break;
                        }
                    }
                });

                io_ctx.run();
                stop_relay.store(true);
                ctrl.close();
                if (relay_thread.joinable()) relay_thread.join();
                if (input_thread.joinable()) input_thread.join();
                return 0;
            }

            uint16_t port = parse_port(argv[2]);
            fs::path save_dir = (argc >= 4) ? fs::path(argv[3]) : fs::path("received");

            auto trust_store = std::make_shared<trust::TrustStore>(identity::TRUST_FILE);
            check_ready(*trust_store);

            net::ssl::context server_ctx(net::ssl::context::tlsv13_server);
            tls_trust::configure_server(server_ctx, trust_store);

            net::ssl::context client_ctx(net::ssl::context::tlsv13_client);
            tls_trust::configure_client(client_ctx, trust_store);

            auto node = std::make_shared<P2PNode>(io_ctx, server_ctx, client_ctx, port, save_dir, trust_store);
            node->start();

            std::thread input_thread([&io_ctx, node]() {
                std::string cmd;
                while (true) {
                    std::cout << "> ";
                    if (!(std::cin >> cmd)) break;
                    if (cmd == "send") {
                        std::string host, p, file;
                        std::cin >> host >> p >> std::quoted(file);
                        node->send_file_to_addr(host, p, file);
                    } else if (cmd == "add") {
                        std::string name, host, p;
                        std::cin >> name >> host >> p;
                        node->add_peer(name, host, p);
                    } else if (cmd == "send_to") {
                        std::string name, file;
                        std::cin >> name >> file;
                        node->send_file(name, file);
                    } else if (cmd == "exit") {
                        io_ctx.stop();
                        break;
                    } else {
                        std::cout << "Commands: send <host> <port> <file>, add <name> <host> <port>, send_to <name> <file>, exit\n";
                    }
                }
            });

            io_ctx.run();
            if (input_thread.joinable()) input_thread.join();

        } else if (mode == "receive") {
            if (contains_flag(argc, argv, "--control")) {
                const auto opts = parse_control_options(argc, argv);
                if (opts.positional.empty() || opts.positional.size() > 2) {
                    throw std::runtime_error(
                        "Usage: BlindVault receive <port> [save_dir] --control <url> [--invite|--claim <code>]");
                }
                const uint16_t port = parse_port(opts.positional[0]);
                const fs::path save_dir = (opts.positional.size() == 2)
                    ? fs::path(opts.positional[1]) : fs::path("received");

                auto trust_store = std::make_shared<trust::TrustStore>(identity::TRUST_FILE);
                check_ready(*trust_store);

                net::ssl::context ssl_ctx(net::ssl::context::tlsv13_server);
                tls_trust::configure_server(ssl_ctx, trust_store,
                                            identity::CERT_FILE, identity::KEY_FILE, opts.passphrase);
                std::make_shared<ServerNode>(io_ctx, ssl_ctx, port, save_dir, trust_store)->start();

                control_plane::ControlClient ctrl(
                    opts.control_url, identity::KEY_FILE, opts.passphrase, opts.ca_file);
                const auto info = ctrl.fetch_server_info();
                const auto reflected = ctrl.probe_udp_endpoint(info);
                ctrl.connect_and_authenticate(reflected);

                std::vector<control_plane::EndpointHint> hints;
                if (!opts.force_relay) {
                    hints = opts.advertise;
                    if (hints.empty()) {
                        if (reflected) hints.push_back({reflected->ip, port, "tcp"});
                        hints.push_back({"127.0.0.1", port, "tcp"});
                    }
                }

                control_plane::PeerMatch match;
                if (!opts.claim_code.empty()) {
                    match = ctrl.claim_invite(opts.claim_code, hints);
                } else {
                    const auto inv = ctrl.create_invite(hints);
                    std::cout << "INVITE_CODE: " << inv.code << '\n';
                    match = ctrl.wait_for_peer_match();
                }
                std::cout << "PAIRED_PEER: " << match.peer_fingerprint
                          << " role=" << match.role << '\n';

                std::atomic<bool> stop_relay{false};
                std::thread relay_thread([&]() {
                    try {
                        while (!stop_relay.load()) {
                            const auto inv = ctrl.wait_for_relay_invite(std::chrono::seconds(300));
                            control_plane::RelayTcpBridge::bridge_to_local_server(
                                opts.control_url, inv.session_id, inv.token, port, opts.ca_file);
                        }
                    } catch (...) {
                    }
                });

                io_ctx.run();
                stop_relay.store(true);
                ctrl.close();
                if (relay_thread.joinable()) relay_thread.join();
                return 0;
            }

            if (argc != 3 && argc != 4) {
                print_usage(argv[0]);
                return 1;
            }
            uint16_t port = parse_port(argv[2]);
            fs::path save_dir = (argc == 4) ? fs::path(argv[3]) : fs::path("received");
            auto trust_store = std::make_shared<trust::TrustStore>(identity::TRUST_FILE);
            check_ready(*trust_store);

            net::ssl::context ssl_ctx(net::ssl::context::tlsv13_server);
            tls_trust::configure_server(ssl_ctx, trust_store);

            std::make_shared<ServerNode>(io_ctx, ssl_ctx, port, save_dir, trust_store)->start();
            io_ctx.run();

        } else if (mode == "send") {
            if (contains_flag(argc, argv, "--control")) {
                const auto opts = parse_control_options(argc, argv);
                std::string file;
                if (opts.positional.size() == 1) file = opts.positional[0];
                else if (opts.positional.size() == 3) file = opts.positional[2];
                else {
                    throw std::runtime_error(
                        "Usage: BlindVault send <file> --control <url> (--invite|--claim <code>) [--force-relay]");
                }

                if (!fs::exists(file)) {
                    throw std::runtime_error("File not found: " + file);
                }

                auto trust_store = std::make_shared<trust::TrustStore>(identity::TRUST_FILE);
                check_ready(*trust_store);

                net::ssl::context ssl_ctx(net::ssl::context::tlsv13_client);
                tls_trust::configure_client(ssl_ctx, trust_store,
                                            identity::CERT_FILE, identity::KEY_FILE, opts.passphrase);

                control_plane::ControlClient ctrl(
                    opts.control_url, identity::KEY_FILE, opts.passphrase, opts.ca_file);
                const auto info = ctrl.fetch_server_info();
                const auto reflected = ctrl.probe_udp_endpoint(info);
                ctrl.connect_and_authenticate(reflected);

                control_plane::PeerMatch match;
                if (!opts.claim_code.empty()) {
                    match = ctrl.claim_invite(opts.claim_code, opts.advertise);
                } else {
                    const auto inv = ctrl.create_invite(opts.advertise);
                    std::cout << "INVITE_CODE: " << inv.code << '\n';
                    match = ctrl.wait_for_peer_match();
                }
                std::cout << "PAIRED_PEER: " << match.peer_fingerprint
                          << " role=" << match.role << '\n';

                std::optional<control_plane::EndpointHint> reachable;
                if (!opts.force_relay) {
                    for (const auto& ep : match.endpoints) {
                        if (control_plane::ControlClient::try_direct_tcp_connect(ep.host, ep.port)) {
                            reachable = ep;
                            break;
                        }
                    }
                }

                auto node = std::make_shared<ClientNode>(io_ctx, ssl_ctx, TransferEvents{}, trust_store);
                std::unique_ptr<control_plane::RelayTcpBridge::LocalRelayProxy> proxy;
                if (reachable) {
                    std::cout << "[CONTROL] Using direct mTLS path to "
                              << reachable->host << ':' << reachable->port << '\n';
                    node->send_file(std::to_string(reachable->port), reachable->host, file);
                } else {
                    std::cout << "[CONTROL] Opening encrypted WebSocket fallback relay...\n";
                    const auto relay = ctrl.create_relay(match.peer_fingerprint);
                    proxy = std::make_unique<control_plane::RelayTcpBridge::LocalRelayProxy>(
                        opts.control_url, relay.session_id, relay.token, opts.ca_file);
                    node->send_file(std::to_string(proxy->local_port()), "127.0.0.1", file);
                }

                io_ctx.run();
                if (proxy) {
                    proxy->stop();
                    proxy->join();
                }
                ctrl.close();
                return node->succeeded() ? 0 : 1;
            }

            if (argc != 5) {
                print_usage(argv[0]);
                return 1;
            }
            const std::string host = argv[2];
            const std::string port = std::to_string(parse_port(argv[3]));
            const std::string file = argv[4];

            auto trust_store = std::make_shared<trust::TrustStore>(identity::TRUST_FILE);
            check_ready(*trust_store);

            net::ssl::context ssl_ctx(net::ssl::context::tlsv13_client);
            tls_trust::configure_client(ssl_ctx, trust_store);

            auto node = std::make_shared<ClientNode>(io_ctx, ssl_ctx);
            node->send_file(port, host, file);
            io_ctx.run();
            return node->succeeded() ? 0 : 1;

        } else {
            print_usage(argv[0]);
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << '\n';
        return 1;
    }
    return 0;
}
