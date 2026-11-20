#pragma once
// BlindVault Control-Plane Client & Zero-Knowledge Fallback Relay TCP Bridge:
//   - HTTP/HTTPS GET /api/v1/info (fetches Ed25519 UDP reflector public key)
//   - UDP endpoint reflection probe ("BVST") with Ed25519 signature verification
//   - WebSocket /ws/control EC P-256 ECDSA-SHA256 challenge authentication & heartbeats
//   - Invite creation/claiming, ICE/hole-punch signaling, and TCP direct reachability probe
//   - Binary-frame WebSocket RelayTcpBridge (/ws/relay/{session_id} via Authorization: Bearer)

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace control_plane {

struct ControlEndpoint {
    bool use_tls = false;
    std::string host;
    std::string port;

    [[nodiscard]] std::string host_header() const;
};

struct ServerInfo {
    std::string version;
    std::uint16_t udp_reflector_port = 0;
    std::string udp_reflector_public_key_b64;
    std::string udp_reflector_signature_alg;
    std::size_t max_relay_frame_bytes = 65536;
};

struct ReflectedEndpoint {
    std::string ip;
    std::uint16_t port = 0;
    std::uint64_t timestamp = 0;
};

struct EndpointHint {
    std::string host;
    std::uint16_t port = 0;
    std::string proto = "tcp";
};

struct InviteResult {
    std::string code;
    int ttl = 0;
};

struct PeerMatch {
    std::string peer_fingerprint;
    std::vector<EndpointHint> endpoints;
    std::string role;
};

struct RelaySessionInfo {
    std::string session_id;
    std::string token;
    std::string from_fingerprint;
};

// Parses http://, https://, ws://, or wss:// control-plane URLs into host, port, and TLS flag.
ControlEndpoint parse_control_url(std::string_view url);

class ControlClient {
public:
    ControlClient(std::string control_url,
                  const std::filesystem::path& identity_key_path,
                  std::string key_passphrase = "",
                  std::string ca_file = "");
    ~ControlClient();

    ControlClient(const ControlClient&) = delete;
    ControlClient& operator=(const ControlClient&) = delete;

    // SHA-256 hex fingerprint of this node's EC P-256 SubjectPublicKeyInfo DER (control-plane ID)
    [[nodiscard]] const std::string& fingerprint() const noexcept;
    [[nodiscard]] int heartbeat_interval_sec() const noexcept;

    // Fetches GET /api/v1/info from blindvault-control
    ServerInfo fetch_server_info();

    // Pure verifier for "BVST" Ed25519 UDP reflection packets (exposed for deterministic tests)
    static std::optional<ReflectedEndpoint> verify_udp_reflection_packet(
        const std::vector<uint8_t>& packet,
        std::string_view ed25519_pubkey_b64,
        const std::array<uint8_t, 16>& expected_nonce);

    // Best-effort UDP reflection probe; returns std::nullopt on timeout or unreachable UDP
    std::optional<ReflectedEndpoint> probe_udp_endpoint(
        const ServerInfo& info,
        std::uint16_t local_port = 0,
        std::size_t timeout_ms = 2000);

    // Connects /ws/control and completes HELLO -> CHALLENGE -> ECDSA AUTH -> AUTH_OK
    void connect_and_authenticate(
        const std::optional<ReflectedEndpoint>& observed = std::nullopt);

    void send_ping();

    InviteResult create_invite(const std::vector<EndpointHint>& endpoints);
    PeerMatch claim_invite(const std::string& code, const std::vector<EndpointHint>& endpoints);
    PeerMatch wait_for_peer_match(std::chrono::seconds timeout = std::chrono::seconds(120));

    void send_signal_offer(const std::string& target_fingerprint,
                           const std::string& session_id,
                           const std::string& host,
                           std::uint16_t port,
                           const std::string& proto = "tcp");

    void send_signal_answer(const std::string& target_fingerprint,
                            const std::string& session_id,
                            const std::string& host,
                            std::uint16_t port,
                            const std::string& proto = "tcp");

    void send_hole_punch_sync(const std::string& target_fingerprint,
                              const std::string& stage,
                              double timestamp_sec = 0.0);

    RelaySessionInfo create_relay(const std::string& target_fingerprint);
    RelaySessionInfo wait_for_relay_invite(std::chrono::seconds timeout = std::chrono::seconds(30));

    static bool try_direct_tcp_connect(const std::string& host,
                                       std::uint16_t port,
                                       std::size_t timeout_ms = 1500);

    void close();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class RelayTcpBridge {
public:
    // Responder/server side: connects to /ws/relay/{session_id} with Bearer token and
    // bridges binary WebSocket frames bidirectionally to 127.0.0.1:local_server_port.
    static void bridge_to_local_server(const std::string& control_url,
                                       const std::string& session_id,
                                       const std::string& token,
                                       std::uint16_t local_server_port,
                                       const std::string& ca_file = "");

    // Initiator/client side: connects to /ws/relay/{session_id} and exposes a loopback TCP
    // listener so ClientNode can establish a normal end-to-end mTLS 1.3 session inside it.
    class LocalRelayProxy {
    public:
        LocalRelayProxy(const std::string& control_url,
                        const std::string& session_id,
                        const std::string& token,
                        const std::string& ca_file = "");
        ~LocalRelayProxy();

        LocalRelayProxy(const LocalRelayProxy&) = delete;
        LocalRelayProxy& operator=(const LocalRelayProxy&) = delete;

        [[nodiscard]] std::uint16_t local_port() const noexcept;
        void join();
        void stop();

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };
};

} // namespace control_plane
