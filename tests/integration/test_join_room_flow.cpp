// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         LIVE FEDERATED join_room INTEGRATION TEST                       |
// |                                                                         |
// |  Spec: Server-Server API v1.19 — Joining Rooms                          |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#joining-rooms   |
// |                                                                         |
// |  Drives merovingian::homeserver::join_room() through a REAL make_join / |
// |  send_join round trip against a local TLS server, exercising the fast- |
// |  join state split, send_join signature verification, and the           |
// |  background membership-fill task end to end. This closes the           |
// |  codecov/patch coverage gap left by PR #341 (room_service.cpp's        |
// |  post-send_join-success path had no integration coverage).             |
// |                                                                         |
// |  join_room always resolves its destination through                     |
// |  federation::discover_server(), which unconditionally rejects loopback |
// |  and private-range addresses (src/federation/security.cpp              |
// |  ip_address_is_private_or_loopback) with no override, and production   |
// |  outbound calls never populate an in-memory CA bundle. This test uses  |
// |  HomeserverRuntime::test_forced_outbound_resolution (see runtime.hpp)  |
// |  to point the outbound call at the local server without weakening      |
// |  that policy for real traffic — the override is never set by any       |
// |  production construction path.                                        |
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
#include "../federation_signing_test_support.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <poll.h>
#include <sodium.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{

// --- TLS test certificate + resident server (adapted from
// tests/integration/test_federation_outbound_flow.cpp) --------------------

struct TlsTestCertificate final
{
    std::filesystem::path directory{};
    std::string certificate_file{};
    std::string private_key_file{};
    std::string certificate_pem{};

    TlsTestCertificate() = default;

    ~TlsTestCertificate()
    {
        auto ignored = std::error_code{};
        std::filesystem::remove_all(directory, ignored);
    }

    TlsTestCertificate(TlsTestCertificate const&) = delete;
    auto operator=(TlsTestCertificate const&) -> TlsTestCertificate& = delete;

    TlsTestCertificate(TlsTestCertificate&& other) noexcept
        : directory{std::move(other.directory)}
        , certificate_file{std::move(other.certificate_file)}
        , private_key_file{std::move(other.private_key_file)}
        , certificate_pem{std::move(other.certificate_pem)}
    {
        other.directory.clear();
    }

    auto operator=(TlsTestCertificate&& other) noexcept -> TlsTestCertificate&
    {
        if (this != &other)
        {
            auto ignored = std::error_code{};
            std::filesystem::remove_all(directory, ignored);
            directory = std::move(other.directory);
            certificate_file = std::move(other.certificate_file);
            private_key_file = std::move(other.private_key_file);
            certificate_pem = std::move(other.certificate_pem);
            other.directory.clear();
        }
        return *this;
    }
};

struct EvpPkeyDeleter final
{
    auto operator()(EVP_PKEY* key) const noexcept -> void
    {
        EVP_PKEY_free(key);
    }
};

struct X509Deleter final
{
    auto operator()(X509* certificate) const noexcept -> void
    {
        X509_free(certificate);
    }
};

struct FileDeleter final
{
    auto operator()(std::FILE* file) const noexcept -> void
    {
        if (file != nullptr)
        {
            static_cast<void>(std::fclose(file));
        }
    }
};

[[nodiscard]] auto read_file_into_string(std::filesystem::path const& path) -> std::string
{
    auto stream = std::ifstream{path, std::ios::binary};
    auto buffer = std::ostringstream{};
    buffer << stream.rdbuf();
    return buffer.str();
}

// Portable across OpenSSL 3 and LibreSSL (OpenBSD) — mirrors
// test_federation_outbound_flow.cpp's generate_rsa_key exactly.
[[nodiscard]] auto generate_rsa_key(int bits) -> EVP_PKEY*
{
    auto* const context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (context == nullptr)
    {
        return nullptr;
    }
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen_init(context) > 0 && EVP_PKEY_CTX_set_rsa_keygen_bits(context, bits) > 0)
    {
        EVP_PKEY_keygen(context, &key);
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

[[nodiscard]] auto write_test_tls_certificate() -> TlsTestCertificate
{
    static auto counter = std::uint32_t{0U};
    auto const directory =
        merovingian::tests::temporary_directory() /
        ("merovingian-join-room-tls-" + std::to_string(::getpid()) + "-" + std::to_string(++counter));
    std::filesystem::create_directories(directory);

    auto key = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>{generate_rsa_key(2048)};
    REQUIRE(key != nullptr);

    auto certificate = std::unique_ptr<X509, X509Deleter>{X509_new()};
    REQUIRE(certificate != nullptr);
    REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1L) == 1);
    REQUIRE(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0L) != nullptr);
    REQUIRE(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600L) != nullptr);
    REQUIRE(X509_set_pubkey(certificate.get(), key.get()) == 1);

    auto* subject = X509_get_subject_name(certificate.get());
    REQUIRE(subject != nullptr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto const* common_name = reinterpret_cast<unsigned char const*>("localhost");
    REQUIRE(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, common_name, -1, -1, 0) == 1);
    REQUIRE(X509_set_issuer_name(certificate.get(), subject) == 1);
    REQUIRE(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0);

    auto output = TlsTestCertificate{};
    output.directory = directory;
    output.certificate_file = (directory / "server.pem").string();
    output.private_key_file = (directory / "server.key").string();

    auto cert_file = std::unique_ptr<std::FILE, FileDeleter>{std::fopen(output.certificate_file.c_str(), "wb")};
    REQUIRE(cert_file != nullptr);
    REQUIRE(PEM_write_X509(cert_file.get(), certificate.get()) == 1);

    auto key_file = std::unique_ptr<std::FILE, FileDeleter>{std::fopen(output.private_key_file.c_str(), "wb")};
    REQUIRE(key_file != nullptr);
    REQUIRE(PEM_write_PrivateKey(key_file.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1);

    cert_file.reset();
    key_file.reset();

    output.certificate_pem = read_file_into_string(output.certificate_file);
    return output;
}

[[nodiscard]] auto accept_loopback(merovingian::net::TcpAcceptor& acceptor, int timeout_ms) -> int
{
    auto pollfd_entry = ::pollfd{acceptor.fd(), POLLIN, 0};
    auto const ready = ::poll(&pollfd_entry, 1U, timeout_ms);
    if (ready <= 0)
    {
        return -1;
    }
    return ::accept(acceptor.fd(), nullptr, nullptr);
}

[[nodiscard]] auto json_http_response(std::string const& status_line, std::string const& body) -> std::string
{
    auto response = std::string{"HTTP/1.1 "};
    response += status_line;
    response += "\r\nContent-Length: ";
    response += std::to_string(body.size());
    response += "\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n";
    response += body;
    return response;
}

// Serves two sequential one-shot HTTPS requests on the same acceptor: the
// resident server side of make_join then send_join. Dispatches by request
// path substring rather than assuming call order, since that is the only
// thing distinguishing the two requests on the wire.
auto run_resident_server(merovingian::net::TcpAcceptor& acceptor,
                         merovingian::homeserver::TlsServerContext& tls_context, std::string const& make_join_response,
                         std::string const& send_join_response) noexcept -> void
{
    for (auto request_index = 0; request_index < 2; ++request_index)
    {
        auto const client_fd = accept_loopback(acceptor, 5000);
        if (client_fd < 0)
        {
            return;
        }
        auto tls_result = merovingian::homeserver::accept_tls_connection(tls_context, client_fd, 5000);
        if (!tls_result.connection.has_value())
        {
            ::close(client_fd);
            continue;
        }
        auto& connection = *tls_result.connection;
        auto buffer = std::array<char, 8192>{};
        auto request_bytes = std::string{};
        while (request_bytes.find("\r\n\r\n") == std::string::npos)
        {
            auto const bytes_read = connection.read(buffer.data(), buffer.size());
            if (bytes_read <= 0)
            {
                break;
            }
            request_bytes.append(buffer.data(), static_cast<std::size_t>(bytes_read));
            if (static_cast<std::size_t>(bytes_read) < buffer.size())
            {
                break;
            }
        }
        auto const is_send_join = request_bytes.find("send_join") != std::string::npos;
        static_cast<void>(connection.write(is_send_join ? send_join_response : make_join_response));
    }
}

// --- Federation fixture construction --------------------------------------

auto constexpr local_server = "example.org"; // default ServerConfig::server_name
auto constexpr resident_server = "resident.example.org";
auto constexpr resident_key_id = "ed25519:auto";
auto constexpr resident_key_seed = "join-room-flow-resident-seed";

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto resident_remote_runtime() -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = resident_server;
    remote.signing_key = {resident_server, resident_key_id, 0U,
                          merovingian::federation::test::keypair_from_seed(resident_key_seed).public_key};
    remote.discovery.server_name = resident_server;
    remote.trust.reputation_score = 100U;
    return remote;
}

// Signs `raw_event_json` with the keypair derived from `sign_seed` and attaches
// the signature under {claimed_server, claimed_key_id}, returning the fully
// signed event as a parsed canonicaljson::Value ready to drop into a state or
// auth_chain array.
[[nodiscard]] auto sign_test_event(std::string const& raw_event_json,
                                   merovingian::rooms::RoomVersionPolicy const& policy,
                                   std::string const& claimed_server, std::string const& claimed_key_id,
                                   std::string const& sign_seed) -> merovingian::canonicaljson::Value
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(raw_event_json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const payload = merovingian::events::make_event_signing_payload(parsed.value, policy);
    REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
    auto const kp = merovingian::federation::test::keypair_from_seed(sign_seed);
    auto sig = std::array<unsigned char, crypto_sign_BYTES>{};
    crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<unsigned char const*>(payload.output.data()),
                         payload.output.size(), reinterpret_cast<unsigned char const*>(kp.secret_key.data()));
    auto const sig_b64 =
        merovingian::events::matrix_base64_from_bytes({reinterpret_cast<char const*>(sig.data()), crypto_sign_BYTES});
    auto const attached =
        merovingian::events::attach_event_signature(parsed.value, {claimed_server, claimed_key_id}, sig_b64);
    REQUIRE(attached.error == merovingian::canonicaljson::CanonicalJsonError::none);
    auto const reparsed = merovingian::canonicaljson::parse_lossless(attached.output);
    REQUIRE(reparsed.error == merovingian::canonicaljson::ParseError::none);
    return reparsed.value;
}

[[nodiscard]] auto canonicaljson_array_to_string(merovingian::canonicaljson::Array const& array) -> std::string
{
    auto out = std::string{"["};
    for (auto index = std::size_t{0U}; index < array.size(); ++index)
    {
        if (index != 0U)
        {
            out += ",";
        }
        auto const serialized = merovingian::canonicaljson::serialize_canonical(array[index]);
        REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
        out += serialized.output;
    }
    out += "]";
    return out;
}

} // namespace

SCENARIO("join_room completes a live federated join and defers the bulk membership list to a background task",
         "[homeserver][federation][join][integration]")
{
    GIVEN("a real HomeserverRuntime, a logged-in local user, and a real TLS resident server")
    {
        REQUIRE(sodium_init() >= 0);
        // Declared before `started`/`runtime` so it destructs AFTER them:
        // HomeserverRuntime's destructor blocks until every orphaned
        // background future (see orphan_futures_) has finished draining, and
        // the background member-fill task holds a reference to `runtime` and
        // may call notify_room_changed() — which writes through
        // runtime.test_room_changed_log — for as long as it is still
        // in-flight. If this vector destructed first (the default order for
        // a variable declared after `runtime`), a THEN block that returns
        // before explicitly waiting on the background task would free this
        // vector while that task could still be writing to it through the
        // now-dangling pointer.
        auto changed_rooms = std::vector<std::string>{};
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.test_room_changed_log = &changed_rooms;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const alice = reg.value;

        auto const certificate = write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        // Route the "resident.example.org" destination at our local TLS server,
        // trusting its self-signed cert, without touching discover_server() or
        // the system CA trust store for any other destination.
        runtime.test_forced_outbound_resolution[resident_server] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

        // wire_federation_callbacks sets runtime.federation.pdu_sink AND
        // runtime.federation.remote_key_resolver (to the real DNS/key-fetch
        // resolver) the first time it runs — and join_room calls it internally
        // if pdu_sink is still unset. Call it here first so that internal call
        // becomes a no-op (pdu_sink guard), then overwrite remote_key_resolver
        // below with the test double. Otherwise join_room's own call would
        // clobber the override set here.
        merovingian::homeserver::wire_federation_callbacks(runtime);
        runtime.federation.remote_key_resolver =
            [](std::string_view server_name,
               std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            if (server_name != resident_server || key_id != resident_key_id)
            {
                return std::nullopt;
            }
            return resident_remote_runtime();
        };

        auto const room_id = std::string{"!liveroom:"} + resident_server;
        auto const creator = std::string{"@creator:"} + resident_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");

        // --- make_join response: a minimal, unsigned v10 join template. ---
        auto const make_join_event = std::string{R"({"type":"m.room.member","state_key":")"} + alice +
                                     R"(","room_id":")" + room_id + R"(","sender":")" + alice +
                                     R"(","depth":6,"origin_server_ts":1000,)"
                                     R"("prev_events":[],"auth_events":[],)"
                                     R"("content":{"membership":"join"}})";
        auto const make_join_body = std::string{R"({"room_version":"10","event":)"} + make_join_event + "}";

        // --- send_join response: critical state (create/power_levels/our own
        // membership) plus five OTHER members' m.room.member events, all signed
        // by the resident server — the bulk that gets deferred to the
        // background task. ---
        auto const create_event = std::string{R"({"type":"m.room.create","state_key":"","sender":")"} + creator +
                                  R"(","room_id":")" + room_id +
                                  R"(","depth":1,"origin_server_ts":900,)"
                                  R"("prev_events":[],"auth_events":[],)"
                                  R"("content":{"room_version":"10","creator":")" +
                                  creator + R"("}})";
        auto const power_levels_event = std::string{R"({"type":"m.room.power_levels","state_key":"","sender":")"} +
                                        creator + R"(","room_id":")" + room_id +
                                        R"(","depth":2,"origin_server_ts":901,)"
                                        R"("prev_events":[],"auth_events":[],"content":{"users":{")" +
                                        creator + R"(":100}}})";

        auto state_array = merovingian::canonicaljson::Array{};
        state_array.push_back(
            sign_test_event(create_event, policy, resident_server, resident_key_id, resident_key_seed));
        state_array.push_back(
            sign_test_event(power_levels_event, policy, resident_server, resident_key_id, resident_key_seed));
        // Our own just-accepted join event: sender domain == our_server, so
        // filter_verified_send_join_events trusts it without a resolver round
        // trip — any placeholder signature is accepted for this entry.
        state_array.push_back(
            sign_test_event(make_join_event, policy, local_server, "ed25519:placeholder", resident_key_seed));

        static constexpr auto k_other_member_count = std::size_t{5U};
        for (auto member_index = std::size_t{0U}; member_index < k_other_member_count; ++member_index)
        {
            auto const member_id = "@member" + std::to_string(member_index) + ":" + resident_server;
            auto const member_event = std::string{R"({"type":"m.room.member","state_key":")"} + member_id +
                                      R"(","room_id":")" + room_id + R"(","sender":")" + member_id +
                                      R"(","depth":3,"origin_server_ts":902,)"
                                      R"("prev_events":[],"auth_events":[],)"
                                      R"("content":{"membership":"join"}})";
            state_array.push_back(
                sign_test_event(member_event, policy, resident_server, resident_key_id, resident_key_seed));
        }

        auto auth_chain_array = merovingian::canonicaljson::Array{};
        auth_chain_array.push_back(
            sign_test_event(create_event, policy, resident_server, resident_key_id, resident_key_seed));
        auth_chain_array.push_back(
            sign_test_event(power_levels_event, policy, resident_server, resident_key_id, resident_key_seed));

        auto const send_join_body = std::string{R"({"state":)"} + canonicaljson_array_to_string(state_array) +
                                    R"(,"auth_chain":)" + canonicaljson_array_to_string(auth_chain_array) + "}";

        auto const make_join_response = json_http_response("200 OK", make_join_body);
        auto const send_join_response = json_http_response("200 OK", send_join_body);

        WHEN("join_room is called with the resident server as the sole via candidate")
        {
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_join_response, send_join_response);
            }};

            auto const result =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});

            server_thread.join();

            THEN("the join succeeds immediately with critical room state already persisted")
            {
                REQUIRE(result.ok);
                REQUIRE(result.status == 200U);
                REQUIRE(result.value == room_id);

                // The background member-fill task (see HomeserverRuntime::orphan_futures_)
                // is still running at this point and writes to persistent_store under
                // runtime.mutex; every reader must take the same lock or race against it.
                auto const lock = std::lock_guard{runtime.mutex};

                auto const& state = runtime.database.persistent_store.state;
                REQUIRE(std::ranges::any_of(state, [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.create";
                }));
                REQUIRE(std::ranges::any_of(state, [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.power_levels";
                }));

                auto const& memberships = runtime.database.persistent_store.memberships;
                REQUIRE(std::ranges::any_of(memberships, [&](auto const& m) {
                    return m.room_id == room_id && m.user_id == alice && m.membership == "join";
                }));
            }

            THEN("after the background task drains, every deferred member is persisted too")
            {
                // Deterministic wait: block on every future queued by this
                // join's background fill (see HomeserverRuntime::orphan_futures_)
                // instead of sleeping. Waiting does not consume/invalidate a
                // std::future, so this is safe to do from the test thread.
                {
                    auto const lock = std::lock_guard{runtime.orphan_futures_mutex_};
                    for (auto& future : runtime.orphan_futures_)
                    {
                        if (future.valid())
                        {
                            future.wait();
                        }
                    }
                }

                auto const& memberships = runtime.database.persistent_store.memberships;
                for (auto member_index = std::size_t{0U}; member_index < k_other_member_count; ++member_index)
                {
                    auto const member_id = "@member" + std::to_string(member_index) + ":" + resident_server;
                    REQUIRE(std::ranges::any_of(memberships, [&](auto const& m) {
                        return m.room_id == room_id && m.user_id == member_id && m.membership == "join";
                    }));
                }

                auto const room_it = std::ranges::find_if(runtime.database.rooms, [&](auto const& r) {
                    return r.room_id == room_id;
                });
                REQUIRE(room_it != runtime.database.rooms.end());
                // alice + 5 deferred members.
                REQUIRE(room_it->members.size() == k_other_member_count + 1U);

                // The federation worker notification fires once for the
                // synchronous critical-state join and again once the
                // background member fill completes (see room_service.cpp's
                // notify_room_changed call sites) — both for this same room.
                REQUIRE_FALSE(changed_rooms.empty());
                REQUIRE(std::ranges::all_of(changed_rooms, [&](auto const& logged_room_id) {
                    return logged_room_id == room_id;
                }));
            }
        }
    }
}
