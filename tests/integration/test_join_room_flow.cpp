// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
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

#include "../federation_signing_test_support.hpp"
#include "../support/joining_threads.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <tuple>
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
                         std::string const& send_join_response, std::vector<std::string>& captured_requests,
                         std::function<void(std::string const&)> const& before_send = {})
{
    for (auto request_index = 0; request_index < 2; ++request_index)
    {
        auto const client_fd = accept_loopback(acceptor, 5000);
        if (client_fd < 0)
        {
            return;
        }
        // Owns the accepted descriptor: TlsConnection only borrows it, so without
        // this every served connection stayed open for the rest of the run.
        auto const owned_client_fd = merovingian::core::SocketHandle{client_fd};
        auto tls_result = merovingian::homeserver::accept_tls_connection(tls_context, client_fd, 5000);
        if (!tls_result.connection.has_value())
        {
            continue;
        }
        auto& connection = *tls_result.connection;
        auto buffer = std::array<char, 8192>{};
        auto request_bytes = std::string{};
        auto expected_bytes = std::size_t{0U};
        while (request_bytes.find("\r\n\r\n") == std::string::npos || request_bytes.size() < expected_bytes)
        {
            auto const bytes_read = connection.read(buffer.data(), buffer.size());
            if (bytes_read <= 0)
            {
                break;
            }
            request_bytes.append(buffer.data(), static_cast<std::size_t>(bytes_read));
            auto const header_end = request_bytes.find("\r\n\r\n");
            if (header_end != std::string::npos && expected_bytes == 0U)
            {
                auto const length_marker = request_bytes.find("Content-Length:");
                if (length_marker != std::string::npos)
                {
                    auto const value_start = length_marker + std::string{"Content-Length:"}.size();
                    auto const value_end = request_bytes.find("\r\n", value_start);
                    auto content_length = std::size_t{0U};
                    auto length_begin = value_start;
                    while (length_begin < value_end &&
                           (request_bytes[length_begin] == ' ' || request_bytes[length_begin] == '\t'))
                    {
                        ++length_begin;
                    }
                    auto const length_text = request_bytes.substr(length_begin, value_end - length_begin);
                    auto const parsed_length =
                        std::from_chars(length_text.data(), length_text.data() + length_text.size(), content_length);
                    expected_bytes =
                        parsed_length.ec == std::errc{} ? header_end + 4U + content_length : header_end + 4U;
                }
                else
                {
                    expected_bytes = header_end + 4U;
                }
            }
            if (static_cast<std::size_t>(bytes_read) < buffer.size())
            {
                if (request_bytes.find("\r\n\r\n") != std::string::npos && request_bytes.size() >= expected_bytes)
                {
                    break;
                }
            }
        }
        captured_requests.push_back(request_bytes);
        auto const is_send = request_bytes.find("/send_join/") != std::string::npos ||
                             request_bytes.find("/send_leave/") != std::string::npos;
        if (is_send && before_send)
        {
            before_send(request_bytes);
        }
        static_cast<void>(connection.write(is_send ? send_join_response : make_join_response));
    }
}

[[nodiscard]] auto request_body(std::string const& request) -> std::string
{
    auto const separator = request.find("\r\n\r\n");
    return separator == std::string::npos ? std::string{} : request.substr(separator + 4U);
}

[[nodiscard]] auto event_from_send_request(std::string const& request) -> merovingian::canonicaljson::Value
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(request_body(request));
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return parsed.value;
}

[[nodiscard]] auto object_member_count(merovingian::canonicaljson::Value const& value,
                                       std::string_view key) -> std::size_t
{
    auto const* object = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
    REQUIRE(object != nullptr);
    return static_cast<std::size_t>(std::ranges::count_if(*object, [&](auto const& member) {
        return member.key == key;
    }));
}

auto require_membership_event_integrity(merovingian::homeserver::HomeserverRuntime& runtime,
                                        merovingian::canonicaljson::Value const& event,
                                        merovingian::rooms::RoomVersionPolicy const& policy) -> void
{
    REQUIRE(object_member_count(event, "hashes") == 1U);
    auto const* object = std::get_if<merovingian::canonicaljson::Object>(&event.storage());
    REQUIRE(object != nullptr);
    auto const* hashes = merovingian::tests::object_member(*object, "hashes");
    REQUIRE(hashes != nullptr);
    REQUIRE(object_member_count(*hashes, "sha256") == 1U);
    auto const content_hash = merovingian::events::make_content_hash(event);
    REQUIRE(content_hash.error.empty());
    auto const* hashes_object = std::get_if<merovingian::canonicaljson::Object>(&hashes->storage());
    REQUIRE(hashes_object != nullptr);
    auto const* sha256 = merovingian::tests::object_member(*hashes_object, "sha256");
    REQUIRE(sha256 != nullptr);
    REQUIRE(std::get<std::string>(sha256->storage()) == content_hash.sha256);

    REQUIRE(object_member_count(event, "signatures") == 1U);
    auto const key_it =
        std::ranges::find_if(runtime.database.persistent_store.server_signing_keys, [&](auto const& key) {
            return key.server_name == runtime.config.server().server_name;
        });
    REQUIRE(key_it != runtime.database.persistent_store.server_signing_keys.end());
    auto const payload = merovingian::events::make_event_signing_payload(event, policy);
    REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
    auto const* signatures = merovingian::tests::object_member(*object, "signatures");
    REQUIRE(signatures != nullptr);
    auto const* signatures_object = std::get_if<merovingian::canonicaljson::Object>(&signatures->storage());
    REQUIRE(signatures_object != nullptr);
    auto const* server_signatures = merovingian::tests::object_member(*signatures_object, key_it->server_name);
    REQUIRE(server_signatures != nullptr);
    auto const* server_signature_object =
        std::get_if<merovingian::canonicaljson::Object>(&server_signatures->storage());
    REQUIRE(server_signature_object != nullptr);
    auto const* signature = merovingian::tests::object_member(*server_signature_object, key_it->key_id);
    REQUIRE(signature != nullptr);
    auto const signature_bytes =
        merovingian::events::matrix_bytes_from_base64(std::get<std::string>(signature->storage()));
    auto const verified = merovingian::crypto::ed25519_verify(
        merovingian::crypto::Ed25519PublicKey{merovingian::events::matrix_bytes_from_base64(key_it->public_key)},
        payload.output, merovingian::crypto::Ed25519Signature{signature_bytes});
    REQUIRE(verified.valid);
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
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

// The resident server's key, valid until 2100-01-01: from room v5 a key must
// still be valid at each event's origin_server_ts (ADR-0075).
[[nodiscard]] auto resident_remote_runtime() -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = resident_server;
    remote.signing_key = {resident_server, resident_key_id, 4'102'444'800'000U,
                          merovingian::federation::test::keypair_from_seed(resident_key_seed).public_key};
    remote.discovery.server_name = resident_server;
    remote.trust.reputation_score = 100U;
    return remote;
}

// Signs `raw_event_json` with the raw 64-byte Ed25519 `secret_key` and attaches
// the signature under {claimed_server, claimed_key_id}, returning the fully
// signed event as a parsed canonicaljson::Value ready to drop into a state or
// auth_chain array. sign_test_event below does the same with the keypair
// derived from a seed.
[[nodiscard]] auto sign_test_event_with_secret(
    std::string const& raw_event_json, merovingian::rooms::RoomVersionPolicy const& policy,
    std::string const& claimed_server, std::string const& claimed_key_id,
    std::span<std::uint8_t const> secret_key) -> merovingian::canonicaljson::Value
{
    REQUIRE(secret_key.size() == crypto_sign_SECRETKEYBYTES);
    auto const parsed = merovingian::canonicaljson::parse_lossless(raw_event_json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const payload = merovingian::events::make_event_signing_payload(parsed.value, policy);
    REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
    auto sig = std::array<unsigned char, crypto_sign_BYTES>{};
    crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<unsigned char const*>(payload.output.data()),
                         payload.output.size(), secret_key.data());
    auto const sig_b64 =
        merovingian::events::matrix_base64_from_bytes({reinterpret_cast<char const*>(sig.data()), crypto_sign_BYTES});
    auto const attached =
        merovingian::events::attach_event_signature(parsed.value, {claimed_server, claimed_key_id}, sig_b64);
    REQUIRE(attached.error == merovingian::canonicaljson::CanonicalJsonError::none);
    auto const reparsed = merovingian::canonicaljson::parse_lossless(attached.output);
    REQUIRE(reparsed.error == merovingian::canonicaljson::ParseError::none);
    return reparsed.value;
}

[[nodiscard]] auto sign_test_event(std::string const& raw_event_json,
                                   merovingian::rooms::RoomVersionPolicy const& policy,
                                   std::string const& claimed_server, std::string const& claimed_key_id,
                                   std::string const& sign_seed) -> merovingian::canonicaljson::Value
{
    auto const kp = merovingian::federation::test::keypair_from_seed(sign_seed);
    return sign_test_event_with_secret(raw_event_json, policy, claimed_server, claimed_key_id,
                                       merovingian::federation::test::secret_key_span(kp));
}

// Signs `raw_event_json` with this runtime's own current server signing key,
// under the key ID the server publishes — an event this server genuinely
// authored, as a resident server would echo it back in a send_join response.
[[nodiscard]] auto sign_with_local_server_key(
    merovingian::homeserver::HomeserverRuntime& runtime, std::string const& raw_event_json,
    merovingian::rooms::RoomVersionPolicy const& policy) -> merovingian::canonicaljson::Value
{
    auto const own_key = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);
    REQUIRE(own_key.has_value());
    return sign_test_event_with_secret(raw_event_json, policy, local_server, own_key->key_id,
                                       runtime.database.signing_secret_key.bytes());
}

[[nodiscard]] auto reference_event_id(merovingian::canonicaljson::Value const& event,
                                      merovingian::rooms::RoomVersionPolicy const& policy) -> std::string
{
    auto const eid = merovingian::events::make_reference_hash_event_id(event, policy);
    REQUIRE(eid.error.empty());
    REQUIRE_FALSE(eid.event_id.empty());
    return eid.event_id;
}

// Blocks until every background task a join queued (the partial-state
// member fill, see HomeserverRuntime::orphan_futures_) has finished.
auto wait_for_join_background_tasks(merovingian::homeserver::HomeserverRuntime& runtime) -> void
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
         "[membership-template-hashes][homeserver][federation][join][integration]")
{
    GIVEN("a real HomeserverRuntime, a logged-in local user, and a real TLS resident server")
    {
        REQUIRE(sodium_init() >= 0);
        auto const template_has_hashes = GENERATE(false, true);
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
                                     R"("prev_events":[],"auth_events":[],)" +
                                     (template_has_hashes ? R"("hashes":{"sha256":"stale"},)" : "") +
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
        // Our own join event, echoed back: sender domain == our_server, so
        // filter_verified_send_join_events verifies it against this server's
        // own signing keys, with no resolver round trip. It must carry a
        // genuine signature from our key — an own-domain event is never
        // trusted without one (FED-1, ADR-0083).
        state_array.push_back(sign_with_local_server_key(runtime, make_join_event, policy));

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
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_join_response, send_join_response,
                                    captured_requests);
            }};

            auto const result =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});

            server_thread.join();

            THEN("the join succeeds immediately with critical room state already persisted")
            {
                CAPTURE(template_has_hashes, result.reason);
                REQUIRE(result.ok);
                REQUIRE(result.status == 200U);
                REQUIRE(result.value == room_id);
                REQUIRE(captured_requests.size() == 2U);
                auto const join_event = event_from_send_request(captured_requests[1]);
                require_membership_event_integrity(runtime, join_event, policy);

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

// ADR-0064 phase B1: the join event must come out of a federated join with
// its own after-state group (the returned state plus the join itself) and
// be the room's sole forward extremity, or every inbound PDU that follows
// fails closed with missing_prev_state — a federation regression, since the
// pre-ADR-0064 code accepted such PDUs (via current-state-only auth) with
// no state-group concept at all. Unlike the scenario above, this fixture's
// send_join state array deliberately does NOT include alice's own join
// event (per spec, "state" is the room's state *before* the join event),
// so the join-event-storage code path this test exercises actually runs.
SCENARIO("A federated join seeds the join event's after-state group and forward extremity, "
         "so a subsequent inbound PDU is accepted",
         "[pdu_ingestion][state_groups][homeserver][federation][join][integration]")
{
    GIVEN("a real HomeserverRuntime, a logged-in local user, and a real TLS resident server")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

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

        runtime.test_forced_outbound_resolution[resident_server] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

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

        auto const room_id = std::string{"!seedroom:"} + resident_server;
        auto const creator = std::string{"@creator:"} + resident_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");

        auto const make_join_event = std::string{R"({"type":"m.room.member","state_key":")"} + alice +
                                     R"(","room_id":")" + room_id + R"(","sender":")" + alice +
                                     R"(","depth":3,"origin_server_ts":1000,)"
                                     R"("prev_events":[],"auth_events":[],)"
                                     R"("content":{"membership":"join"}})";
        auto const make_join_body = std::string{R"({"room_version":"10","event":)"} + make_join_event + "}";

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

        // The state array is the room's state BEFORE the join — create and
        // power_levels only, no join event and no other members, matching
        // spec (server-server-api.md#joining-rooms).
        auto state_array = merovingian::canonicaljson::Array{};
        state_array.push_back(
            sign_test_event(create_event, policy, resident_server, resident_key_id, resident_key_seed));
        state_array.push_back(
            sign_test_event(power_levels_event, policy, resident_server, resident_key_id, resident_key_seed));

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
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_join_response, send_join_response,
                                    captured_requests);
            }};

            auto const result =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});

            server_thread.join();

            THEN("the join succeeds and the join event's after-state equals the returned state plus the join")
            {
                CAPTURE(result.reason);
                REQUIRE(result.ok);
                REQUIRE(result.status == 200U);

                auto const lock = std::lock_guard{runtime.mutex};
                auto const& store = runtime.database.persistent_store;

                // Find the stored join event: the one m.room.member row for
                // alice in this room.
                auto const join_state_row =
                    std::ranges::find_if(store.state, [&](merovingian::database::PersistentStateEvent const& s) {
                        return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == alice;
                    });
                REQUIRE(join_state_row != store.state.end());
                auto const join_event_id = join_state_row->event_id;

                auto const group = merovingian::database::find_event_state_group(store, join_event_id);
                REQUIRE(group.has_value());
                auto const full = merovingian::database::read_state_group_full_state(store, *group);
                REQUIRE(full.has_value());
                REQUIRE(full->size() == 3U); // create + power_levels + alice's join
                REQUIRE(std::ranges::any_of(*full, [](auto const& e) {
                    return e.event_type == "m.room.create";
                }));
                REQUIRE(std::ranges::any_of(*full, [](auto const& e) {
                    return e.event_type == "m.room.power_levels";
                }));
                auto const member_entry = std::ranges::find_if(*full, [](auto const& e) {
                    return e.event_type == "m.room.member";
                });
                REQUIRE(member_entry != full->end());
                REQUIRE(member_entry->state_key == alice);
                REQUIRE(member_entry->event_id == join_event_id);

                AND_THEN("the join event is the room's sole forward extremity")
                {
                    auto const extremities = merovingian::database::find_forward_extremities(store, room_id);
                    REQUIRE(extremities.size() == 1U);
                    REQUIRE(extremities.front() == join_event_id);
                }

                AND_THEN("a subsequent inbound PDU referencing the join event is accepted, not missing_prev_state")
                {
                    auto content = merovingian::canonicaljson::Object{};
                    content.push_back(merovingian::canonicaljson::make_member(
                        "body", merovingian::canonicaljson::Value{std::string{"hello after join"}}));
                    content.push_back(merovingian::canonicaljson::make_member(
                        "msgtype", merovingian::canonicaljson::Value{std::string{"m.text"}}));
                    auto obj = merovingian::canonicaljson::Object{};
                    obj.push_back(merovingian::canonicaljson::make_member(
                        "type", merovingian::canonicaljson::Value{std::string{"m.room.message"}}));
                    obj.push_back(
                        merovingian::canonicaljson::make_member("room_id", merovingian::canonicaljson::Value{room_id}));
                    obj.push_back(
                        merovingian::canonicaljson::make_member("sender", merovingian::canonicaljson::Value{alice}));
                    obj.push_back(
                        merovingian::canonicaljson::make_member("content", merovingian::canonicaljson::Value{content}));
                    obj.push_back(merovingian::canonicaljson::make_member(
                        "origin_server_ts", merovingian::canonicaljson::Value{std::int64_t{2000}}));
                    obj.push_back(merovingian::canonicaljson::make_member(
                        "depth", merovingian::canonicaljson::Value{std::int64_t{4}}));
                    auto prev_arr = merovingian::canonicaljson::Array{};
                    prev_arr.push_back(merovingian::canonicaljson::Value{join_event_id});
                    obj.push_back(merovingian::canonicaljson::make_member(
                        "prev_events", merovingian::canonicaljson::Value{std::move(prev_arr)}));
                    // ADR-0064 phase B2: ingest_pdu_event now authorises
                    // against the PDU's own named auth_events (spec step
                    // 4), so this fixture needs the room's real
                    // create/power_levels events and alice's own (just
                    // established) join — read from `full`, the join
                    // event's own after-state, computed above.
                    auto const create_entry = std::ranges::find_if(*full, [](auto const& e) {
                        return e.event_type == "m.room.create";
                    });
                    auto const pl_entry = std::ranges::find_if(*full, [](auto const& e) {
                        return e.event_type == "m.room.power_levels";
                    });
                    REQUIRE(create_entry != full->end());
                    REQUIRE(pl_entry != full->end());
                    // This fixture pins room_version "10" below (not v12),
                    // so create is a required, permitted auth_events entry
                    // — unlike the v12 case elsewhere, where it must be
                    // omitted.
                    auto auth_event_ids =
                        std::vector<std::string>{create_entry->event_id, pl_entry->event_id, join_event_id};
                    auto auth_arr = merovingian::canonicaljson::Array{};
                    for (auto const& id : auth_event_ids)
                    {
                        auth_arr.push_back(merovingian::canonicaljson::Value{id});
                    }
                    obj.push_back(merovingian::canonicaljson::make_member(
                        "auth_events", merovingian::canonicaljson::Value{std::move(auth_arr)}));
                    auto const hash = merovingian::events::make_content_hash(merovingian::canonicaljson::Value{obj});
                    REQUIRE(hash.error.empty());
                    auto hashes = merovingian::canonicaljson::Object{};
                    hashes.push_back(merovingian::canonicaljson::make_member(
                        "sha256", merovingian::canonicaljson::Value{hash.sha256}));
                    obj.push_back(merovingian::canonicaljson::make_member(
                        "hashes", merovingian::canonicaljson::Value{std::move(hashes)}));
                    auto const serialized = merovingian::canonicaljson::serialize_canonical(
                        merovingian::canonicaljson::Value{std::move(obj)});
                    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);

                    auto envelope = merovingian::federation::InboundPduEnvelope{};
                    envelope.event_id = "$after_join:" + std::string{resident_server};
                    envelope.room_id = room_id;
                    envelope.room_version = "10";
                    envelope.sender = alice;
                    envelope.event_type = "m.room.message";
                    envelope.origin_server_ts = 2000;
                    envelope.depth = 4U;
                    envelope.prev_event_ids = {join_event_id};
                    envelope.auth_event_ids = std::move(auth_event_ids);
                    envelope.json = serialized.output;

                    auto const ingest_result = merovingian::homeserver::ingest_pdu_event(runtime, envelope);
                    REQUIRE(ingest_result.status == merovingian::federation::PduIngestionStatus::accepted);
                }
            }
        }
    }
}

SCENARIO("Outbound joins defer concurrent PDUs until committed and discard them on failure",
         "[security][federation][fed-11][fed-11-lifecycle][join][integration]")
{
    GIVEN("a local user joining a real TLS resident with concurrent PDU delivery")
    {
        auto const failure = std::string{GENERATE("none", "response", "throw", "drain")};
        auto const flood = std::string{GENERATE("single", "count", "bytes")};
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

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

        runtime.test_forced_outbound_resolution[resident_server] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

        merovingian::homeserver::wire_federation_callbacks(runtime);
        runtime.federation.remote_key_resolver =
            [failure](std::string_view server_name,
                      std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            if (server_name != resident_server || key_id != resident_key_id)
            {
                return std::nullopt;
            }
            if (failure == "throw")
            {
                throw std::runtime_error{"join verification failed"};
            }
            return resident_remote_runtime();
        };

        auto const room_id = std::string{"!seedroom:"} + resident_server;
        auto const creator = std::string{"@creator:"} + resident_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");

        auto const make_join_event = std::string{R"({"type":"m.room.member","state_key":")"} + alice +
                                     R"(","room_id":")" + room_id + R"(","sender":")" + alice +
                                     R"(","depth":3,"origin_server_ts":1000,)"
                                     R"("prev_events":[],"auth_events":[],)"
                                     R"("content":{"membership":"join"}})";
        auto const make_join_body = std::string{R"({"room_version":"10","event":)"} + make_join_event + "}";

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

        // The state array is the room's state BEFORE the join — create and
        // power_levels only, no join event and no other members, matching
        // spec (server-server-api.md#joining-rooms).
        auto state_array = merovingian::canonicaljson::Array{};
        state_array.push_back(
            sign_test_event(create_event, policy, resident_server, resident_key_id, resident_key_seed));
        state_array.push_back(
            sign_test_event(power_levels_event, policy, resident_server, resident_key_id, resident_key_seed));

        auto auth_chain_array = merovingian::canonicaljson::Array{};
        auth_chain_array.push_back(
            sign_test_event(create_event, policy, resident_server, resident_key_id, resident_key_seed));
        auth_chain_array.push_back(
            sign_test_event(power_levels_event, policy, resident_server, resident_key_id, resident_key_seed));

        auto const send_join_body = std::string{R"({"state":)"} + canonicaljson_array_to_string(state_array) +
                                    R"(,"auth_chain":)" + canonicaljson_array_to_string(auth_chain_array) + "}";

        auto const make_join_response = json_http_response("200 OK", make_join_body);
        auto const send_join_response =
            json_http_response(failure == "response" ? "500 Internal Server Error" : "200 OK", send_join_body);

        WHEN("the resident delivers a PDU before completing send_join")
        {
            auto captured_requests = std::vector<std::string>{};
            auto pending = merovingian::federation::InboundPduEnvelope{};
            auto deferred = merovingian::federation::PduIngestionResult{};
            auto events_unchanged = false;
            auto ordering_unchanged = false;
            auto sync_unchanged = false;
            auto queue_size = std::size_t{0U};
            auto queue_bytes = std::size_t{0U};
            auto duplicate_unchanged = false;
            auto refused_excess = false;
            auto other_room_refused = false;
            auto overlap_refused = false;
            auto saturated_room_refused = false;
            auto server_thread = merovingian::tests::JoiningThreads{};
            server_thread.emplace_back([&]() {
                run_resident_server(
                    acceptor, *tls_context.context, make_join_response, send_join_response, captured_requests,
                    [&](std::string const& request) {
                        auto const join = event_from_send_request(request);
                        auto const join_id = reference_event_id(join, policy);
                        auto const create_id = reference_event_id(state_array[0], policy);
                        auto const power_id = reference_event_id(state_array[1], policy);
                        auto const message =
                            std::string{R"({"type":"m.room.message","room_id":")"} + room_id + R"(","sender":")" +
                            alice +
                            R"(","content":{"body":"during join","msgtype":"m.text"},"depth":4,"origin_server_ts":2000,"prev_events":[")" +
                            join_id + R"("],"auth_events":[")" + create_id + R"(",")" + power_id + R"(",")" + join_id +
                            R"("]})";
                        auto const lock = std::lock_guard{runtime.mutex};
                        auto const with_hash = merovingian::canonicaljson::parse_lossless(message);
                        auto const hash = merovingian::events::make_content_hash(with_hash.value);
                        auto message_object = std::get<merovingian::canonicaljson::Object>(with_hash.value.storage());
                        auto hashes = merovingian::canonicaljson::Object{};
                        hashes.push_back(merovingian::canonicaljson::make_member(
                            "sha256", merovingian::canonicaljson::Value{hash.sha256}));
                        message_object.push_back(merovingian::canonicaljson::make_member(
                            "hashes", merovingian::canonicaljson::Value{std::move(hashes)}));
                        auto const hash_json = merovingian::canonicaljson::serialize_canonical(
                                                   merovingian::canonicaljson::Value{std::move(message_object)})
                                                   .output;
                        auto const signed_json = merovingian::canonicaljson::serialize_canonical(
                                                     sign_with_local_server_key(runtime, hash_json, policy))
                                                     .output;
                        pending = *merovingian::federation::parse_inbound_pdu_envelope(signed_json, "10");
                        // Direct validated-envelope receipt: origin is deliberately omitted
                        // so the RED baseline cannot fetch the not-yet-committed join.
                        // The post-commit drain still runs the full common auth pipeline.
                        auto const events = runtime.database.persistent_store.events.size();
                        auto const ordering = runtime.database.next_stream_ordering;
                        auto const sync = runtime.database.persistent_store.next_sync_stream_id;
                        deferred = runtime.federation.pdu_sink(pending);
                        if (deferred.status == merovingian::federation::PduIngestionStatus::missing_prev_state &&
                            runtime.pending_federated_joins.contains(room_id))
                        {
                            auto const initial_bytes = runtime.pending_federated_joins.at(room_id).json_bytes;
                            std::ignore = runtime.federation.pdu_sink(pending);
                            duplicate_unchanged =
                                runtime.pending_federated_joins.at(room_id).pdus.size() == 1U &&
                                runtime.pending_federated_joins.at(room_id).json_bytes == initial_bytes;
                            auto other = pending;
                            other.room_id = "!other:resident.example.org";
                            other.event_id = "$unrelated";
                            auto const other_result = runtime.federation.pdu_sink(other);
                            other_room_refused =
                                other_result.status == merovingian::federation::PduIngestionStatus::rejected_invalid;
                            auto const overlap = merovingian::homeserver::join_room(runtime, login.value, room_id,
                                                                                    {std::string{resident_server}});
                            overlap_refused = !overlap.ok && overlap.status == 429U &&
                                              runtime.pending_federated_joins.at(room_id).pdus.size() == 1U;
                            // Saturate the global reservation bound while a REAL lease is
                            // alive, then prove a new room fails before issuing make_join.
                            for (auto index = 0U; index < 31U; ++index)
                            {
                                runtime.pending_federated_joins.try_emplace("!reserved" + std::to_string(index));
                            }
                            auto const saturated = merovingian::homeserver::join_room(
                                runtime, login.value, "!overflow:resident.example.org", {std::string{resident_server}});
                            saturated_room_refused = !saturated.ok && saturated.status == 429U &&
                                                     runtime.pending_federated_joins.size() == 32U;
                            for (auto index = 0U; index < 31U; ++index)
                            {
                                runtime.pending_federated_joins.erase("!reserved" + std::to_string(index));
                            }
                            if (flood != "single")
                            {
                                // Signed, format-valid v10 events, not manually invented
                                // envelopes. Count and byte limits must be independent.
                                for (auto index = 0U; index < 40U; ++index)
                                {
                                    auto const filler =
                                        flood == "bytes" ? std::string(60U * 1024U, 'X') : std::string{"filler"};
                                    auto const raw =
                                        std::string{R"({"type":"m.room.message","room_id":")"} + room_id +
                                        R"(","sender":"@creator:resident.example.org","content":{"body":")" + filler +
                                        std::to_string(index) +
                                        R"(","msgtype":"m.text"},"depth":1,"origin_server_ts":1000,"prev_events":[],"auth_events":[]})";
                                    auto const json = merovingian::federation::test::make_signed_event_json(
                                        raw, resident_server, resident_key_id, resident_key_seed, "10");
                                    auto envelope = *merovingian::federation::parse_inbound_pdu_envelope(json, "10");
                                    envelope.origin = resident_server;
                                    auto const result = runtime.federation.pdu_sink(envelope);
                                    if (result.status == merovingian::federation::PduIngestionStatus::main_overloaded)
                                    {
                                        refused_excess = true;
                                    }
                                }
                            }
                            queue_size = runtime.pending_federated_joins.at(room_id).pdus.size();
                            queue_bytes = runtime.pending_federated_joins.at(room_id).json_bytes;
                        }
                        events_unchanged = runtime.database.persistent_store.events.size() == events;
                        ordering_unchanged = runtime.database.next_stream_ordering == ordering;
                        sync_unchanged = runtime.database.persistent_store.next_sync_stream_id == sync;
                        if (failure == "drain")
                        {
                            runtime.federation.pdu_sink =
                                [](auto const&) -> merovingian::federation::PduIngestionResult {
                                throw std::runtime_error{"drain ingestion exception"};
                            };
                        }
                    });
            });
            auto result = merovingian::homeserver::OperationResult{};
            auto threw = false;
            auto outer_lock_restored = false;
            try
            {
                auto outer_guard = std::unique_lock{runtime.mutex};
                auto const request_scope = merovingian::homeserver::RequestLockScope{outer_guard};
                result =
                    merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});
                outer_lock_restored = runtime.mutex.held_by_current_thread();
            }
            catch (std::runtime_error const&)
            {
                threw = true;
            }
            server_thread.join();
            THEN("receipt is deferred without storage or stream allocation")
            {
                CHECK(deferred.status == merovingian::federation::PduIngestionStatus::missing_prev_state);
                CHECK(events_unchanged);
                CHECK(ordering_unchanged);
                CHECK(sync_unchanged);
                CHECK(duplicate_unchanged);
                CHECK(other_room_refused);
                CHECK(overlap_refused);
                CHECK(saturated_room_refused);
                CHECK(runtime.pending_federated_joins.empty());
                CHECK(queue_bytes <= 512U * 1024U);
                CHECK(queue_size <= 32U);
                if (flood == "count")
                {
                    CHECK(queue_size == 32U);
                    CHECK(refused_excess);
                }
                if (flood == "bytes")
                {
                    CHECK(queue_size < 32U);
                    CHECK(refused_excess);
                }
                auto const stored =
                    std::ranges::find_if(runtime.database.persistent_store.events, [&](auto const& event) {
                        return event.event_id == pending.event_id;
                    });
                if (failure == "none" || failure == "drain")
                {
                    INFO(result.reason);
                    REQUIRE(result.ok);
                    REQUIRE_FALSE(threw);
                    CHECK(outer_lock_restored);
                    if (failure == "none")
                    {
                        REQUIRE(stored != runtime.database.persistent_store.events.end());
                        CHECK(stored->status == "accepted");
                    }
                    else
                    {
                        CHECK(stored == runtime.database.persistent_store.events.end());
                        CHECK(std::ranges::any_of(
                            runtime.database.persistent_store.memberships, [&](auto const& membership) {
                                return membership.room_id == room_id && membership.user_id == alice &&
                                       membership.membership == "join";
                            }));
                    }
                }
                else
                {
                    CHECK_FALSE(result.ok);
                    CHECK(threw == (failure == "throw"));
                    CHECK(stored == runtime.database.persistent_store.events.end());
                    CHECK(runtime.database.persistent_store.events.empty());
                    auto const before = runtime.database.next_stream_ordering;
                    std::ignore = runtime.federation.pdu_sink(pending);
                    CHECK(runtime.database.persistent_store.events.empty());
                    CHECK(runtime.database.next_stream_ordering == before);
                    // Repeated failures cannot turn ephemeral queues into rejected rows.
                    for (auto attempt = 0U; attempt < 2U; ++attempt)
                    {
                        auto const ordering = runtime.database.next_stream_ordering;
                        auto const sync = runtime.database.persistent_store.next_sync_stream_id;
                        auto repeated_requests = std::vector<std::string>{};
                        auto repeated = merovingian::tests::JoiningThreads{};
                        repeated.emplace_back([&]() {
                            run_resident_server(acceptor, *tls_context.context, make_join_response, send_join_response,
                                                repeated_requests, [&](auto const&) {
                                                    std::ignore = runtime.federation.pdu_sink(pending);
                                                });
                        });
                        try
                        {
                            auto const again = merovingian::homeserver::join_room(runtime, login.value, room_id,
                                                                                  {std::string{resident_server}});
                            CHECK_FALSE(again.ok);
                        }
                        catch (std::runtime_error const&)
                        {
                            CHECK(failure == "throw");
                        }
                        repeated.join();
                        CHECK(runtime.pending_federated_joins.empty());
                        CHECK(runtime.database.persistent_store.events.empty());
                        CHECK(runtime.database.next_stream_ordering == ordering);
                        CHECK(runtime.database.persistent_store.next_sync_stream_id == sync);
                    }
                }
            }
        }
    }
}

// FED-1 (security audit 2026-09-29): a send_join response is the resident
// server's description of the room being joined, and nothing else. Spec:
// Server-Server API v1.19, "Joining Rooms" (`state` is the room state before
// the join event, `auth_chain` its auth chain) and "Checks performed on
// receipt of a PDU", step 2: "Passes signature checks, otherwise it is
// dropped" — with no exception for events naming our own domain. Before the
// fix, a local user could join a room on a server they control and have its
// send_join response rewrite the current state of any room hosted here.
SCENARIO("A send_join response cannot inject state into a local room",
         "[fed1][security][homeserver][federation][join][integration]")
{
    GIVEN("local room L with power levels P, and a resident server whose send_join names L in forged events")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice_reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                            merovingian::tests::registration_token);
        REQUIRE(alice_reg.ok);
        auto const alice_login =
            merovingian::homeserver::login_local_user(runtime, alice_reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(alice_login.ok);
        auto const bob_reg = merovingian::homeserver::register_local_user(runtime, "bob", "CorrectHorse7!",
                                                                          merovingian::tests::registration_token);
        REQUIRE(bob_reg.ok);
        auto const bob_login =
            merovingian::homeserver::login_local_user(runtime, bob_reg.value, "CorrectHorse7!", "DEVICE2");
        REQUIRE(bob_login.ok);
        auto const bob = bob_reg.value;

        // L: created by alice, bob invited and joined, alice holds power 100.
        auto const created = merovingian::homeserver::create_room(runtime, alice_login.value);
        REQUIRE(created.ok);
        auto const local_room = created.value;
        REQUIRE(merovingian::homeserver::invite_user(runtime, alice_login.value, local_room, bob).ok);
        REQUIRE(merovingian::homeserver::join_room(runtime, bob_login.value, local_room).ok);

        using StateRow = std::tuple<std::string, std::string, std::string>;
        auto const local_state = [&] {
            auto rows = std::vector<StateRow>{};
            for (auto const& s : runtime.database.persistent_store.state)
            {
                if (s.room_id == local_room)
                {
                    rows.emplace_back(s.event_type, s.state_key, s.event_id);
                }
            }
            std::ranges::sort(rows);
            return rows;
        };
        auto const local_memberships = [&] {
            auto rows = std::vector<std::pair<std::string, std::string>>{};
            for (auto const& m : runtime.database.persistent_store.memberships)
            {
                if (m.room_id == local_room)
                {
                    rows.emplace_back(m.user_id, m.membership);
                }
            }
            std::ranges::sort(rows);
            return rows;
        };
        auto const local_event_ids = [&] {
            auto ids = std::vector<std::string>{};
            for (auto const& e : runtime.database.persistent_store.events)
            {
                if (e.room_id == local_room)
                {
                    ids.push_back(e.event_id);
                }
            }
            std::ranges::sort(ids);
            return ids;
        };
        auto const state_before = local_state();
        auto const memberships_before = local_memberships();
        auto const events_before = local_event_ids();
        REQUIRE(std::ranges::any_of(state_before, [](StateRow const& row) {
            return std::get<0>(row) == "m.room.power_levels";
        }));

        auto const certificate = write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);
        runtime.test_forced_outbound_resolution[resident_server] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};
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

        auto const joined_room = std::string{"!fed1:"} + resident_server;
        auto const creator = std::string{"@creator:"} + resident_server;
        auto const evil = std::string{"@evil:"} + resident_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");

        auto const make_join_event = std::string{R"({"type":"m.room.member","state_key":")"} + bob +
                                     R"(","room_id":")" + joined_room + R"(","sender":")" + bob +
                                     R"(","depth":3,"origin_server_ts":1000,)"
                                     R"("prev_events":[],"auth_events":[],)"
                                     R"("content":{"membership":"join"}})";
        auto const make_join_body = std::string{R"({"room_version":"10","event":)"} + make_join_event + "}";
        auto const create_event = std::string{R"({"type":"m.room.create","state_key":"","sender":")"} + creator +
                                  R"(","room_id":")" + joined_room +
                                  R"(","depth":1,"origin_server_ts":900,"prev_events":[],"auth_events":[],)"
                                  R"("content":{"room_version":"10","creator":")" +
                                  creator + R"("}})";
        auto const power_levels_event = std::string{R"({"type":"m.room.power_levels","state_key":"","sender":")"} +
                                        creator + R"(","room_id":")" + joined_room +
                                        R"(","depth":2,"origin_server_ts":901,"prev_events":[],"auth_events":[],)"
                                        R"("content":{"users":{")" +
                                        creator + R"(":100}}})";

        // (a) an unsigned m.room.power_levels for L naming an own-domain sender.
        auto const forged_unsigned_pl = std::string{R"({"type":"m.room.power_levels","state_key":"","sender":")"} +
                                        bob + R"(","room_id":")" + local_room +
                                        R"(","depth":10,"origin_server_ts":950,"prev_events":[],"auth_events":[],)"
                                        R"("content":{"users":{")" +
                                        bob + R"(":100}}})";
        // (b) an m.room.power_levels for L genuinely signed by the resident server.
        auto const forged_signed_pl = std::string{R"({"type":"m.room.power_levels","state_key":"","sender":")"} + evil +
                                      R"(","room_id":")" + local_room +
                                      R"(","depth":11,"origin_server_ts":951,"prev_events":[],"auth_events":[],)"
                                      R"("content":{"users":{")" +
                                      bob + R"(":100,")" + evil + R"(":100}}})";
        // (c) another user's m.room.member for L, deferred to the background fill.
        auto const forged_member = std::string{R"({"type":"m.room.member","state_key":")"} + evil + R"(","room_id":")" +
                                   local_room + R"(","sender":")" + evil +
                                   R"(","depth":12,"origin_server_ts":952,"prev_events":[],"auth_events":[],)"
                                   R"("content":{"membership":"join"}})";

        auto const forged_unsigned_pl_value = merovingian::canonicaljson::parse_lossless(forged_unsigned_pl).value;
        auto const forged_signed_pl_value =
            sign_test_event(forged_signed_pl, policy, resident_server, resident_key_id, resident_key_seed);
        auto const forged_member_value =
            sign_test_event(forged_member, policy, resident_server, resident_key_id, resident_key_seed);
        auto const forged_ids = std::vector<std::string>{
            reference_event_id(forged_unsigned_pl_value, policy),
            reference_event_id(forged_signed_pl_value, policy),
            reference_event_id(forged_member_value, policy),
        };

        auto state_array = merovingian::canonicaljson::Array{};
        state_array.push_back(
            sign_test_event(create_event, policy, resident_server, resident_key_id, resident_key_seed));
        state_array.push_back(
            sign_test_event(power_levels_event, policy, resident_server, resident_key_id, resident_key_seed));
        state_array.push_back(forged_unsigned_pl_value);
        state_array.push_back(forged_signed_pl_value);
        state_array.push_back(forged_member_value);

        auto auth_chain_array = merovingian::canonicaljson::Array{};
        auth_chain_array.push_back(
            sign_test_event(create_event, policy, resident_server, resident_key_id, resident_key_seed));
        auth_chain_array.push_back(
            sign_test_event(power_levels_event, policy, resident_server, resident_key_id, resident_key_seed));
        auth_chain_array.push_back(forged_unsigned_pl_value);
        auth_chain_array.push_back(forged_signed_pl_value);

        auto const send_join_body = std::string{R"({"state":)"} + canonicaljson_array_to_string(state_array) +
                                    R"(,"auth_chain":)" + canonicaljson_array_to_string(auth_chain_array) + "}";
        auto const make_join_response = json_http_response("200 OK", make_join_body);
        auto const send_join_response = json_http_response("200 OK", send_join_body);

        WHEN("bob joins the resident server's room through it")
        {
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_join_response, send_join_response,
                                    captured_requests);
            }};
            auto const result = merovingian::homeserver::join_room(runtime, bob_login.value, joined_room,
                                                                   {std::string{resident_server}});
            server_thread.join();
            wait_for_join_background_tasks(runtime);
            auto const lock = std::lock_guard{runtime.mutex};

            THEN("the join itself still succeeds, with the joined room's genuine state")
            {
                CAPTURE(result.reason);
                REQUIRE(result.ok);
                REQUIRE(std::ranges::any_of(runtime.database.persistent_store.state, [&](auto const& s) {
                    return s.room_id == joined_room && s.event_type == "m.room.power_levels";
                }));
            }

            THEN("L's current state and memberships are unchanged")
            {
                REQUIRE(local_state() == state_before);
                REQUIRE(local_memberships() == memberships_before);
            }

            THEN("none of the forged events is stored")
            {
                REQUIRE(local_event_ids() == events_before);
                for (auto const& forged_id : forged_ids)
                {
                    CAPTURE(forged_id);
                    REQUIRE_FALSE(std::ranges::any_of(runtime.database.persistent_store.events, [&](auto const& e) {
                        return e.event_id == forged_id;
                    }));
                }
            }
        }
    }
}

// FED-1, the legitimate side: an own-domain event genuinely signed with this
// server's key (a re-join, where the resident server echoes back events we
// authored) is still accepted. And an event that reaches us only through the
// auth chain is an outlier: stored for auth lookups, never current state.
SCENARIO("A send_join response's own-domain events are accepted when signed with our key, and auth-chain-only "
         "events never become current state",
         "[fed1][security][homeserver][federation][join][integration]")
{
    GIVEN("a resident server whose state holds a local user's membership signed with our key, and whose auth chain "
          "holds an event that is not in the state")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const alice = reg.value;
        auto const carol = std::string{"@carol:"} + local_server;

        auto const certificate = write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);
        runtime.test_forced_outbound_resolution[resident_server] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};
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

        auto const room_id = std::string{"!fed1legit:"} + resident_server;
        auto const creator = std::string{"@creator:"} + resident_server;
        auto const former = std::string{"@former:"} + resident_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");

        auto const make_join_event = std::string{R"({"type":"m.room.member","state_key":")"} + alice +
                                     R"(","room_id":")" + room_id + R"(","sender":")" + alice +
                                     R"(","depth":5,"origin_server_ts":1000,)"
                                     R"("prev_events":[],"auth_events":[],)"
                                     R"("content":{"membership":"join"}})";
        auto const make_join_body = std::string{R"({"room_version":"10","event":)"} + make_join_event + "}";
        auto const create_event = std::string{R"({"type":"m.room.create","state_key":"","sender":")"} + creator +
                                  R"(","room_id":")" + room_id +
                                  R"(","depth":1,"origin_server_ts":900,"prev_events":[],"auth_events":[],)"
                                  R"("content":{"room_version":"10","creator":")" +
                                  creator + R"("}})";
        auto const power_levels_event = std::string{R"({"type":"m.room.power_levels","state_key":"","sender":")"} +
                                        creator + R"(","room_id":")" + room_id +
                                        R"(","depth":2,"origin_server_ts":901,"prev_events":[],"auth_events":[],)"
                                        R"("content":{"users":{")" +
                                        creator + R"(":100}}})";
        auto const carol_member = std::string{R"({"type":"m.room.member","state_key":")"} + carol + R"(","room_id":")" +
                                  room_id + R"(","sender":")" + carol +
                                  R"(","depth":3,"origin_server_ts":902,"prev_events":[],"auth_events":[],)"
                                  R"("content":{"membership":"join"}})";
        auto const former_member = std::string{R"({"type":"m.room.member","state_key":")"} + former +
                                   R"(","room_id":")" + room_id + R"(","sender":")" + former +
                                   R"(","depth":2,"origin_server_ts":901,"prev_events":[],"auth_events":[],)"
                                   R"("content":{"membership":"join"}})";

        auto const carol_value = sign_with_local_server_key(runtime, carol_member, policy);
        auto const carol_event_id = reference_event_id(carol_value, policy);
        auto const former_value =
            sign_test_event(former_member, policy, resident_server, resident_key_id, resident_key_seed);
        auto const former_event_id = reference_event_id(former_value, policy);

        auto state_array = merovingian::canonicaljson::Array{};
        state_array.push_back(
            sign_test_event(create_event, policy, resident_server, resident_key_id, resident_key_seed));
        state_array.push_back(
            sign_test_event(power_levels_event, policy, resident_server, resident_key_id, resident_key_seed));
        state_array.push_back(carol_value);

        auto auth_chain_array = merovingian::canonicaljson::Array{};
        auth_chain_array.push_back(
            sign_test_event(create_event, policy, resident_server, resident_key_id, resident_key_seed));
        auth_chain_array.push_back(
            sign_test_event(power_levels_event, policy, resident_server, resident_key_id, resident_key_seed));
        auth_chain_array.push_back(former_value);

        auto const send_join_body = std::string{R"({"state":)"} + canonicaljson_array_to_string(state_array) +
                                    R"(,"auth_chain":)" + canonicaljson_array_to_string(auth_chain_array) + "}";
        auto const make_join_response = json_http_response("200 OK", make_join_body);
        auto const send_join_response = json_http_response("200 OK", send_join_body);

        WHEN("alice joins the room through the resident server")
        {
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_join_response, send_join_response,
                                    captured_requests);
            }};
            auto const result =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});
            server_thread.join();
            wait_for_join_background_tasks(runtime);
            auto const lock = std::lock_guard{runtime.mutex};
            auto const& store = runtime.database.persistent_store;

            THEN("the own-domain membership signed with our key is accepted into the room's state")
            {
                CAPTURE(result.reason);
                REQUIRE(result.ok);
                REQUIRE(std::ranges::any_of(store.state, [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == carol &&
                           s.event_id == carol_event_id;
                }));
                REQUIRE(std::ranges::any_of(store.memberships, [&](auto const& m) {
                    return m.room_id == room_id && m.user_id == carol && m.membership == "join";
                }));
            }

            THEN("the auth-chain-only event is stored as an outlier but is not current state")
            {
                REQUIRE(result.ok);
                auto const stored = std::ranges::find_if(store.events, [&](auto const& e) {
                    return e.event_id == former_event_id;
                });
                REQUIRE(stored != store.events.end());
                REQUIRE(stored->status == "outlier");
                REQUIRE_FALSE(std::ranges::any_of(store.state, [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == former;
                }));
                REQUIRE_FALSE(std::ranges::any_of(store.memberships, [&](auto const& m) {
                    return m.room_id == room_id && m.user_id == former;
                }));
            }
        }
    }
}

SCENARIO("leave_room signs remote membership templates with and without existing hashes",
         "[membership-template-hashes][homeserver][federation][integration]")
{
    GIVEN("a logged-in local user with a persisted remote membership and a TLS resident server")
    {
        REQUIRE(sodium_init() >= 0);
        auto const template_has_hashes = GENERATE(false, true);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const alice = reg.value;
        auto const room_id = std::string{"!leavehashes:"} + resident_server;
        {
            auto const lock = std::lock_guard{runtime.mutex};
            runtime.database.persistent_store.memberships.push_back({room_id, alice, "join", 1U});
        }

        auto const certificate = write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        runtime.test_forced_outbound_resolution[resident_server] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", acceptor.bound_port(), {"127.0.0.1"}, certificate.certificate_pem};

        auto const leave_event =
            std::string{R"({"type":"m.room.member","state_key":")"} + alice + R"(","room_id":")" + room_id +
            R"(","sender":")" + alice + R"(","depth":7,"origin_server_ts":1001,"prev_events":[],"auth_events":[],)" +
            (template_has_hashes ? R"("hashes":{"sha256":"stale"},)" : "") + R"("content":{"membership":"leave"}})";
        auto const make_leave_response =
            json_http_response("200 OK", std::string{R"({"room_version":"10","event":)"} + leave_event + "}");
        auto const send_response = json_http_response("200 OK", "{}");
        auto captured_requests = std::vector<std::string>{};

        WHEN("leave_room performs make_leave and send_leave against the resident server")
        {
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_leave_response, send_response,
                                    captured_requests);
            }};
            auto const result = merovingian::homeserver::leave_room(runtime, login.value, room_id);
            server_thread.join();

            THEN("the leave succeeds and the outbound event has one correct hash and a valid local signature")
            {
                CAPTURE(template_has_hashes, result.reason);
                REQUIRE(result.ok);
                REQUIRE(result.value == room_id);
                REQUIRE(captured_requests.size() == 2U);
                auto const leave = event_from_send_request(captured_requests[1]);
                auto const policy = *merovingian::rooms::find_room_version_policy("10");
                require_membership_event_integrity(runtime, leave, policy);
                REQUIRE(std::ranges::any_of(runtime.database.persistent_store.memberships, [&](auto const& member) {
                    return member.room_id == room_id && member.user_id == alice && member.membership == "leave";
                }));
            }
        }
    }
}
