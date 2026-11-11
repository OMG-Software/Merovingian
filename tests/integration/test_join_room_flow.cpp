// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"
//
// +-------------------------------------------------------------------------+
// |         LIVE FEDERATED join_room INTEGRATION TEST                       |
// |                                                                         |
// |  Spec: Server-Server API v1.19 — Joining Rooms                          |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#joining-rooms   |
// |                                                                         |
// |  Drives merovingian::homeserver::join_room() through a REAL make_join / |
// |  send_join round trip against a local TLS server, exercising send_join |
// |  signature verification and persistence of the whole returned state   |
// |  (ADR-0241) end to end. This closes the                                |
// |  codecov/patch coverage gap left by PR #341 (RoomService.cpp's        |
// |  post-send_join-success path had no integration coverage).             |
// |                                                                         |
// |  join_room always resolves its destination through                     |
// |  federation::discover_server(), which unconditionally rejects loopback |
// |  and private-range addresses (src/federation/Security.cpp              |
// |  ip_address_is_private_or_loopback) with no override, and production   |
// |  outbound calls never populate an in-memory CA bundle. This test uses  |
// |  HomeserverRuntime::test_forced_outbound_resolution (see HomeserverRuntime.hpp)  |
// |  to point the outbound call at the local server without weakening      |
// |  that policy for real traffic — the override is never set by any       |
// |  production construction path.                                        |
// +-------------------------------------------------------------------------+

#include "../FederationSigningTestSupport.hpp"
#include "../support/JoiningThreads.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TlsMockServer.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/core/SocketHandle.hpp"
#include "merovingian/crypto/Ed25519.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentProfile.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/EventId.hpp"
#include "merovingian/events/EventSigner.hpp"
#include "merovingian/federation/FederationRemoteRuntime.hpp"
#include "merovingian/federation/InboundIngestion.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/InviteRoomState.hpp"
#include "merovingian/federation/PduIngestionResult.hpp"
#include "merovingian/federation/PduIngestionStatus.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/RequestLockScope.hpp"
#include "merovingian/homeserver/RoomService.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/TestOnlyForcedOutboundResolution.hpp"
#include "merovingian/homeserver/Tls.hpp"
#include "merovingian/homeserver/TlsServerContext.hpp"
#include "merovingian/net/TcpAcceptor.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"
#include "merovingian/sync/DeviceListDelta.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <poll.h>
#include <sodium.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

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
                             request_bytes.find("/send_leave/") != std::string::npos ||
                             request_bytes.find("/send_knock/") != std::string::npos;
        if (is_send && before_send)
        {
            before_send(request_bytes);
        }
        std::ignore = connection.write(is_send ? send_join_response : make_join_response);
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

[[nodiscard]] auto object_member_count(merovingian::canonicaljson::Value const& value, std::string_view key)
    -> std::size_t
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
// `event` with its real hashes.sha256, replacing any it holds.
[[nodiscard]] auto with_content_hash(merovingian::canonicaljson::Value const& event)
    -> merovingian::canonicaljson::Value
{
    auto const hash = merovingian::events::make_content_hash(event);
    REQUIRE(hash.error.empty());
    auto object = std::get<merovingian::canonicaljson::Object>(event.storage());
    std::erase_if(object, [](merovingian::canonicaljson::ObjectMember const& member) {
        return member.key == "hashes";
    });
    auto hashes = merovingian::canonicaljson::Object{};
    hashes.push_back(merovingian::canonicaljson::make_member("sha256", merovingian::canonicaljson::Value{hash.sha256}));
    object.push_back(
        merovingian::canonicaljson::make_member("hashes", merovingian::canonicaljson::Value{std::move(hashes)}));
    return merovingian::canonicaljson::Value{std::move(object)};
}

[[nodiscard]] auto sign_test_event_with_secret(std::string const& raw_event_json,
                                               merovingian::rooms::RoomVersionPolicy const& policy,
                                               std::string const& claimed_server, std::string const& claimed_key_id,
                                               std::span<std::uint8_t const> secret_key)
    -> merovingian::canonicaljson::Value
{
    REQUIRE(secret_key.size() == crypto_sign_SECRETKEYBYTES);
    auto const parsed = merovingian::canonicaljson::parse_lossless(raw_event_json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    // An honest server's event carries its real content hash (F-45): the joining server redacts any other.
    auto const hashed = with_content_hash(parsed.value);
    auto const payload = merovingian::events::make_event_signing_payload(hashed, policy);
    REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
    auto sig = std::array<unsigned char, crypto_sign_BYTES>{};
    crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<unsigned char const*>(payload.output.data()),
                         payload.output.size(), secret_key.data());
    auto const sig_b64 =
        merovingian::events::matrix_base64_from_bytes({reinterpret_cast<char const*>(sig.data()), crypto_sign_BYTES});
    auto const attached =
        merovingian::events::attach_event_signature(hashed, {claimed_server, claimed_key_id}, sig_b64);
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
[[nodiscard]] auto sign_with_local_server_key(merovingian::homeserver::HomeserverRuntime& runtime,
                                              std::string const& raw_event_json,
                                              merovingian::rooms::RoomVersionPolicy const& policy)
    -> merovingian::canonicaljson::Value
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

// The start of an honest resident's public room: every event names the events that authorise it, so a joining
// server's receipt checks pass (F-45, ADR-0369).
struct ResidentRoomChain final
{
    merovingian::canonicaljson::Value create{};
    merovingian::canonicaljson::Value creator_join{};
    merovingian::canonicaljson::Value power_levels{};
    merovingian::canonicaljson::Value join_rules{};
    std::string create_id{};
    std::string creator_join_id{};
    std::string power_levels_id{};
    std::string join_rules_id{};

    [[nodiscard]] auto events() const -> merovingian::canonicaljson::Array
    {
        return {create, creator_join, power_levels, join_rules};
    }
    // What a member event for a user holding no membership names.
    [[nodiscard]] auto member_auth() const -> std::string
    {
        return "\"" + create_id + "\",\"" + power_levels_id + "\",\"" + join_rules_id + "\"";
    }
};

[[nodiscard]] auto resident_room_chain(std::string const& room_id, std::string const& creator,
                                       merovingian::rooms::RoomVersionPolicy const& policy) -> ResidentRoomChain
{
    auto const event = [&](std::string const& type, std::string const& state_key, std::string const& content, int depth,
                           std::string const& prev, std::string const& auth) {
        return sign_test_event(std::string{R"({"type":")"} + type + R"(","state_key":")" + state_key +
                                   R"(","sender":")" + creator + R"(","room_id":")" + room_id + R"(","depth":)" +
                                   std::to_string(depth) + R"(,"origin_server_ts":900,"prev_events":[)" + prev +
                                   R"(],"auth_events":[)" + auth + R"(],"content":)" + content + "}",
                               policy, resident_server, resident_key_id, resident_key_seed);
    };
    auto const quoted = [](std::string const& id) {
        return "\"" + id + "\"";
    };
    auto chain = ResidentRoomChain{};
    chain.create = event("m.room.create", "", R"({"room_version":"10","creator":")" + creator + "\"}", 1, "", "");
    chain.create_id = reference_event_id(chain.create, policy);
    chain.creator_join = event("m.room.member", creator, R"({"membership":"join"})", 2, quoted(chain.create_id),
                               quoted(chain.create_id));
    chain.creator_join_id = reference_event_id(chain.creator_join, policy);
    auto const creator_auth = quoted(chain.create_id) + "," + quoted(chain.creator_join_id);
    chain.power_levels = event("m.room.power_levels", "", R"({"users":{")" + creator + R"(":100}})", 3,
                               quoted(chain.creator_join_id), creator_auth);
    chain.power_levels_id = reference_event_id(chain.power_levels, policy);
    chain.join_rules = event("m.room.join_rules", "", R"({"join_rule":"public"})", 4, quoted(chain.power_levels_id),
                             creator_auth + "," + quoted(chain.power_levels_id));
    chain.join_rules_id = reference_event_id(chain.join_rules, policy);
    return chain;
}

// `raw_event_json`, built with an empty auth_events, naming `auth` instead.
[[nodiscard]] auto naming_auth_events(std::string raw_event_json, std::string const& auth) -> std::string
{
    auto const empty = std::string{R"("auth_events":[])"};
    auto const position = raw_event_json.find(empty);
    REQUIRE(position != std::string::npos);
    raw_event_json.replace(position, empty.size(), R"("auth_events":[)" + auth + "]");
    return raw_event_json;
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

// ADR-0241: a federated join verifies and persists every event of the send_join `state` array,
// other members' m.room.member events included, before it returns. The join event's after-state
// group is built from all of it, so an event from any member who was joined before us is judged
// against state that holds that member. With the earlier fast join, other members were filled in
// afterwards, never into the join's state group, and every event they sent next failed the auth
// rules as "sender is not joined to the room" (Complement F1).
SCENARIO("join_room completes a live federated join with every member of the returned state in the join's state",
         "[membership-template-hashes][homeserver][federation][join][join-full-state][integration]")
{
    GIVEN("a real HomeserverRuntime, a logged-in local user, and a real TLS resident server")
    {
        REQUIRE(sodium_init() >= 0);
        auto const template_has_hashes = GENERATE(false, true);
        auto const profile_mode = GENERATE(as<std::string>{}, "absent", "empty", "display-only", "avatar-only");
        // Declared before `started`/`runtime` so it outlives them: join_room
        // writes through runtime.test_room_changed_log when it notifies the
        // federation worker.
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
        if (profile_mode != "absent")
        {
            auto profile = merovingian::database::PersistentProfile{alice, {}, {}};
            if (profile_mode == "display-only")
            {
                profile.displayname = "Alice Local";
            }
            else if (profile_mode == "avatar-only")
            {
                profile.avatar_url = "mxc://example.org/alice-local";
            }
            REQUIRE(merovingian::database::store_profile(runtime.database.persistent_store, std::move(profile)));
        }

        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
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
        auto const room_chain = resident_room_chain(room_id, creator, policy);
        auto const make_join_event =
            naming_auth_events(std::string{R"({"type":"m.room.member","state_key":")"} + alice + R"(","room_id":")" +
                                   room_id + R"(","sender":")" + alice +
                                   R"(","depth":6,"origin_server_ts":1000,)"
                                   R"("prev_events":[],"auth_events":[],)" +
                                   (template_has_hashes ? R"("hashes":{"sha256":"stale"},)" : "") +
                                   R"("content":{"membership":"join","displayname":"Resident Supplied",)"
                                   R"("avatar_url":"mxc://resident.example.org/forged"}})",
                               room_chain.member_auth());
        auto const make_join_body = std::string{R"({"room_version":"10","event":)"} + make_join_event + "}";

        // --- send_join response: create, power_levels and our own membership,
        // plus five OTHER members' m.room.member events, all signed by the
        // resident server. ---

        auto state_array = room_chain.events();
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
            auto const member_event =
                naming_auth_events(std::string{R"({"type":"m.room.member","state_key":")"} + member_id +
                                       R"(","room_id":")" + room_id + R"(","sender":")" + member_id +
                                       R"(","depth":3,"origin_server_ts":902,)"
                                       R"("prev_events":[],"auth_events":[],)"
                                       R"("content":{"membership":"join"}})",
                                   room_chain.member_auth());
            state_array.push_back(
                sign_test_event(member_event, policy, resident_server, resident_key_id, resident_key_seed));
        }

        auto auth_chain_array = room_chain.events();

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

            THEN("the join succeeds with the room's state persisted")
            {
                CAPTURE(template_has_hashes, profile_mode, result.reason);
                REQUIRE(result.ok);
                REQUIRE(result.status == 200U);
                REQUIRE(result.value == room_id);
                REQUIRE(captured_requests.size() == 2U);
                auto const join_event = event_from_send_request(captured_requests[1]);
                require_membership_event_integrity(runtime, join_event, policy);
                auto const* join_object = std::get_if<merovingian::canonicaljson::Object>(&join_event.storage());
                REQUIRE(join_object != nullptr);
                auto const* join_content_value = merovingian::tests::object_member(*join_object, "content");
                REQUIRE(join_content_value != nullptr);
                auto const* join_content =
                    std::get_if<merovingian::canonicaljson::Object>(&join_content_value->storage());
                REQUIRE(join_content != nullptr);
                // The resident template supplies join membership. It must remain in the locally signed event.
                auto const* membership = merovingian::tests::string_member(*join_content, "membership");
                REQUIRE(membership != nullptr);
                REQUIRE(*membership == "join");
                // Local profile fields replace resident values independently. Missing or empty local fields
                // must not inherit a value supplied by the resident server.
                auto const* displayname = merovingian::tests::string_member(*join_content, "displayname");
                if (profile_mode == "display-only")
                {
                    REQUIRE(displayname != nullptr);
                    REQUIRE(*displayname == "Alice Local");
                }
                else
                {
                    REQUIRE(displayname == nullptr);
                }
                auto const* avatar_url = merovingian::tests::string_member(*join_content, "avatar_url");
                if (profile_mode == "avatar-only")
                {
                    REQUIRE(avatar_url != nullptr);
                    REQUIRE(*avatar_url == "mxc://example.org/alice-local");
                }
                else
                {
                    REQUIRE(avatar_url == nullptr);
                }

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

            THEN("every other member is joined, and in the join event's state, as soon as join_room returns")
            {
                CAPTURE(template_has_hashes, profile_mode, result.reason);
                REQUIRE(result.ok);
                auto const lock = std::lock_guard{runtime.mutex};
                auto const& store = runtime.database.persistent_store;

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

                for (auto member_index = std::size_t{0U}; member_index < k_other_member_count; ++member_index)
                {
                    auto const member_id = "@member" + std::to_string(member_index) + ":" + resident_server;
                    CAPTURE(member_id);
                    REQUIRE(std::ranges::any_of(store.memberships, [&](auto const& m) {
                        return m.room_id == room_id && m.user_id == member_id && m.membership == "join";
                    }));
                    REQUIRE(std::ranges::any_of(*full, [&](auto const& e) {
                        return e.event_type == "m.room.member" && e.state_key == member_id;
                    }));
                }

                auto const room_it = std::ranges::find_if(runtime.database.rooms, [&](auto const& r) {
                    return r.room_id == room_id;
                });
                REQUIRE(room_it != runtime.database.rooms.end());
                // alice, the creator and the five members the resident returned.
                REQUIRE(room_it->members.size() == k_other_member_count + 2U);

                // The federation worker is told about this room, and no other.
                REQUIRE_FALSE(changed_rooms.empty());
                REQUIRE(std::ranges::all_of(changed_rooms, [&](auto const& logged_room_id) {
                    return logged_room_id == room_id;
                }));

                AND_THEN("a message from one of those members, after the join, is accepted")
                {
                    auto const sender = "@member0:" + std::string{resident_server};
                    auto const state_event_id = [&](std::string_view type, std::string_view state_key) {
                        auto const entry = std::ranges::find_if(*full, [&](auto const& e) {
                            return e.event_type == type && e.state_key == state_key;
                        });
                        REQUIRE(entry != full->end());
                        return entry->event_id;
                    };
                    auto auth_event_ids = std::vector<std::string>{state_event_id("m.room.create", ""),
                                                                   state_event_id("m.room.power_levels", ""),
                                                                   state_event_id("m.room.member", sender)};

                    auto content = merovingian::canonicaljson::Object{};
                    content.push_back(merovingian::canonicaljson::make_member(
                        "body", merovingian::canonicaljson::Value{std::string{"hello from a resident member"}}));
                    content.push_back(merovingian::canonicaljson::make_member(
                        "msgtype", merovingian::canonicaljson::Value{std::string{"m.text"}}));
                    auto obj = merovingian::canonicaljson::Object{};
                    obj.push_back(merovingian::canonicaljson::make_member(
                        "type", merovingian::canonicaljson::Value{std::string{"m.room.message"}}));
                    obj.push_back(
                        merovingian::canonicaljson::make_member("room_id", merovingian::canonicaljson::Value{room_id}));
                    obj.push_back(
                        merovingian::canonicaljson::make_member("sender", merovingian::canonicaljson::Value{sender}));
                    obj.push_back(
                        merovingian::canonicaljson::make_member("content", merovingian::canonicaljson::Value{content}));
                    obj.push_back(merovingian::canonicaljson::make_member(
                        "origin_server_ts", merovingian::canonicaljson::Value{std::int64_t{2000}}));
                    obj.push_back(merovingian::canonicaljson::make_member(
                        "depth", merovingian::canonicaljson::Value{std::int64_t{7}}));
                    auto prev_arr = merovingian::canonicaljson::Array{};
                    prev_arr.push_back(merovingian::canonicaljson::Value{join_event_id});
                    obj.push_back(merovingian::canonicaljson::make_member(
                        "prev_events", merovingian::canonicaljson::Value{std::move(prev_arr)}));
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
                    auto const unsigned_json = merovingian::canonicaljson::serialize_canonical(
                        merovingian::canonicaljson::Value{std::move(obj)});
                    REQUIRE(unsigned_json.error == merovingian::canonicaljson::CanonicalJsonError::none);
                    auto const signed_json = merovingian::canonicaljson::serialize_canonical(sign_test_event(
                        unsigned_json.output, policy, resident_server, resident_key_id, resident_key_seed));
                    REQUIRE(signed_json.error == merovingian::canonicaljson::CanonicalJsonError::none);

                    auto envelope = merovingian::federation::InboundPduEnvelope{};
                    envelope.event_id = "$member_after_join:" + std::string{resident_server};
                    envelope.room_id = room_id;
                    envelope.room_version = "10";
                    envelope.sender = sender;
                    envelope.event_type = "m.room.message";
                    envelope.origin_server_ts = 2000;
                    envelope.depth = 7U;
                    envelope.prev_event_ids = {join_event_id};
                    envelope.auth_event_ids = std::move(auth_event_ids);
                    envelope.json = signed_json.output;

                    auto const ingest_result = merovingian::homeserver::ingest_pdu_event(runtime, envelope);
                    CAPTURE(ingest_result.reason);
                    REQUIRE(ingest_result.status == merovingian::federation::PduIngestionStatus::accepted);
                }
            }

            // Spec: Client-Server API v1.19, "Tracking the device list for a user" and the /sync
            // `DeviceLists` table: `changed` lists the users "who now share an encrypted room with the
            // client". The joiner's server learns the whole roster at once, so every member is listed;
            // the joiner's own ID is listed too, which the spec permits ("a server may add Alice to
            // `changed` when Alice and Bob share a new room") and which tells their other devices to
            // refresh the account's device list (Complement TestDeviceListsUpdateOverFederation).
            THEN("the joiner's client is told to refresh every member's devices, its own included")
            {
                CAPTURE(template_has_hashes, profile_mode, result.reason);
                REQUIRE(result.ok);
                auto const lock = std::lock_guard{runtime.mutex};
                auto const delta =
                    merovingian::sync::collect_device_list_delta(runtime.database.persistent_store, alice, 0U);
                REQUIRE(std::ranges::find(delta.changed, alice) != delta.changed.end());
                for (auto member_index = std::size_t{0U}; member_index < k_other_member_count; ++member_index)
                {
                    auto const member_id = "@member" + std::to_string(member_index) + ":" + resident_server;
                    CAPTURE(member_id);
                    REQUIRE(std::ranges::find(delta.changed, member_id) != delta.changed.end());
                }
                REQUIRE(delta.left.empty());
            }
        }
    }
}

// Spec: Client-Server API v1.19, POST /_matrix/client/v3/join/{roomIdOrAlias}, 403: "You do
// not have permission to join the room ... The room is invite-only and the user was not
// invited". When the resident server refuses the join (make_join or send_join answered 403),
// that is the answer the client gets; it was a 502 (Complement TestKnocking, "Attempting to
// join a room with join rule 'knock' without an invite should fail").
SCENARIO("join_room answers 403 when the resident server refuses the join",
         "[homeserver][federation][join][join-refused][integration]")
{
    GIVEN("a real HomeserverRuntime, a logged-in local user, and a resident server that refuses the join")
    {
        REQUIRE(sodium_init() >= 0);
        auto const refused_step = GENERATE(as<std::string>{}, "make_join", "send_join");
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const alice = reg.value;

        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
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

        auto const room_id = std::string{"!knockroom:"} + resident_server;
        auto const make_join_event = std::string{R"({"type":"m.room.member","state_key":")"} + alice +
                                     R"(","room_id":")" + room_id + R"(","sender":")" + alice +
                                     R"(","depth":3,"origin_server_ts":1000,)"
                                     R"("prev_events":[],"auth_events":[],)"
                                     R"("content":{"membership":"join"}})";
        auto const refusal =
            json_http_response("403 Forbidden", R"({"errcode":"M_FORBIDDEN","error":"You are not invited"})");
        auto const make_join_response =
            refused_step == "make_join"
                ? refusal
                : json_http_response("200 OK", std::string{R"({"room_version":"10","event":)"} + make_join_event + "}");

        WHEN("join_room is called with that server as the only via")
        {
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_join_response, refusal, captured_requests);
            }};
            auto const result =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});
            server_thread.join();

            THEN("the join fails with 403, and the user is not joined")
            {
                CAPTURE(refused_step, result.reason);
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 403U);
                auto const lock = std::lock_guard{runtime.mutex};
                REQUIRE_FALSE(std::ranges::any_of(runtime.database.persistent_store.memberships, [&](auto const& m) {
                    return m.room_id == room_id && m.user_id == alice && m.membership == "join";
                }));
            }
        }
    }
}

// Spec: Client-Server API v1.19, POST /_matrix/client/v3/knock/{roomIdOrAlias}; Server-Server
// API v1.19, "Knocking upon a room" (make_knock, send_knock, knock_room_state); /sync
// rooms.knock knock_state. A knock on a room this server is not in goes to the server the
// client names (ADR-0242, ADR-0243): `server_name` as well as `via`, the body's `reason` on the
// event, and the resident's signed knock_room_state kept for the user's /sync, without any
// entry whose signature does not check out ("SHOULD be removed"). Complement TestKnocking.
// Release-gate audit, knock_room_state: what is kept from a resident's answer is bounded as an invite's room state is
// (ADR-0620). Spec (Server-Server API, PUT /send_knock): "Entries which are improperly signed or formatted SHOULD be
// removed", so a bad list costs the list, not the knock the resident accepted.
SCENARIO("What a knock keeps of a resident's knock_room_state is bounded in count and bytes",
         "[homeserver][federation][knock][knock-bounds][security][gate-m-sync]")
{
    GIVEN("a logged-in local user and a resident server hosting a knock room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto& runtime = rt.homeserver;
        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const alice = reg.value;

        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
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

        auto const room_id = std::string{"!knockable:elsewhere.example.org"};
        auto const creator = std::string{"@creator:"} + resident_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto const signed_state = [&](std::string const& type, std::string const& state_key, std::string const& content,
                                      int depth) {
            return sign_test_event(
                std::string{R"({"type":")"} + type + R"(","state_key":")" + state_key + R"(","sender":")" + creator +
                    R"(","room_id":")" + room_id + R"(","depth":)" + std::to_string(depth) +
                    R"(,"origin_server_ts":900,"prev_events":[],"auth_events":[],"content":)" + content + "}",
                policy, resident_server, resident_key_id, resident_key_seed);
        };
        auto const make_knock_response = json_http_response(
            "200 OK", std::string{R"({"room_version":"10","event":{"type":"m.room.member","state_key":")"} + alice +
                          R"(","room_id":")" + room_id + R"(","sender":")" + alice +
                          R"(","depth":5,"origin_server_ts":1000,"prev_events":[],"auth_events":[],)"
                          R"("content":{"membership":"knock"}}})");
        auto const knock_answering = [&](std::string const& send_knock_response) {
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_knock_response, send_knock_response,
                                    captured_requests);
            }};
            auto const knocked = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST",
                 "/_matrix/client/v3/knock/%21knockable%3Aelsewhere.example.org?server_name=" +
                     std::string{resident_server},
                 login.value, "{}"},
                /*can_wait=*/false);
            server_thread.join();
            return knocked.response;
        };
        auto const record = [&]() {
            return merovingian::database::find_invite(runtime.database.persistent_store, room_id, alice);
        };
        auto const answer_with = [](merovingian::canonicaljson::Array const& list) {
            return json_http_response("200 OK", std::string{R"({"knock_room_state":)"} +
                                                    canonicaljson_array_to_string(list) + "}");
        };

        WHEN("the resident answers with the summary a real room has, and a type /sync would never show")
        {
            auto list = merovingian::canonicaljson::Array{};
            list.push_back(signed_state("m.room.create", "", R"({"room_version":"10","creator":"@c:d"})", 1));
            list.push_back(signed_state("m.room.join_rules", "", R"({"join_rule":"knock"})", 2));
            list.push_back(signed_state("m.room.name", "", R"({"name":"Knock Here"})", 3));
            list.push_back(signed_state("m.room.power_levels", "", R"({"users_default":0})", 4));
            list.push_back(signed_state("m.room.member", "@someone:else.example", R"({"membership":"join"})", 5));
            auto const response = knock_answering(answer_with(list));

            THEN("the knock stands and exactly the entries /sync shows are kept")
            {
                CAPTURE(response.body);
                REQUIRE(response.status == 200U);
                auto const kept = record();
                REQUIRE(kept.has_value());
                REQUIRE(kept->invite_state_events_json.size() == 3U);
            }
        }

        WHEN("the resident answers with exactly as many summary entries as an invite may carry")
        {
            auto list = merovingian::canonicaljson::Array{};
            for (auto entry = std::size_t{0U}; entry < merovingian::federation::max_invite_room_state_entries; ++entry)
            {
                list.push_back(signed_state("m.room.name", "", R"({"name":"n"})", static_cast<int>(entry) + 1));
            }
            auto const response = knock_answering(answer_with(list));

            THEN("they are kept")
            {
                CAPTURE(response.body);
                REQUIRE(response.status == 200U);
                REQUIRE(record()->invite_state_events_json.size() ==
                        merovingian::federation::max_invite_room_state_entries);
            }
        }

        WHEN("the resident answers with one summary entry more than an invite may carry")
        {
            auto list = merovingian::canonicaljson::Array{};
            for (auto entry = std::size_t{0U}; entry <= merovingian::federation::max_invite_room_state_entries; ++entry)
            {
                list.push_back(signed_state("m.room.name", "", R"({"name":"n"})", static_cast<int>(entry) + 1));
            }
            auto const response = knock_answering(answer_with(list));

            THEN("the knock stands and the whole list is dropped")
            {
                CAPTURE(response.body);
                REQUIRE(response.status == 200U);
                auto const kept = record();
                REQUIRE(kept.has_value());
                REQUIRE(kept->invite_state_events_json.empty());
            }
        }

        WHEN("the resident's answer is larger than an invite's body may be")
        {
            auto const padding = std::string(1048576U + 1024U, 'x');
            auto const response =
                knock_answering(json_http_response("200 OK", R"({"knock_room_state":[],"pad":")" + padding + R"("})"));

            THEN("the answer is not read whole and no knock is recorded")
            {
                CAPTURE(response.status);
                REQUIRE(response.status == 502U);
                REQUIRE_FALSE(record().has_value());
            }
        }

        WHEN("the user already holds as many knocks as allowed")
        {
            runtime.database.persistent_store.max_remote_knocks_per_user = 1U;
            auto held = merovingian::database::PersistentInvite{
                "!held:elsewhere.example.org", alice, alice, "$held", "{}", {}, 1U, resident_server};
            REQUIRE(merovingian::database::store_membership_projection(runtime.database.persistent_store,
                                                                       "!held:elsewhere.example.org",
                                                                       {alice, "knock", 1U, std::move(held)}));
            auto const knocked = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST",
                 "/_matrix/client/v3/knock/%21knockable%3Aelsewhere.example.org?server_name=" +
                     std::string{resident_server},
                 login.value, "{}"},
                /*can_wait=*/false);

            THEN("it is refused before any exchange, with nothing recorded")
            {
                CAPTURE(knocked.response.body);
                REQUIRE(knocked.response.status == 403U);
                REQUIRE(knocked.response.body.find("M_FORBIDDEN") != std::string::npos);
                REQUIRE_FALSE(record().has_value());
            }
        }
    }
}

SCENARIO("A knock on a room on another server goes through make_knock and send_knock",
         "[homeserver][federation][knock][knock-remote][integration]")
{
    GIVEN("a client API runtime, a logged-in local user, and a resident server hosting a knock room")
    {
        REQUIRE(sodium_init() >= 0);
        auto const refuse = GENERATE(false, true);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto& runtime = rt.homeserver;
        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const alice = reg.value;

        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
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

        // The room ID names a server other than the resident the client routes through, so
        // the knock, and its retraction, must go where the client sent it (ADR-0242).
        auto const room_id = std::string{"!knockable:elsewhere.example.org"};
        auto const creator = std::string{"@creator:"} + resident_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto const state_event = [&](std::string const& type, std::string const& content, int depth) {
            return std::string{R"({"type":")"} + type + R"(","state_key":"","sender":")" + creator +
                   R"(","room_id":")" + room_id + R"(","depth":)" + std::to_string(depth) +
                   R"(,"origin_server_ts":900,"prev_events":[],"auth_events":[],"content":)" + content + "}";
        };
        auto knock_state = merovingian::canonicaljson::Array{};
        knock_state.push_back(sign_test_event(
            state_event("m.room.create", std::string{R"({"room_version":"10","creator":")"} + creator + R"("})", 1),
            policy, resident_server, resident_key_id, resident_key_seed));
        knock_state.push_back(sign_test_event(state_event("m.room.join_rules", R"({"join_rule":"knock"})", 2), policy,
                                              resident_server, resident_key_id, resident_key_seed));
        knock_state.push_back(sign_test_event(state_event("m.room.name", R"({"name":"Knock Here"})", 3), policy,
                                              resident_server, resident_key_id, resident_key_seed));
        // Forged: no signature at all.
        auto const forged = merovingian::canonicaljson::parse_lossless(
            state_event("m.room.topic", R"({"topic":"forged by a middlebox"})", 4));
        REQUIRE(forged.error == merovingian::canonicaljson::ParseError::none);
        knock_state.push_back(forged.value);

        auto const make_knock_event = std::string{R"({"type":"m.room.member","state_key":")"} + alice +
                                      R"(","room_id":")" + room_id + R"(","sender":")" + alice +
                                      R"(","depth":5,"origin_server_ts":1000,)"
                                      R"("prev_events":[],"auth_events":[],)"
                                      R"("content":{"membership":"knock"}})";
        auto const refusal =
            json_http_response("403 Forbidden", R"({"errcode":"M_FORBIDDEN","error":"You cannot knock here"})");
        auto const make_knock_response =
            refuse ? refusal
                   : json_http_response("200 OK",
                                        std::string{R"({"room_version":"10","event":)"} + make_knock_event + "}");
        auto const send_knock_response = json_http_response(
            "200 OK", std::string{R"({"knock_room_state":)"} + canonicaljson_array_to_string(knock_state) + "}");

        // A /leave for the same room while the knock's exchange is in flight would find no
        // membership, answer 200, and be overwritten when the accepted knock commits: it is
        // refused instead, and the knock stands.
        if (!refuse)
        {
            WHEN("the user leaves while the resident is answering the knock")
            {
                auto captured_requests = std::vector<std::string>{};
                auto leave_status = 0;
                auto server_thread = std::thread{[&]() {
                    run_resident_server(acceptor, *tls_context.context, make_knock_response, send_knock_response,
                                        captured_requests, [&](std::string const& request) {
                                            if (request.find("/send_knock/") == std::string::npos)
                                            {
                                                return;
                                            }
                                            leave_status = merovingian::homeserver::handle_client_server_request(
                                                               rt,
                                                               {"POST",
                                                                "/_matrix/client/v3/rooms/"
                                                                "%21knockable%3Aelsewhere.example.org/leave",
                                                                login.value, "{}"},
                                                               /*can_wait=*/false)
                                                               .response.status;
                                        });
                }};
                auto const knocked = merovingian::homeserver::handle_client_server_request(
                    rt,
                    {"POST",
                     "/_matrix/client/v3/knock/%21knockable%3Aelsewhere.example.org?server_name=" +
                         std::string{resident_server},
                     login.value, "{}"},
                    /*can_wait=*/false);
                server_thread.join();

                THEN("the leave is refused with 429 and the knock stands")
                {
                    CAPTURE(knocked.response.body);
                    REQUIRE(knocked.response.status == 200);
                    REQUIRE(leave_status == 429);
                    auto const lock = std::lock_guard{runtime.mutex};
                    REQUIRE(std::ranges::any_of(runtime.database.persistent_store.memberships, [&](auto const& m) {
                        return m.room_id == room_id && m.user_id == alice && m.membership == "knock";
                    }));
                }
            }
        }

        WHEN("the user knocks through POST /knock naming the resident with server_name, with a reason")
        {
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_knock_response, send_knock_response,
                                    captured_requests);
            }};
            auto const knocked = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST",
                 "/_matrix/client/v3/knock/%21knockable%3Aelsewhere.example.org?server_name=" +
                     std::string{resident_server},
                 login.value, R"({"reason":"let me in"})"},
                /*can_wait=*/false);
            server_thread.join();

            if (refuse)
            {
                THEN("a resident's refusal is a 403, and the user has no knock")
                {
                    CAPTURE(knocked.response.body);
                    REQUIRE(knocked.response.status == 403);
                    auto const lock = std::lock_guard{runtime.mutex};
                    REQUIRE_FALSE(
                        std::ranges::any_of(runtime.database.persistent_store.memberships, [&](auto const& m) {
                            return m.room_id == room_id && m.user_id == alice;
                        }));
                }
            }
            else
            {
                THEN("the knock is signed by this server, carries the reason, and the user has knocked")
                {
                    CAPTURE(knocked.response.body);
                    REQUIRE(knocked.response.status == 200);
                    REQUIRE(captured_requests.size() == 2U);
                    REQUIRE(captured_requests[0].find("/_matrix/federation/v1/make_knock/") != std::string::npos);
                    REQUIRE(captured_requests[0].find("ver=10") != std::string::npos);
                    REQUIRE(captured_requests[1].find("/_matrix/federation/v1/send_knock/") != std::string::npos);
                    auto const knock_event = event_from_send_request(captured_requests[1]);
                    require_membership_event_integrity(runtime, knock_event, policy);
                    auto const& knock_object = std::get<merovingian::canonicaljson::Object>(knock_event.storage());
                    auto const* content = merovingian::tests::object_member_as_object(knock_object, "content");
                    REQUIRE(content != nullptr);
                    REQUIRE(*merovingian::tests::string_member(*content, "membership") == "knock");
                    REQUIRE(*merovingian::tests::string_member(*content, "reason") == "let me in");
                    REQUIRE(*merovingian::tests::string_member(knock_object, "origin") == "example.org");

                    auto const lock = std::lock_guard{runtime.mutex};
                    REQUIRE(std::ranges::any_of(runtime.database.persistent_store.memberships, [&](auto const& m) {
                        return m.room_id == room_id && m.user_id == alice && m.membership == "knock";
                    }));
                }

                THEN("the user's /sync shows the room under knock with the resident's signed stripped state")
                {
                    auto const synced = merovingian::homeserver::handle_client_server_request(
                        rt, {"GET", "/_matrix/client/v3/sync", login.value, {}}, /*can_wait=*/false);
                    REQUIRE(synced.response.status == 200);
                    auto const body = merovingian::tests::parse_object(synced.response.body);
                    auto const* rooms = merovingian::tests::object_member_as_object(body, "rooms");
                    REQUIRE(rooms != nullptr);
                    auto const* knock = merovingian::tests::object_member_as_object(*rooms, "knock");
                    REQUIRE(knock != nullptr);
                    auto const* room = merovingian::tests::object_member_as_object(*knock, room_id);
                    REQUIRE(room != nullptr);
                    auto const* state = merovingian::tests::object_member_as_object(*room, "knock_state");
                    REQUIRE(state != nullptr);
                    auto const* events_value = merovingian::tests::object_member(*state, "events");
                    REQUIRE(events_value != nullptr);
                    auto const& events = std::get<merovingian::canonicaljson::Array>(events_value->storage());
                    auto const has = [&](std::string_view type, std::string_view key, std::string_view value) {
                        return std::ranges::any_of(events, [&](merovingian::canonicaljson::Value const& entry) {
                            auto const& event = std::get<merovingian::canonicaljson::Object>(entry.storage());
                            auto const* event_type = merovingian::tests::string_member(event, "type");
                            auto const* event_content = merovingian::tests::object_member_as_object(event, "content");
                            auto const* field = event_content == nullptr
                                                    ? nullptr
                                                    : merovingian::tests::string_member(*event_content, key);
                            return event_type != nullptr && *event_type == type && field != nullptr && *field == value;
                        });
                    };
                    REQUIRE(has("m.room.member", "membership", "knock"));
                    REQUIRE(has("m.room.name", "name", "Knock Here"));
                    REQUIRE(has("m.room.join_rules", "join_rule", "knock"));
                    // Spec: improperly signed entries "SHOULD be removed by the server".
                    REQUIRE_FALSE(has("m.room.topic", "topic", "forged by a middlebox"));
                }

                // Spec: Client-Server API v1.19, "Leaving rooms": leaving "can retract a knock";
                // Server-Server API v1.19, "Knocking upon a room": servers retract knocks over
                // federation by leaving the room, as for rejecting invites (make_leave, send_leave).
                WHEN("the user then retracts the knock with POST /leave")
                {
                    auto const make_leave_event = std::string{R"({"type":"m.room.member","state_key":")"} + alice +
                                                  R"(","room_id":")" + room_id + R"(","sender":")" + alice +
                                                  R"(","depth":6,"origin_server_ts":1100,)"
                                                  R"("prev_events":[],"auth_events":[],)"
                                                  R"("content":{"membership":"leave"}})";
                    auto const make_leave_response = json_http_response(
                        "200 OK", std::string{R"({"room_version":"10","event":)"} + make_leave_event + "}");
                    auto const send_leave_response = json_http_response("200 OK", "{}");
                    auto leave_requests = std::vector<std::string>{};
                    auto leave_thread = std::thread{[&]() {
                        run_resident_server(acceptor, *tls_context.context, make_leave_response, send_leave_response,
                                            leave_requests);
                    }};
                    auto const left = merovingian::homeserver::handle_client_server_request(
                        rt,
                        {"POST", "/_matrix/client/v3/rooms/%21knockable%3Aelsewhere.example.org/leave", login.value,
                         "{}"},
                        /*can_wait=*/false);
                    leave_thread.join();

                    THEN("the leave goes to the resident, and the user no longer has a knock")
                    {
                        CAPTURE(left.response.body);
                        REQUIRE(knocked.response.status == 200);
                        REQUIRE(left.response.status == 200);
                        REQUIRE(leave_requests.size() == 2U);
                        REQUIRE(leave_requests[0].find("/_matrix/federation/v1/make_leave/") != std::string::npos);
                        REQUIRE(leave_requests[1].find("/_matrix/federation/v2/send_leave/") != std::string::npos);
                        auto const lock = std::lock_guard{runtime.mutex};
                        REQUIRE(std::ranges::any_of(runtime.database.persistent_store.memberships, [&](auto const& m) {
                            return m.room_id == room_id && m.user_id == alice && m.membership == "leave";
                        }));
                        REQUIRE_FALSE(
                            std::ranges::any_of(runtime.database.persistent_store.invites, [&](auto const& i) {
                                return i.room_id == room_id && i.user_id == alice;
                            }));
                    }
                }
            }
        }
    }
}

// Spec: Client-Server API v1.19, GET /sync: a joined room's `state` is "all state up to the start
// of the timeline". When the timeline starts at a federated join, that is the state before the
// join, where the user is invited. The join's own state group holds the state after it, and its
// prev_events (the invite, kept only as an outlier) have none, so the state before is rebuilt
// from the after-state with the join's key taken back to the value the join replaced: the
// member event its auth_events name for the user (Server-Server API v1.19, "Auth events
// selection": "The current m.room.member event for the target's state_key, if any"). Review of
// #541.
SCENARIO("An initial sync whose timeline starts at a federated join shows the invite it replaced",
         "[homeserver][federation][join][sync][integration][join-sync-state]")
{
    GIVEN("a local user invited to a remote room, joining it through the resident")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto& runtime = rt.homeserver;
        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const alice = reg.value;

        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
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

        // The resident's invite-only room, built as a chain: create, the creator's join, power
        // levels, join rules, then alice's invite. Each event names the one before as its
        // prev_event and the events that authorise it as auth_events, signed by the resident.
        auto const room_id = std::string{"!invited:"} + resident_server;
        auto const creator = std::string{"@creator:"} + resident_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto const event = [&](std::string const& type, std::string const& state_key, std::string const& sender,
                               std::string const& content, int depth, std::string const& prev,
                               std::string const& auth) {
            return sign_test_event(std::string{R"({"type":")"} + type + R"(","state_key":")" + state_key +
                                       R"(","sender":")" + sender + R"(","room_id":")" + room_id + R"(","depth":)" +
                                       std::to_string(depth) + R"(,"origin_server_ts":900,"prev_events":[)" + prev +
                                       R"(],"auth_events":[)" + auth + R"(],"content":)" + content + "}",
                                   policy, resident_server, resident_key_id, resident_key_seed);
        };
        auto const quoted = [](std::string const& id) {
            return "\"" + id + "\"";
        };
        auto const create =
            event("m.room.create", "", creator, R"({"room_version":"10","creator":")" + creator + "\"}", 1, "", "");
        auto const create_id = reference_event_id(create, policy);
        auto const creator_join = event("m.room.member", creator, creator, R"({"membership":"join"})", 2,
                                        quoted(create_id), quoted(create_id));
        auto const creator_join_id = reference_event_id(creator_join, policy);
        auto const power_levels = event("m.room.power_levels", "", creator, R"({"users":{")" + creator + R"(":100}})",
                                        3, quoted(creator_join_id), quoted(create_id) + "," + quoted(creator_join_id));
        auto const power_levels_id = reference_event_id(power_levels, policy);
        auto const join_rules =
            event("m.room.join_rules", "", creator, R"({"join_rule":"invite"})", 4, quoted(power_levels_id),
                  quoted(create_id) + "," + quoted(creator_join_id) + "," + quoted(power_levels_id));
        auto const join_rules_id = reference_event_id(join_rules, policy);
        auto const invite =
            event("m.room.member", alice, creator, R"({"membership":"invite"})", 5, quoted(join_rules_id),
                  quoted(create_id) + "," + quoted(creator_join_id) + "," + quoted(power_levels_id) + "," +
                      quoted(join_rules_id));
        auto const invite_id = reference_event_id(invite, policy);

        // send_join returns that whole chain as the state before the join, and as its auth chain.
        auto state_array = merovingian::canonicaljson::Array{create, creator_join, power_levels, join_rules, invite};
        auto const send_join_body = std::string{R"({"state":)"} + canonicaljson_array_to_string(state_array) +
                                    R"(,"auth_chain":)" + canonicaljson_array_to_string(state_array) + "}";
        // The template follows the invite, and its auth_events name the invite as alice's
        // current membership, as a resident's must.
        auto const make_join_event =
            std::string{R"({"type":"m.room.member","state_key":")"} + alice + R"(","room_id":")" + room_id +
            R"(","sender":")" + alice + R"(","depth":6,"origin_server_ts":1000,"prev_events":[)" + quoted(invite_id) +
            R"(],"auth_events":[)" + quoted(create_id) + "," + quoted(power_levels_id) + "," + quoted(join_rules_id) +
            "," + quoted(invite_id) + R"(],"content":{"membership":"join"}})";
        auto const make_join_response =
            json_http_response("200 OK", std::string{R"({"room_version":"10","event":)"} + make_join_event + "}");
        auto const send_join_response = json_http_response("200 OK", send_join_body);

        WHEN("the user joins and then makes an initial sync whose timeline is the join alone")
        {
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_join_response, send_join_response,
                                    captured_requests);
            }};
            auto const joined =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});
            server_thread.join();
            REQUIRE(joined.ok);
            // {"room":{"timeline":{"limit":1}}}
            auto const synced = merovingian::homeserver::handle_client_server_request(
                rt,
                {"GET",
                 "/_matrix/client/v3/sync?filter=%7B%22room%22%3A%7B%22timeline%22%3A%7B%22limit%22%3A1%7D%7D%7D",
                 login.value,
                 {}},
                /*can_wait=*/false);
            REQUIRE(synced.response.status == 200);
            auto const body = merovingian::tests::parse_object(synced.response.body);
            auto const* rooms = merovingian::tests::object_member_as_object(body, "rooms");
            auto const* join = rooms == nullptr ? nullptr : merovingian::tests::object_member_as_object(*rooms, "join");
            auto const* room = join == nullptr ? nullptr : merovingian::tests::object_member_as_object(*join, room_id);
            REQUIRE(room != nullptr);
            // alice's memberships in the room's `timeline` or `state` section, in order.
            auto const membership_in = [&](std::string_view section) {
                auto memberships = std::vector<std::string>{};
                auto const* part = merovingian::tests::object_member_as_object(*room, section);
                auto const* events =
                    part == nullptr ? nullptr : merovingian::tests::object_member_as_array(*part, "events");
                REQUIRE(events != nullptr);
                for (auto const& entry : *events)
                {
                    auto const& object = std::get<merovingian::canonicaljson::Object>(entry.storage());
                    auto const* type = merovingian::tests::string_member(object, "type");
                    auto const* key = merovingian::tests::string_member(object, "state_key");
                    auto const* content = merovingian::tests::object_member_as_object(object, "content");
                    auto const* value =
                        content == nullptr ? nullptr : merovingian::tests::string_member(*content, "membership");
                    if (type != nullptr && *type == "m.room.member" && key != nullptr && *key == alice &&
                        value != nullptr)
                    {
                        memberships.push_back(*value);
                    }
                }
                return memberships;
            };

            THEN("the timeline is the join, and the state before it holds the user's invite")
            {
                CAPTURE(synced.response.body);
                REQUIRE(membership_in("timeline") == std::vector<std::string>{"join"});
                REQUIRE(membership_in("state") == std::vector<std::string>{"invite"});
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

        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
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

        auto const room_chain = resident_room_chain(room_id, creator, policy);
        auto const make_join_event =
            naming_auth_events(std::string{R"({"type":"m.room.member","state_key":")"} + alice + R"(","room_id":")" +
                                   room_id + R"(","sender":")" + alice +
                                   R"(","depth":3,"origin_server_ts":1000,)"
                                   R"("prev_events":[],"auth_events":[],)"
                                   R"("content":{"membership":"join"}})",
                               room_chain.member_auth());
        auto const make_join_body = std::string{R"({"room_version":"10","event":)"} + make_join_event + "}";


        // The state array is the room's state BEFORE the join — create and
        // power_levels only, no join event and no other members, matching
        // spec (server-server-api.md#joining-rooms).
        auto state_array = room_chain.events();

        auto auth_chain_array = room_chain.events();

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
                REQUIRE(full->size() == 5U); // create, creator's join, power_levels, join_rules, alice's join
                REQUIRE(std::ranges::any_of(*full, [](auto const& e) {
                    return e.event_type == "m.room.create";
                }));
                REQUIRE(std::ranges::any_of(*full, [](auto const& e) {
                    return e.event_type == "m.room.power_levels";
                }));
                auto const member_entry = std::ranges::find_if(*full, [&](auto const& e) {
                    return e.event_type == "m.room.member" && e.state_key == alice;
                });
                REQUIRE(member_entry != full->end());
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

        // Spec: Server-Server API v1.19, "Joining Rooms": a server that is not in the room joins
        // through a resident with make_join and send_join. Once this server's last user has left,
        // it is no longer in the room even though it still knows the room, so a rejoin must go
        // through the resident, which decides it. It was composed here instead, so a join the
        // resident would refuse (Complement TestRestrictedRoomsRemoteJoin, "Join should fail with
        // mangled join rules") succeeded, and nothing told the resident.
        WHEN("alice joins through the resident, leaves through it, and joins again")
        {
            auto first_requests = std::vector<std::string>{};
            auto first_server = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_join_response, send_join_response,
                                    first_requests);
            }};
            auto const joined =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});
            first_server.join();
            REQUIRE(joined.ok);

            auto const make_leave_event = std::string{R"({"type":"m.room.member","state_key":")"} + alice +
                                          R"(","room_id":")" + room_id + R"(","sender":")" + alice +
                                          R"(","depth":4,"origin_server_ts":1100,)"
                                          R"("prev_events":[],"auth_events":[],)"
                                          R"("content":{"membership":"leave"}})";
            auto leave_requests = std::vector<std::string>{};
            auto leave_server = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context,
                                    json_http_response("200 OK", std::string{R"({"room_version":"10","event":)"} +
                                                                     make_leave_event + "}"),
                                    json_http_response("200 OK", "{}"), leave_requests);
            }};
            auto const left = merovingian::homeserver::leave_room(runtime, login.value, room_id);
            leave_server.join();
            REQUIRE(left.ok);

            auto rejoin_requests = std::vector<std::string>{};
            auto rejoin_server = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_join_response, send_join_response,
                                    rejoin_requests);
            }};
            auto const rejoined =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});
            rejoin_server.join();

            THEN("the rejoin goes through the resident's make_join and send_join")
            {
                CAPTURE(rejoined.reason);
                REQUIRE(rejoined.ok);
                REQUIRE(rejoin_requests.size() == 2U);
                REQUIRE(rejoin_requests[0].find("/_matrix/federation/v1/make_join/") != std::string::npos);
                REQUIRE(rejoin_requests[1].find("/_matrix/federation/v2/send_join/") != std::string::npos);
            }
        }

        WHEN("join_room rejoins a room whose last event from an earlier stay is still a forward extremity")
        {
            // An earlier stay ended with this server's own leave as the room's
            // tip here. The resident's DAG has moved on past it, so the join's
            // prev_events (which the make_join template chose) descend from it.
            auto const left_behind = std::string{"$earlier_leave:"} + resident_server;
            {
                auto const lock = std::lock_guard{runtime.mutex};
                REQUIRE(merovingian::database::update_forward_extremities(runtime.database.persistent_store, room_id,
                                                                          left_behind, {}, true));
            }
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_join_response, send_join_response,
                                    captured_requests);
            }};

            auto const result =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});

            server_thread.join();

            THEN("the join event replaces it as the room's sole forward extremity")
            {
                CAPTURE(result.reason);
                REQUIRE(result.ok);
                auto const lock = std::lock_guard{runtime.mutex};
                auto const& store = runtime.database.persistent_store;
                auto const join_state_row =
                    std::ranges::find_if(store.state, [&](merovingian::database::PersistentStateEvent const& s) {
                        return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == alice;
                    });
                REQUIRE(join_state_row != store.state.end());
                REQUIRE(merovingian::database::find_forward_extremities(store, room_id) ==
                        std::vector<std::string>{join_state_row->event_id});
            }
        }

        // The state the join's after-state is recorded from cannot be stored:
        // the join answers a server error instead of leaving a joined room
        // with no state to build the next event on.
        auto const join_with_failing_statement = [&](std::string const& statement_name) {
            {
                auto const lock = std::lock_guard{runtime.mutex};
                runtime.database.persistent_store.force_failure_statement_names.insert(statement_name);
            }
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_join_response, send_join_response,
                                    captured_requests);
            }};
            auto const result =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});
            server_thread.join();
            return result;
        };

        // ADR-0228: the join event, alice's membership, the join's state group,
        // its mapping, the forward extremities and current state commit in
        // one transaction, so a refused write leaves alice not joined.
        auto const nothing_of_the_join_is_left = [&]() {
            auto const lock = std::lock_guard{runtime.mutex};
            auto const& store = runtime.database.persistent_store;
            REQUIRE_FALSE(std::ranges::any_of(store.memberships, [&](auto const& m) {
                return m.room_id == room_id && m.user_id == alice && m.membership == "join";
            }));
            REQUIRE_FALSE(std::ranges::any_of(store.state, [&](auto const& s) {
                return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == alice;
            }));
            REQUIRE(merovingian::database::find_forward_extremities(store, room_id).empty());
            REQUIRE_FALSE(std::ranges::any_of(store.state_groups, [&](auto const& group) {
                return group.room_id == room_id;
            }));
        };

        WHEN("join_room cannot store the join event's after-state group")
        {
            auto const result = join_with_failing_statement("insert_state_group");

            THEN("the join answers a server error and alice is not joined")
            {
                CAPTURE(result.reason);
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 500U);
                nothing_of_the_join_is_left();
            }
        }

        WHEN("join_room cannot map the join event to its after-state group")
        {
            auto const result = join_with_failing_statement("upsert_event_state_group");

            THEN("the join answers a server error and alice is not joined")
            {
                CAPTURE(result.reason);
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 500U);
                nothing_of_the_join_is_left();
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

        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
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

        auto const room_chain = resident_room_chain(room_id, creator, policy);
        auto const make_join_event =
            naming_auth_events(std::string{R"({"type":"m.room.member","state_key":")"} + alice + R"(","room_id":")" +
                                   room_id + R"(","sender":")" + alice +
                                   R"(","depth":3,"origin_server_ts":1000,)"
                                   R"("prev_events":[],"auth_events":[],)"
                                   R"("content":{"membership":"join"}})",
                               room_chain.member_auth());
        auto const make_join_body = std::string{R"({"room_version":"10","event":)"} + make_join_event + "}";


        // The state array is the room's state BEFORE the join — create and
        // power_levels only, no join event and no other members, matching
        // spec (server-server-api.md#joining-rooms).
        auto state_array = room_chain.events();

        auto auth_chain_array = room_chain.events();

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
                        auto const power_id = room_chain.power_levels_id;
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
                        if (deferred.status == merovingian::federation::PduIngestionStatus::deferred &&
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
                auto outer_guard = merovingian::homeserver::RuntimeLock{runtime.mutex};
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
                CHECK(deferred.status == merovingian::federation::PduIngestionStatus::deferred);
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

        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
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

        auto const room_chain = resident_room_chain(joined_room, creator, policy);
        auto const make_join_event = naming_auth_events(std::string{R"({"type":"m.room.member","state_key":")"} + bob +
                                                            R"(","room_id":")" + joined_room + R"(","sender":")" + bob +
                                                            R"(","depth":3,"origin_server_ts":1000,)"
                                                            R"("prev_events":[],"auth_events":[],)"
                                                            R"("content":{"membership":"join"}})",
                                                        room_chain.member_auth());
        auto const make_join_body = std::string{R"({"room_version":"10","event":)"} + make_join_event + "}";

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

        auto state_array = room_chain.events();
        state_array.push_back(forged_unsigned_pl_value);
        state_array.push_back(forged_signed_pl_value);
        state_array.push_back(forged_member_value);

        auto auth_chain_array = room_chain.events();
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

        // A real runtime with a registered user, because the join code consults the local signing key and the user
        // session.
        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const alice = reg.value;
        auto const carol = std::string{"@carol:"} + local_server;

        // The resident is a TLS mock on loopback; the forced outbound resolution routes the resident server name to it
        // without touching DNS.
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
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

        auto const room_chain = resident_room_chain(room_id, creator, policy);
        auto const make_join_event =
            naming_auth_events(std::string{R"({"type":"m.room.member","state_key":")"} + alice + R"(","room_id":")" +
                                   room_id + R"(","sender":")" + alice +
                                   R"(","depth":5,"origin_server_ts":1000,)"
                                   R"("prev_events":[],"auth_events":[],)"
                                   R"("content":{"membership":"join"}})",
                               room_chain.member_auth());
        auto const make_join_body = std::string{R"({"room_version":"10","event":)"} + make_join_event + "}";
        // Carol is an own-domain member event, signed with this server key below to model a re-join echoed back by the
        // resident.
        auto const carol_member =
            naming_auth_events(std::string{R"({"type":"m.room.member","state_key":")"} + carol + R"(","room_id":")" +
                                   room_id + R"(","sender":")" + carol +
                                   R"(","depth":3,"origin_server_ts":902,"prev_events":[],"auth_events":[],)"
                                   R"("content":{"membership":"join"}})",
                               room_chain.member_auth());
        auto const former_member =
            naming_auth_events(std::string{R"({"type":"m.room.member","state_key":")"} + former + R"(","room_id":")" +
                                   room_id + R"(","sender":")" + former +
                                   R"(","depth":2,"origin_server_ts":901,"prev_events":[],"auth_events":[],)"
                                   R"("content":{"membership":"join"}})",
                               room_chain.member_auth());

        auto const carol_value = sign_with_local_server_key(runtime, carol_member, policy);
        auto const carol_event_id = reference_event_id(carol_value, policy);
        auto const former_value =
            sign_test_event(former_member, policy, resident_server, resident_key_id, resident_key_seed);
        auto const former_event_id = reference_event_id(former_value, policy);

        auto state_array = room_chain.events();
        state_array.push_back(carol_value);

        auto auth_chain_array = room_chain.events();
        auth_chain_array.push_back(former_value);

        auto const send_join_body = std::string{R"({"state":)"} + canonicaljson_array_to_string(state_array) +
                                    R"(,"auth_chain":)" + canonicaljson_array_to_string(auth_chain_array) + "}";
        // Canned make_join and send_join answers: the mock resident serves exactly these two responses.
        auto const make_join_response = json_http_response("200 OK", make_join_body);
        auto const send_join_response = json_http_response("200 OK", send_join_body);

        // The mock resident runs on its own thread while join_room talks to it; the runtime lock is taken only to
        // inspect the store.
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

// Spec: Matrix Server-Server API v1.19, "Joining Rooms" (make_leave templates are
// filled in the same way): the joining server "is expected to add or replace the
// origin, origin_server_ts, and event_id on the templated event". The leave we
// sign carries our origin and our clock, whatever the template held, and a
// template without them is accepted.
// Spec: Matrix Server-Server API v1.19, "Checks performed on receipt of a PDU"
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
//
// "3. Passes hash checks, otherwise it is redacted before being processed further. 4. Passes authorisation rules
// based on the event's auth events, otherwise it is rejected." A resident's send_join answer is a receipt like any
// other (F-45, ADR-0369).
SCENARIO("A joining server applies the receipt checks to a resident's send_join answer",
         "[f45][security][homeserver][federation][join][integration]")
{
    GIVEN("a resident server answering a join with a room it controls")
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

        // The resident is a loopback TLS mock; forced resolution sends the resident server name there instead of DNS.
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
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
        // Only the resident server key resolves: any other origin or key id yields no key, so its signatures cannot
        // verify.
        runtime.federation.remote_key_resolver =
            [](std::string_view server_name,
               std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            if (server_name != resident_server || key_id != resident_key_id)
            {
                return std::nullopt;
            }
            return resident_remote_runtime();
        };

        auto const room_id = std::string{"!f45:"} + resident_server;
        auto const creator = std::string{"@creator:"} + resident_server;
        auto const bob = std::string{"@bob:"} + resident_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto const room_chain = resident_room_chain(room_id, creator, policy);
        auto const make_join_event =
            naming_auth_events(std::string{R"({"type":"m.room.member","state_key":")"} + alice + R"(","room_id":")" +
                                   room_id + R"(","sender":")" + alice +
                                   R"(","depth":5,"origin_server_ts":1000,)"
                                   R"("prev_events":[],"auth_events":[],)"
                                   R"("content":{"membership":"join"}})",
                               room_chain.member_auth());
        auto const make_join_response =
            json_http_response("200 OK", std::string{R"({"room_version":"10","event":)"} + make_join_event + "}");

        // Bob join is genuinely signed by the resident and later tampered with or refused per scenario.
        auto const bob_join = sign_test_event(
            naming_auth_events(std::string{R"({"type":"m.room.member","state_key":")"} + bob + R"(","room_id":")" +
                                   room_id + R"(","sender":")" + bob +
                                   R"(","depth":5,"origin_server_ts":950,"prev_events":[],"auth_events":[],)"
                                   R"("content":{"membership":"join"}})",
                               room_chain.member_auth()),
            policy, resident_server, resident_key_id, resident_key_seed);

        // One helper runs the join against a mock that serves the given state, so each WHEN only varies the answer.
        auto const join_with_answer = [&](merovingian::canonicaljson::Array const& state) {
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_join_response,
                                    json_http_response("200 OK", std::string{R"({"state":)"} +
                                                                     canonicaljson_array_to_string(state) +
                                                                     R"(,"auth_chain":[]})"),
                                    captured_requests);
            }};
            auto result =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});
            server_thread.join();
            return result;
        };

        WHEN("the resident changes an event's content after it was signed")
        {
            // m.room.server_acl keeps no content when redacted, so the signature and the event ID still hold.
            auto const genuine_acl = sign_test_event(
                naming_auth_events(std::string{R"({"type":"m.room.server_acl","state_key":"","room_id":")"} + room_id +
                                       R"(","sender":")" + creator +
                                       R"(","depth":5,"origin_server_ts":951,"prev_events":[],"auth_events":[],)"
                                       R"("content":{"allow":["*"],"deny":[]}})",
                                   "\"" + room_chain.create_id + "\",\"" + room_chain.creator_join_id + "\",\"" +
                                       room_chain.power_levels_id + "\""),
                policy, resident_server, resident_key_id, resident_key_seed);
            auto const acl_id = reference_event_id(genuine_acl, policy);
            auto tampered_json = merovingian::canonicaljson::serialize_canonical(genuine_acl).output;
            auto const genuine_content = std::string{R"("allow":["*"],"deny":[])"};
            auto const content_position = tampered_json.find(genuine_content);
            REQUIRE(content_position != std::string::npos);
            tampered_json.replace(content_position, genuine_content.size(),
                                  R"("allow":["evil.example.org"],"deny":[])");
            auto const tampered = merovingian::canonicaljson::parse_lossless(tampered_json);
            REQUIRE(tampered.error == merovingian::canonicaljson::ParseError::none);
            REQUIRE(reference_event_id(tampered.value, policy) == acl_id);

            auto state = room_chain.events();
            state.push_back(tampered.value);
            auto const result = join_with_answer(state);
            auto const lock = std::lock_guard{runtime.mutex};
            auto const stored = runtime.database.persistent_store.events.find_in_room(room_id, acl_id);

            THEN("the join succeeds and the event is stored redacted, without the resident's content")
            {
                CAPTURE(result.reason);
                REQUIRE(result.ok);
                REQUIRE(stored != runtime.database.persistent_store.events.end());
                REQUIRE(stored->json.find("evil.example.org") == std::string::npos);
            }
        }

        // A correctly signed event can still fail the auth rules: signature checks alone are not enough.
        WHEN("the answer lists an event the auth rules refuse")
        {
            // Bob holds power level 0; a state event needs 50.
            auto const forged = sign_test_event(
                naming_auth_events(std::string{R"({"type":"m.room.power_levels","state_key":"","room_id":")"} +
                                       room_id + R"(","sender":")" + bob +
                                       R"(","depth":6,"origin_server_ts":952,"prev_events":[],"auth_events":[],)"
                                       R"("content":{"users":{")" +
                                       bob + R"(":100}}})",
                                   "\"" + room_chain.create_id + "\",\"" + room_chain.power_levels_id + "\",\"" +
                                       reference_event_id(bob_join, policy) + "\""),
                policy, resident_server, resident_key_id, resident_key_seed);
            auto const forged_id = reference_event_id(forged, policy);
            auto state = room_chain.events();
            state.push_back(bob_join);
            state.push_back(forged);
            auto const result = join_with_answer(state);
            auto const lock = std::lock_guard{runtime.mutex};
            auto const& store = runtime.database.persistent_store;

            THEN("the join succeeds, the refused event is not stored and the genuine power levels stay")
            {
                CAPTURE(result.reason);
                REQUIRE(result.ok);
                REQUIRE(store.events.find_in_room(room_id, forged_id) == store.events.end());
                REQUIRE(merovingian::database::find_current_state_event_id(store, room_id, "m.room.power_levels", "") ==
                        room_chain.power_levels_id);
            }
        }

        WHEN("the answer's join rules do not let the joining user in")
        {
            auto const invite_only = sign_test_event(
                naming_auth_events(std::string{R"({"type":"m.room.join_rules","state_key":"","room_id":")"} + room_id +
                                       R"(","sender":")" + creator +
                                       R"(","depth":4,"origin_server_ts":900,"prev_events":[],"auth_events":[],)"
                                       R"("content":{"join_rule":"invite"}})",
                                   "\"" + room_chain.create_id + "\",\"" + room_chain.creator_join_id + "\",\"" +
                                       room_chain.power_levels_id + "\""),
                policy, resident_server, resident_key_id, resident_key_seed);
            auto const invite_only_id = reference_event_id(invite_only, policy);
            auto const refused_template = naming_auth_events(
                std::string{R"({"type":"m.room.member","state_key":")"} + alice + R"(","room_id":")" + room_id +
                    R"(","sender":")" + alice +
                    R"(","depth":5,"origin_server_ts":1000,"prev_events":[],"auth_events":[],)"
                    R"("content":{"membership":"join"}})",
                "\"" + room_chain.create_id + "\",\"" + room_chain.power_levels_id + "\",\"" + invite_only_id + "\"");
            auto const answer = merovingian::canonicaljson::Array{room_chain.create, room_chain.creator_join,
                                                                  room_chain.power_levels, invite_only};
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(
                    acceptor, *tls_context.context,
                    json_http_response("200 OK",
                                       std::string{R"({"room_version":"10","event":)"} + refused_template + "}"),
                    json_http_response("200 OK", std::string{R"({"state":)"} + canonicaljson_array_to_string(answer) +
                                                     R"(,"auth_chain":[]})"),
                    captured_requests);
            }};
            auto const result =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});
            server_thread.join();
            auto const lock = std::lock_guard{runtime.mutex};
            auto const& store = runtime.database.persistent_store;

            THEN("the join is refused and nothing of the room is stored")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(store.events.find_in_room(room_id, room_chain.create_id) == store.events.end());
                REQUIRE_FALSE(std::ranges::any_of(store.memberships, [&](auto const& row) {
                    return row.room_id == room_id && row.user_id == alice && row.membership == "join";
                }));
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, "Checks performed on receipt of a PDU", and rooms/v10.md, authorisation rule
// 2.4: "If there is no m.room.create event among the entries, reject." A room version comes from the room's create
// event (client-server-api.md, m.room.create), so a PDU that arrived before the create was stored is judged again
// under the version the create declares (F-44, ADR-0370).
SCENARIO("A PDU parked during a federated join is judged under the room version the create event declares",
         "[f44][security][homeserver][federation][join][integration]")
{
    GIVEN("a version 10 room whose resident delivers PDUs before it answers send_join")
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

        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
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

        auto const room_id = std::string{"!f44:"} + resident_server;
        auto const creator = std::string{"@creator:"} + resident_server;
        auto const bob = std::string{"@bob:"} + resident_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto const guessed_policy = *merovingian::rooms::find_room_version_policy("12");
        auto const room_chain = resident_room_chain(room_id, creator, policy);
        auto const make_join_event =
            naming_auth_events(std::string{R"({"type":"m.room.member","state_key":")"} + alice + R"(","room_id":")" +
                                   room_id + R"(","sender":")" + alice +
                                   R"(","depth":6,"origin_server_ts":1000,)"
                                   R"("prev_events":[],"auth_events":[],)"
                                   R"("content":{"membership":"join"}})",
                               room_chain.member_auth());
        auto const bob_join = sign_test_event(
            naming_auth_events(std::string{R"({"type":"m.room.member","state_key":")"} + bob + R"(","room_id":")" +
                                   room_id + R"(","sender":")" + bob +
                                   R"(","depth":5,"origin_server_ts":950,"prev_events":[],"auth_events":[],)"
                                   R"("content":{"membership":"join"}})",
                               room_chain.member_auth()),
            policy, resident_server, resident_key_id, resident_key_seed);
        auto const bob_join_id = reference_event_id(bob_join, policy);
        auto state = room_chain.events();
        state.push_back(bob_join);
        auto const make_join_response =
            json_http_response("200 OK", std::string{R"({"room_version":"10","event":)"} + make_join_event + "}");
        auto const send_join_response = json_http_response(
            "200 OK", std::string{R"({"state":)"} + canonicaljson_array_to_string(state) + R"(,"auth_chain":[]})");

        auto const quoted = [](std::string const& id) {
            return "\"" + id + "\"";
        };
        // This server holds no create event yet, so every receipt path guesses version 12.
        auto const received = [&](std::string const& raw, merovingian::rooms::RoomVersionPolicy const& signing_policy) {
            auto const signed_event =
                sign_test_event(raw, signing_policy, resident_server, resident_key_id, resident_key_seed);
            auto const json = merovingian::canonicaljson::serialize_canonical(signed_event).output;
            auto envelope = merovingian::federation::parse_inbound_pdu_envelope(json, "12");
            REQUIRE(envelope.has_value());
            envelope->origin = resident_server;
            return *envelope;
        };

        WHEN("the PDUs arrive while the join is in progress")
        {
            auto ban_event_id = std::string{};
            auto honest_event_id = std::string{};
            auto forged_event_ids = std::vector<std::string>{};
            auto statuses = std::vector<merovingian::federation::PduIngestionStatus>{};
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = merovingian::tests::JoiningThreads{};
            server_thread.emplace_back([&]() {
                run_resident_server(
                    acceptor, *tls_context.context, make_join_response, send_join_response, captured_requests,
                    [&](std::string const& request) {
                        auto const join_id = reference_event_id(event_from_send_request(request), policy);
                        // Valid under version 12, where a creator outranks everyone and the create event is not named.
                        // Version 10 rejects it: its auth_events hold no m.room.create.
                        auto const ban =
                            received(std::string{R"({"type":"m.room.member","state_key":")"} + bob +
                                         R"(","room_id":")" + room_id + R"(","sender":")" + creator +
                                         R"(","depth":7,"origin_server_ts":1100,"prev_events":[)" + quoted(join_id) +
                                         R"(],"auth_events":[)" + quoted(room_chain.power_levels_id) + "," +
                                         quoted(room_chain.creator_join_id) + "," + quoted(bob_join_id) +
                                         R"(],"content":{"membership":"ban"}})",
                                     guessed_policy);
                        ban_event_id =
                            reference_event_id(merovingian::canonicaljson::parse_lossless(ban.json).value, policy);
                        statuses.push_back(runtime.federation.pdu_sink(ban).status);
                        // Signed over the version 12 redaction, which drops a top-level `origin`. Version 10 keeps it,
                        // so the signature does not cover what version 10 checks.
                        auto const forged = received(
                            std::string{R"({"type":"m.room.message","room_id":")"} + room_id + R"(","sender":")" +
                                creator +
                                R"(","origin":"resident.example.org","depth":7,"origin_server_ts":1101,"prev_events":[)" +
                                quoted(join_id) + R"(],"auth_events":[)" + quoted(room_chain.create_id) + "," +
                                quoted(room_chain.power_levels_id) + "," + quoted(room_chain.creator_join_id) +
                                R"(],"content":{"body":"x","msgtype":"m.text"}})",
                            guessed_policy);
                        forged_event_ids.push_back(forged.event_id);
                        forged_event_ids.push_back(
                            reference_event_id(merovingian::canonicaljson::parse_lossless(forged.json).value, policy));
                        statuses.push_back(runtime.federation.pdu_sink(forged).status);
                        // Nothing wrong with this one, under the room's real version.
                        auto const honest = received(
                            std::string{R"({"type":"m.room.message","room_id":")"} + room_id + R"(","sender":")" +
                                creator + R"(","depth":7,"origin_server_ts":1102,"prev_events":[)" + quoted(join_id) +
                                R"(],"auth_events":[)" + quoted(room_chain.create_id) + "," +
                                quoted(room_chain.power_levels_id) + "," + quoted(room_chain.creator_join_id) +
                                R"(],"content":{"body":"hello","msgtype":"m.text"}})",
                            policy);
                        honest_event_id = honest.event_id;
                        statuses.push_back(runtime.federation.pdu_sink(honest).status);
                    });
            });
            auto const result =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});
            server_thread.join();

            auto const lock = std::lock_guard{runtime.mutex};
            auto const& store = runtime.database.persistent_store;
            auto const status_of = [&](std::string const& event_id) -> std::string {
                auto const stored = store.events.find_in_room(room_id, event_id);
                return stored != store.events.end() ? stored->status : std::string{"absent"};
            };

            THEN("every one was parked until the join committed")
            {
                CAPTURE(result.reason);
                REQUIRE(result.ok);
                REQUIRE(statuses.size() == 3U);
                REQUIRE(std::ranges::all_of(statuses, [](auto const status) {
                    return status == merovingian::federation::PduIngestionStatus::deferred;
                }));
            }

            THEN("the ban that only version 12 allows does not take effect")
            {
                CAPTURE(status_of(ban_event_id));
                REQUIRE(status_of(ban_event_id) != "accepted");
                REQUIRE(merovingian::database::find_current_state_event_id(store, room_id, "m.room.member", bob) ==
                        bob_join_id);
            }

            THEN("the event whose signature holds only under version 12 is not stored under either ID")
            {
                for (auto const& event_id : forged_event_ids)
                {
                    CAPTURE(event_id);
                    REQUIRE(status_of(event_id) == "absent");
                }
            }

            THEN("the honest event is accepted under the room's real version")
            {
                REQUIRE(status_of(honest_event_id) == "accepted");
            }

            AND_WHEN("a PDU still carrying the guessed version arrives once the create is stored")
            {
                auto const late =
                    received(std::string{R"({"type":"m.room.message","room_id":")"} + room_id + R"(","sender":")" +
                                 creator + R"(","depth":8,"origin_server_ts":1103,"prev_events":[)" +
                                 quoted(honest_event_id) + R"(],"auth_events":[)" + quoted(room_chain.create_id) + "," +
                                 quoted(room_chain.power_levels_id) + "," + quoted(room_chain.creator_join_id) +
                                 R"(],"content":{"body":"late","msgtype":"m.text"}})",
                             policy);
                auto const answer = runtime.federation.pdu_sink(late);

                THEN("it is refused: the version it was verified under is not the room's")
                {
                    REQUIRE(answer.status == merovingian::federation::PduIngestionStatus::rejected_invalid);
                    REQUIRE(status_of(late.event_id) == "absent");
                }
            }
        }
    }
}

SCENARIO("leave_room signs remote membership templates with and without existing hashes",
         "[membership-template-hashes][homeserver][federation][integration][make-join]")
{
    GIVEN("a logged-in local user with a persisted remote membership and a TLS resident server")
    {
        REQUIRE(sodium_init() >= 0);
        auto const template_has_hashes = GENERATE(false, true);
        auto const template_is_stamped = GENERATE(true, false);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto constexpr our_clock_ms = std::int64_t{1'800'000'000'000};
        runtime.test_frozen_event_clock_ms = our_clock_ms;
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

        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        runtime.test_forced_outbound_resolution[resident_server] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", acceptor.bound_port(), {"127.0.0.1"}, certificate.certificate_pem};

        auto const leave_event = std::string{R"({"type":"m.room.member","state_key":")"} + alice + R"(","room_id":")" +
                                 room_id + R"(","sender":")" + alice + R"(","depth":7,)" +
                                 (template_is_stamped ? std::string{R"("origin":")"} + resident_server +
                                                            R"(","origin_server_ts":1001,"event_id":"$resident",)"
                                                      : std::string{}) +
                                 R"("prev_events":[],"auth_events":[],)" +
                                 (template_has_hashes ? R"("hashes":{"sha256":"stale"},)" : "") +
                                 R"("content":{"membership":"leave"}})";
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
                CAPTURE(template_has_hashes, template_is_stamped, result.reason);
                REQUIRE(result.ok);
                REQUIRE(result.value == room_id);
                REQUIRE(captured_requests.size() == 2U);
                auto const leave = event_from_send_request(captured_requests[1]);
                auto const policy = *merovingian::rooms::find_room_version_policy("10");
                require_membership_event_integrity(runtime, leave, policy);
                auto const* leave_object = std::get_if<merovingian::canonicaljson::Object>(&leave.storage());
                REQUIRE(leave_object != nullptr);
                // Ours, not the resident's: origin, origin_server_ts and no event_id.
                auto const* origin = merovingian::tests::string_member(*leave_object, "origin");
                REQUIRE(origin != nullptr);
                REQUIRE(*origin == local_server);
                auto const* timestamp = merovingian::tests::int_member(*leave_object, "origin_server_ts");
                REQUIRE(timestamp != nullptr);
                REQUIRE(*timestamp == our_clock_ms);
                REQUIRE(merovingian::tests::object_member(*leave_object, "event_id") == nullptr);
                REQUIRE(std::ranges::any_of(runtime.database.persistent_store.memberships, [&](auto const& member) {
                    return member.room_id == room_id && member.user_id == alice && member.membership == "leave";
                }));
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, "Joining Rooms"
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#joining-rooms
//
// "The joining server is expected to add or replace the origin,
// origin_server_ts, and event_id on the templated event received by the
// resident server." Regression for Complement run 2 (0.12.58): a template
// without origin_server_ts was refused (`502 make_join event origin_server_ts
// is required`), and a template with one had the resident's timestamp signed
// as ours. From room version 5 other servers judge our key at that timestamp
// (ADR-0075), so the resident must not choose it.
SCENARIO("join_room signs the join with its own origin and timestamp, whatever the make_join template holds",
         "[homeserver][federation][join][integration][make-join]")
{
    GIVEN("a logged-in local user, a frozen event clock and a TLS resident server")
    {
        REQUIRE(sodium_init() >= 0);
        // Both template shapes: one already carrying the resident's origin, timestamp and
        // event_id, and one carrying none of them.
        auto const template_is_stamped = GENERATE(true, false);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        // A frozen clock, so the signed timestamp can be compared exactly.
        auto constexpr our_clock_ms = std::int64_t{1'800'000'000'000};
        runtime.test_frozen_event_clock_ms = our_clock_ms;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const alice = reg.value;

        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        runtime.test_forced_outbound_resolution[resident_server] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", acceptor.bound_port(), {"127.0.0.1"}, certificate.certificate_pem};

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

        // The resident's room: the TLS mock answers make_join with the template below, and
        // send_join with the create and power-levels state, signed by the resident's key.
        auto const room_id = std::string{"!stamproom:"} + resident_server;
        auto const creator = std::string{"@creator:"} + resident_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");

        auto const room_chain = resident_room_chain(room_id, creator, policy);
        auto const make_join_event =
            naming_auth_events(std::string{R"({"type":"m.room.member","state_key":")"} + alice + R"(","room_id":")" +
                                   room_id + R"(","sender":")" + alice + R"(","depth":3,)" +
                                   (template_is_stamped ? std::string{R"("origin":")"} + resident_server +
                                                              R"(","origin_server_ts":1,"event_id":"$resident",)"
                                                        : std::string{}) +
                                   R"("prev_events":[],"auth_events":[],"content":{"membership":"join"}})",
                               room_chain.member_auth());
        auto const make_join_body = std::string{R"({"room_version":"10","event":)"} + make_join_event + "}";

        // The state before the join, and its auth chain: the same two events.
        auto state_array = room_chain.events();
        auto auth_chain_array = room_chain.events();
        auto const send_join_body = std::string{R"({"state":)"} + canonicaljson_array_to_string(state_array) +
                                    R"(,"auth_chain":)" + canonicaljson_array_to_string(auth_chain_array) + "}";

        auto const make_join_response = json_http_response("200 OK", make_join_body);
        auto const send_join_response = json_http_response("200 OK", send_join_body);

        WHEN("join_room joins through the resident server")
        {
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, make_join_response, send_join_response,
                                    captured_requests);
            }};
            auto const result =
                merovingian::homeserver::join_room(runtime, login.value, room_id, {std::string{resident_server}});
            server_thread.join();

            THEN("the join succeeds, and the event we signed carries our origin and clock and no event_id")
            {
                CAPTURE(template_is_stamped, result.reason);
                REQUIRE(result.ok);
                REQUIRE(captured_requests.size() == 2U);
                // The second request is send_join; its body is the event this server signed.
                auto const join_event = event_from_send_request(captured_requests[1]);
                require_membership_event_integrity(runtime, join_event, policy);
                auto const* join_object = std::get_if<merovingian::canonicaljson::Object>(&join_event.storage());
                REQUIRE(join_object != nullptr);
                auto const* origin = merovingian::tests::string_member(*join_object, "origin");
                REQUIRE(origin != nullptr);
                REQUIRE(*origin == local_server);
                auto const* timestamp = merovingian::tests::int_member(*join_object, "origin_server_ts");
                REQUIRE(timestamp != nullptr);
                REQUIRE(*timestamp == our_clock_ms);
                REQUIRE(merovingian::tests::object_member(*join_object, "event_id") == nullptr);
            }
        }
    }
}

// Security audit run-1 (rooms.room-version-resolution-divergent-fallbacks-create-without-room_version):
// a room's version is the one its m.room.create declares, and a create event with no room_version
// is room version 1 (client-server-api.md, m.room.create), which this server does not support (ADR-0076). The federated
// join took the version from the make_join response alone, so a resident server could seat a local
// user in a room whose create event says something else, which every component then resolved
// with a different default. The join is now refused, before anything is stored, unless the create
// event in the send_join state declares the make_join version.
SCENARIO("A federated join is refused when the room's create event does not declare the make_join version",
         "[security][homeserver][federation][join][integration][room-version]")
{
    GIVEN("a resident server whose make_join says room version 10")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const bob_reg = merovingian::homeserver::register_local_user(runtime, "bob", "CorrectHorse7!",
                                                                          merovingian::tests::registration_token);
        REQUIRE(bob_reg.ok);
        auto const bob_login =
            merovingian::homeserver::login_local_user(runtime, bob_reg.value, "CorrectHorse7!", "DEVICE2");
        REQUIRE(bob_login.ok);
        auto const bob = bob_reg.value;

        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
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

        auto const joined_room = std::string{"!versions:"} + resident_server;
        auto const creator = std::string{"@creator:"} + resident_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto const make_join_event = std::string{R"({"type":"m.room.member","state_key":")"} + bob +
                                     R"(","room_id":")" + joined_room + R"(","sender":")" + bob +
                                     R"(","depth":3,"origin_server_ts":1000,)"
                                     R"("prev_events":[],"auth_events":[],)"
                                     R"("content":{"membership":"join"}})";
        // The resident server answers make_join with version 10. Only the create event inside its send_join
        // answer changes between the two WHEN blocks.
        auto const make_join_body = std::string{R"({"room_version":"10","event":)"} + make_join_event + "}";
        auto const power_levels_event = std::string{R"({"type":"m.room.power_levels","state_key":"","sender":")"} +
                                        creator + R"(","room_id":")" + joined_room +
                                        R"(","depth":2,"origin_server_ts":901,"prev_events":[],"auth_events":[],)"
                                        R"("content":{"users":{")" +
                                        creator + R"(":100}}})";

        // Builds a send_join answer whose state and auth chain hold a create event with the given content,
        // signed by the resident server, plus its power levels.
        auto const send_join_with_create_content = [&](std::string const& create_content) {
            auto const create_event = std::string{R"({"type":"m.room.create","state_key":"","sender":")"} + creator +
                                      R"(","room_id":")" + joined_room +
                                      R"(","depth":1,"origin_server_ts":900,"prev_events":[],"auth_events":[],)"
                                      R"("content":)" +
                                      create_content + "}";
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
            return std::string{R"({"state":)"} + canonicaljson_array_to_string(state_array) + R"(,"auth_chain":)" +
                   canonicaljson_array_to_string(auth_chain_array) + "}";
        };
        // Serves make_join then send_join from the mock resident server and joins bob through it.
        auto const join_through_resident = [&](std::string const& send_join_body) {
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_resident_server(acceptor, *tls_context.context, json_http_response("200 OK", make_join_body),
                                    json_http_response("200 OK", send_join_body), captured_requests);
            }};
            auto result = merovingian::homeserver::join_room(runtime, bob_login.value, joined_room,
                                                             {std::string{resident_server}});
            server_thread.join();
            return result;
        };
        // Nothing of a refused room may be stored: no current state and no event.
        auto const room_is_stored = [&] {
            auto const lock = std::lock_guard{runtime.mutex};
            return std::ranges::any_of(runtime.database.persistent_store.state,
                                       [&](auto const& row) {
                                           return row.room_id == joined_room;
                                       }) ||
                   std::ranges::any_of(runtime.database.persistent_store.events, [&](auto const& row) {
                       return row.room_id == joined_room;
                   });
        };

        // No room_version means room version 1 (client-server-api.md, m.room.create), not 10.
        WHEN("the create event in its send_join state has no room_version (room version 1)")
        {
            auto const result =
                join_through_resident(send_join_with_create_content(R"({"creator":")" + creator + R"("})"));

            THEN("the join is refused and nothing of the room is stored")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(room_is_stored());
            }
        }

        // A resident server must not choose the rule set by naming one version in make_join and another
        // in the create event.
        WHEN("the create event declares room version 11 while make_join said 10")
        {
            auto const result = join_through_resident(
                send_join_with_create_content(R"({"room_version":"11","creator":")" + creator + R"("})"));

            THEN("the join is refused and nothing of the room is stored")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(room_is_stored());
            }
        }
    }
}
