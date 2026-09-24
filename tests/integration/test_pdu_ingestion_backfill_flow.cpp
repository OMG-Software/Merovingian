// SPDX-License-Identifier: GPL-3.0-or-later
//
// ADR-0064 phase C integration test: when an inbound PDU names a prev_event
// this server has never seen, ingest_pdu_event fetches it from the sending
// server via /_matrix/federation/v1/get_missing_events, verifies the
// returned event (content hash, signature, auth), stores it as an outlier
// with a state group, and then accepts the original PDU.
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md — "Backfilling and
// retrieving missing events", "Checks performed on receipt of a PDU".
// Tags: [pdu_ingestion][backfill].

#include "../federation_signing_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

namespace
{

using namespace merovingian;
using merovingian::federation::InboundPduEnvelope;
using merovingian::federation::PduIngestionStatus;
using merovingian::homeserver::HomeserverRuntime;

constexpr auto remote_server = "remote.example.org";
constexpr auto remote_key_id = "ed25519:auto";
constexpr auto remote_key_seed = "pdu-backfill-test-remote-seed";
constexpr auto local_server = "local.example.org";
constexpr auto room_version = "10";

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() / ("merovingian-pdu-backfill-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto config_with_sqlite(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = local_server;

    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();

    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.federation.enabled = true;

    return {server,   merovingian::config::ListenersConfig{},        database,
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
}

// Seeds a room whose genesis (create/power_levels/member) is recorded as both
// current state and an ADR-0064 phase-A state group, matching
// tests/unit/test_pdu_ingestion_state_groups.cpp's fixture.
auto seed_room_with_genesis_state_group(HomeserverRuntime& runtime, std::string const& room_id) -> void
{
    using namespace merovingian;

    auto& store = runtime.database.persistent_store;
    auto& local = runtime.database.rooms;

    store.rooms.push_back({room_id, "@admin:local.example.org"});
    local.push_back({room_id, "@admin:local.example.org", {}, {}, false});

    auto const create_id = room_id + ":create";
    auto const pl_id = room_id + ":pl";
    auto const member_id = room_id + ":member";
    auto const member_bob_id = room_id + ":member:bob";

    auto const make_json = [&](std::string_view type, std::string_view state_key, std::string_view sender,
                               canonicaljson::Object content, std::int64_t depth, std::int64_t ts) -> std::string {
        auto hashes = canonicaljson::Object{};
        hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{std::string{"hash"}}));
        auto obj = canonicaljson::Object{};
        obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{canonicaljson::Array{}}));
        obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
        obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{depth}));
        obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));
        obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{ts}));
        obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{canonicaljson::Array{}}));
        obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{std::string{room_id}}));
        obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{sender}}));
        obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{state_key}}));
        obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{type}}));
        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
        REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
        return serialized.output;
    };

    auto create_content = canonicaljson::Object{};
    create_content.push_back(
        canonicaljson::make_member("creator", canonicaljson::Value{std::string{"@admin:local.example.org"}}));
    create_content.push_back(
        canonicaljson::make_member("room_version", canonicaljson::Value{std::string{room_version}}));
    auto const create_json =
        make_json("m.room.create", "", "@admin:local.example.org", std::move(create_content), 0, 1);
    store.events.push_back({create_id, room_id, "@admin:local.example.org", create_json, 0U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.create", "", create_id});

    auto pl_content = canonicaljson::Object{};
    pl_content.push_back(canonicaljson::make_member("state_default", canonicaljson::Value{std::int64_t{0}}));
    auto pl_users = canonicaljson::Object{};
    pl_users.push_back(canonicaljson::make_member("@admin:local.example.org", canonicaljson::Value{std::int64_t{100}}));
    pl_content.push_back(canonicaljson::make_member("users", canonicaljson::Value{std::move(pl_users)}));
    auto const pl_json = make_json("m.room.power_levels", "", "@admin:local.example.org", std::move(pl_content), 1, 2);
    store.events.push_back({pl_id, room_id, "@admin:local.example.org", pl_json, 1U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.power_levels", "", pl_id});

    auto member_content = canonicaljson::Object{};
    member_content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    auto const member_json = make_json("m.room.member", "@admin:local.example.org", "@admin:local.example.org",
                                       std::move(member_content), 2, 3);
    store.events.push_back({member_id, room_id, "@admin:local.example.org", member_json, 2U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.member", "@admin:local.example.org", member_id});
    store.memberships.push_back({room_id, "@admin:local.example.org", "join", 0U});

    auto member_bob_content = canonicaljson::Object{};
    member_bob_content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    auto const member_bob_json = make_json("m.room.member", "@bob:remote.example.org", "@bob:remote.example.org",
                                           std::move(member_bob_content), 3, 4);
    store.events.push_back({member_bob_id, room_id, "@bob:remote.example.org", member_bob_json, 3U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.member", "@bob:remote.example.org", member_bob_id});
    store.memberships.push_back({room_id, "@bob:remote.example.org", "join", 0U});

    auto const genesis_state = std::vector<database::PersistentStateGroupStateEntry>{
        {"", "m.room.create",       "",                         create_id    },
        {"", "m.room.power_levels", "",                         pl_id        },
        {"", "m.room.member",       "@admin:local.example.org", member_id    },
        {"", "m.room.member",       "@bob:remote.example.org",  member_bob_id},
    };
    auto const group_id =
        database::create_or_reuse_state_group(store, room_id, room_id + ":genesis-group", std::nullopt, genesis_state);
    REQUIRE(group_id.has_value());
    REQUIRE(database::set_event_state_group(store, member_id, *group_id));
    REQUIRE(database::update_forward_extremities(store, room_id, member_id, {}, true));
}

[[nodiscard]] auto make_remote_message_json(std::string const& room_id, std::vector<std::string> const& prev_event_ids,
                                            std::vector<std::string> const& auth_event_ids, std::int64_t depth,
                                            std::int64_t ts) -> std::string
{
    auto prev = canonicaljson::Array{};
    for (auto const& id : prev_event_ids)
    {
        prev.push_back(canonicaljson::Value{id});
    }
    auto auth = canonicaljson::Array{};
    for (auto const& id : auth_event_ids)
    {
        auth.push_back(canonicaljson::Value{id});
    }

    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("msgtype", canonicaljson::Value{std::string{"m.text"}}));
    content.push_back(canonicaljson::make_member("body", canonicaljson::Value{std::string{"backfill test"}}));

    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.message"}}));
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{"@bob:remote.example.org"}}));
    obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{ts}));
    obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{depth}));
    obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{std::move(prev)}));
    obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{std::move(auth)}));

    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);

    return merovingian::federation::test::make_signed_event_json(serialized.output, remote_server, remote_key_id,
                                                                 remote_key_seed, room_version);
}

[[nodiscard]] auto make_remote_message_pdu(std::string const& room_id, std::vector<std::string> const& prev_event_ids,
                                           std::vector<std::string> const& auth_event_ids, std::int64_t depth,
                                           std::int64_t ts) -> InboundPduEnvelope
{
    auto const signed_json = make_remote_message_json(room_id, prev_event_ids, auth_event_ids, depth, ts);
    REQUIRE(!signed_json.empty());
    auto envelope = merovingian::federation::parse_inbound_pdu_envelope(signed_json, room_version);
    REQUIRE(envelope.has_value());
    envelope->origin = remote_server;
    return *envelope;
}

[[nodiscard]] auto remote_runtime() -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = remote_server;
    remote.signing_key = {remote_server, remote_key_id, 0U,
                          merovingian::federation::test::keypair_from_seed(remote_key_seed).public_key};
    remote.discovery.server_name = remote_server;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto get_missing_events_response(std::string const& event_json) -> std::string
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

    auto events = merovingian::canonicaljson::Array{};
    events.push_back(parsed.value);
    auto obj = merovingian::canonicaljson::Object{};
    obj.push_back(
        merovingian::canonicaljson::make_member("events", merovingian::canonicaljson::Value{std::move(events)}));

    auto const serialized =
        merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

// Reads a full HTTP/1.1 request (headers + Content-Length body) from a TLS
// connection so the mock can receive a POST body before responding. The generic
// helpers in tls_mock_server.hpp stop at the header terminator, which is fine
// for GETs but risks a POST client seeing the response before its body is read.
[[nodiscard]] auto read_full_http_request(merovingian::homeserver::TlsConnection& connection) -> std::string
{
    auto buffer = std::array<char, 8192>{};
    auto request = std::string{};
    while (request.find("\r\n\r\n") == std::string::npos)
    {
        auto const n = connection.read(buffer.data(), buffer.size());
        if (n <= 0)
        {
            break;
        }
        request.append(buffer.data(), static_cast<std::size_t>(n));
    }
    auto const header_end = request.find("\r\n\r\n");
    if (header_end == std::string::npos)
    {
        return request;
    }
    auto const content_length_pos = request.find("Content-Length: ");
    if (content_length_pos == std::string::npos)
    {
        return request;
    }
    auto const value_start = content_length_pos + std::string{"Content-Length: "}.size();
    auto const value_end = request.find("\r\n", value_start);
    if (value_end == std::string::npos)
    {
        return request;
    }
    auto length = std::size_t{0U};
    auto const length_text = std::string_view{request}.substr(value_start, value_end - value_start);
    for (auto const ch : length_text)
    {
        if (ch < '0' || ch > '9')
        {
            break;
        }
        length = (length * 10U) + static_cast<std::size_t>(ch - '0');
    }
    auto const body_start = header_end + 4U;
    while (request.size() < body_start + length)
    {
        auto const n = connection.read(buffer.data(), buffer.size());
        if (n <= 0)
        {
            break;
        }
        request.append(buffer.data(), static_cast<std::size_t>(n));
    }
    return request;
}

inline auto run_body_aware_tls_server(merovingian::net::TcpAcceptor& acceptor,
                                      merovingian::homeserver::TlsServerContext& tls_context,
                                      std::string const& http_response,
                                      std::string* captured_request = nullptr) noexcept -> void
{
    auto const client_fd = merovingian::tests::tls_mock::accept_loopback(acceptor, 5000);
    if (client_fd < 0)
    {
        return;
    }
    auto tls_result = merovingian::homeserver::accept_tls_connection(tls_context, client_fd, 5000);
    if (!tls_result.connection.has_value())
    {
        ::close(client_fd);
        return;
    }
    auto& connection = *tls_result.connection;
    auto const request = read_full_http_request(connection);
    if (captured_request != nullptr)
    {
        *captured_request = request;
    }
    std::ignore = connection.write(http_response);
}

} // namespace

SCENARIO("ingest_pdu_event backfills a missing prev_event from the sending server and accepts the PDU",
         "[pdu_ingestion][backfill]")
{
    GIVEN("a fresh runtime seeded with a room genesis state group")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_id = room_id + ":member";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        auto const missing_event = make_remote_message_pdu(room_id, {member_id}, auth_event_ids, 3, 10);
        auto const missing_event_id = missing_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {missing_event_id}, auth_event_ids, 4, 20);

        AND_GIVEN("a mock sending server that returns the missing event on /get_missing_events")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };

            auto captured_request = std::string{};
            auto const response_body = get_missing_events_response(missing_event.json);
            auto const http_response = merovingian::tests::tls_mock::json_http_response("200 OK", response_body);
            auto server_thread = std::thread{[&]() {
                run_body_aware_tls_server(acceptor, tls_context, http_response, &captured_request);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the PDU is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the PDU is accepted")
                {
                    REQUIRE(result.status == PduIngestionStatus::accepted);
                }

                THEN("the missing prev_event is stored as an outlier with a state group")
                {
                    auto const* event = [&]() -> merovingian::database::PersistentEvent const* {
                        for (auto const& e : runtime.database.persistent_store.events)
                        {
                            if (e.event_id == missing_event_id)
                            {
                                return &e;
                            }
                        }
                        return nullptr;
                    }();
                    REQUIRE(event != nullptr);
                    REQUIRE(event->status == "outlier");
                    REQUIRE(merovingian::database::find_event_state_group(runtime.database.persistent_store,
                                                                          missing_event_id)
                                .has_value());
                }

                THEN("the mock server received exactly one /get_missing_events request")
                {
                    REQUIRE(captured_request.find("POST /_matrix/federation/v1/get_missing_events/") !=
                            std::string::npos);
                }
            }

            std::filesystem::remove(path);
        }
    }
}
