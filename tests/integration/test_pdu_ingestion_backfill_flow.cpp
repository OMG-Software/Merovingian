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
#include <utility>
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
    REQUIRE(database::set_event_state_group(store, create_id, *group_id));
    REQUIRE(database::set_event_state_group(store, pl_id, *group_id));
    REQUIRE(database::set_event_state_group(store, member_id, *group_id));
    REQUIRE(database::set_event_state_group(store, member_bob_id, *group_id));
    REQUIRE(database::update_forward_extremities(store, room_id, member_id, {}, true));
}

[[nodiscard]] auto make_remote_event_json(std::string const& room_id, std::string const& type,
                                          std::optional<std::string> const& state_key, std::string const& sender,
                                          merovingian::canonicaljson::Object content,
                                          std::vector<std::string> const& prev_event_ids,
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

    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{type}));
    if (state_key.has_value())
    {
        obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{*state_key}));
    }
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{sender}));
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

[[nodiscard]] auto make_remote_message_json(std::string const& room_id, std::vector<std::string> const& prev_event_ids,
                                            std::vector<std::string> const& auth_event_ids, std::int64_t depth,
                                            std::int64_t ts) -> std::string
{
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("msgtype", canonicaljson::Value{std::string{"m.text"}}));
    content.push_back(canonicaljson::make_member("body", canonicaljson::Value{std::string{"backfill test"}}));
    return make_remote_event_json(room_id, "m.room.message", std::nullopt, "@bob:remote.example.org",
                                  std::move(content), prev_event_ids, auth_event_ids, depth, ts);
}

[[nodiscard]] auto make_remote_event_pdu(std::string const& room_id, std::string const& type,
                                         std::optional<std::string> const& state_key, std::string const& sender,
                                         merovingian::canonicaljson::Object content,
                                         std::vector<std::string> const& prev_event_ids,
                                         std::vector<std::string> const& auth_event_ids, std::int64_t depth,
                                         std::int64_t ts) -> InboundPduEnvelope
{
    auto const signed_json = make_remote_event_json(room_id, type, state_key, sender, std::move(content),
                                                    prev_event_ids, auth_event_ids, depth, ts);
    REQUIRE(!signed_json.empty());
    auto envelope = merovingian::federation::parse_inbound_pdu_envelope(signed_json, room_version);
    REQUIRE(envelope.has_value());
    envelope->origin = remote_server;
    return *envelope;
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

// Seeds a restrictive power_levels event accepted into the room, making it the
// new forward extremity and current state. Used to construct a state-before
// that is stricter than the permissive genesis power_levels.
auto seed_strict_power_levels(HomeserverRuntime& runtime, std::string const& room_id,
                              std::string const& /*permissive_pl_id*/, std::string const& prev_event_id) -> std::string
{
    using namespace merovingian;

    auto& store = runtime.database.persistent_store;
    auto* policy = rooms::find_room_version_policy(room_version);
    REQUIRE(policy != nullptr);

    auto const strict_pl_id = room_id + ":strict-pl";
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("state_default", canonicaljson::Value{std::int64_t{100}}));
    auto users = canonicaljson::Object{};
    users.push_back(canonicaljson::make_member("@admin:local.example.org", canonicaljson::Value{std::int64_t{100}}));
    content.push_back(canonicaljson::make_member("users", canonicaljson::Value{std::move(users)}));

    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.power_levels"}}));
    obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{}}));
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{"@admin:local.example.org"}}));
    obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{std::int64_t{5}}));
    obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{std::int64_t{4}}));
    auto prev = canonicaljson::Array{};
    prev.push_back(canonicaljson::Value{prev_event_id});
    obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{std::move(prev)}));
    obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{canonicaljson::Array{}}));
    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{std::string{"hash"}}));
    obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);

    store.events.push_back(
        {strict_pl_id, room_id, "@admin:local.example.org", serialized.output, 4U, 0U, {prev_event_id}, {}, {}});
    store.state.push_back({room_id, "m.room.power_levels", "", strict_pl_id});

    auto const state_before = homeserver::compute_state_before(store, room_id, *policy, {prev_event_id});
    REQUIRE(state_before.ok);
    auto const state_after = homeserver::compute_state_after(state_before.state, strict_pl_id, "m.room.power_levels",
                                                             std::optional<std::string>{std::string{}});
    auto const group = homeserver::record_event_state(store, room_id, strict_pl_id, {prev_event_id}, state_after, true);
    REQUIRE(group.has_value());
    REQUIRE(homeserver::recompute_current_state(store, room_id, *policy));
    return strict_pl_id;
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

// Multi-request body-aware TLS server. Dispatches each received request to the
// first unused response whose path substring appears in the request bytes. This
// variant reads the full request (headers + Content-Length body) so POSTs such
// as /get_missing_events are handled correctly.
inline auto run_body_aware_dispatch_tls_server(merovingian::net::TcpAcceptor& acceptor,
                                               merovingian::homeserver::TlsServerContext& tls_context,
                                               std::vector<std::pair<std::string, std::string>> const& path_responses,
                                               std::vector<std::string>* captured_requests = nullptr) noexcept -> void
{
    auto served = std::vector<bool>(path_responses.size(), false);
    for (auto iteration = std::size_t{0U}; iteration < path_responses.size(); ++iteration)
    {
        auto const client_fd = merovingian::tests::tls_mock::accept_loopback(acceptor, 10000);
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
        auto const request = read_full_http_request(connection);
        if (captured_requests != nullptr)
        {
            captured_requests->push_back(request);
        }
        auto chosen = path_responses.size();
        for (auto index = std::size_t{0U}; index < path_responses.size(); ++index)
        {
            if (!served[index] && request.find(path_responses[index].first) != std::string::npos)
            {
                chosen = index;
                break;
            }
        }
        if (chosen == path_responses.size())
        {
            for (auto index = std::size_t{0U}; index < path_responses.size(); ++index)
            {
                if (!served[index])
                {
                    chosen = index;
                    break;
                }
            }
        }
        if (chosen == path_responses.size())
        {
            std::ignore = connection.write(path_responses.front().second);
            continue;
        }
        served[chosen] = true;
        std::ignore = connection.write(path_responses[chosen].second);
    }
}

[[nodiscard]] auto make_empty_get_missing_events_response() -> std::string
{
    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("events", canonicaljson::Value{canonicaljson::Array{}}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

[[nodiscard]] auto make_state_ids_response(std::vector<std::string> const& pdu_ids,
                                           std::vector<std::string> const& auth_chain_ids) -> std::string
{
    auto pdu_array = canonicaljson::Array{};
    for (auto const& id : pdu_ids)
    {
        pdu_array.push_back(canonicaljson::Value{id});
    }
    auto auth_array = canonicaljson::Array{};
    for (auto const& id : auth_chain_ids)
    {
        auth_array.push_back(canonicaljson::Value{id});
    }
    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("auth_chain_ids", canonicaljson::Value{std::move(auth_array)}));
    obj.push_back(canonicaljson::make_member("pdu_ids", canonicaljson::Value{std::move(pdu_array)}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

[[nodiscard]] auto make_event_transaction_response(std::string const& event_json, std::string const& origin)
    -> std::string
{
    auto parsed = merovingian::canonicaljson::parse_lossless(event_json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto pdus = merovingian::canonicaljson::Array{};
    pdus.push_back(std::move(parsed.value));
    auto obj = merovingian::canonicaljson::Object{};
    obj.push_back(merovingian::canonicaljson::make_member("origin", merovingian::canonicaljson::Value{origin}));
    obj.push_back(merovingian::canonicaljson::make_member("origin_server_ts",
                                                          merovingian::canonicaljson::Value{std::int64_t{0}}));
    obj.push_back(merovingian::canonicaljson::make_member("pdus", merovingian::canonicaljson::Value{std::move(pdus)}));
    auto const serialized =
        merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
    return serialized.output;
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

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Checks performed on receipt of a PDU, step 5
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
//
// "Passes authorisation rules based on the state before the event, otherwise
// it is rejected." A backfilled event (fetched as a missing prev_event) must
// run the same step-5 check as a directly received PDU. If it passes its own
// auth_events but fails against the state before it, it must be stored as
// rejected and its after-state must exclude the event, so later PDUs that
// reference it do not see its state.
SCENARIO("A backfilled event passing its auth_events but failing state-before is stored rejected",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with a permissive genesis and a strict power_levels tip")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-state-before:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);
        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const strict_pl_id = seed_strict_power_levels(runtime, room_id, pl_id, member_bob_id);

        // Bob's topic names the old permissive power_levels in auth_events,
        // which is a permitted selection, but its prev_event is the strict tip,
        // so the state immediately before it requires power 100.
        auto topic_content = canonicaljson::Object{};
        topic_content.push_back(canonicaljson::make_member("topic", canonicaljson::Value{std::string{"forged topic"}}));
        auto const topic_pdu =
            make_remote_event_pdu(room_id, "m.room.topic", std::string{}, "@bob:remote.example.org",
                                  std::move(topic_content), {strict_pl_id}, {create_id, pl_id, member_bob_id}, 5, 10);
        auto const topic_id = topic_pdu.event_id;

        auto const followup_pdu =
            make_remote_message_pdu(room_id, {topic_id}, {create_id, strict_pl_id, member_bob_id}, 6, 20);

        AND_GIVEN("a mock sending server that returns the topic event on /get_missing_events")
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

            auto const response_body = get_missing_events_response(topic_pdu.json);
            auto const http_response = merovingian::tests::tls_mock::json_http_response("200 OK", response_body);
            auto server_thread = std::thread{[&]() {
                run_body_aware_tls_server(acceptor, tls_context, http_response, nullptr);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the follow-up PDU referencing the missing topic is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, followup_pdu);

                THEN("the follow-up PDU is accepted")
                {
                    REQUIRE(result.status == PduIngestionStatus::accepted);
                }

                THEN("the backfilled topic is stored, marked rejected")
                {
                    auto const* event = [&]() -> merovingian::database::PersistentEvent const* {
                        for (auto const& e : runtime.database.persistent_store.events)
                        {
                            if (e.event_id == topic_id)
                            {
                                return &e;
                            }
                        }
                        return nullptr;
                    }();
                    REQUIRE(event != nullptr);
                    REQUIRE(event->status == "rejected");
                }

                THEN("the rejected topic's after-state group excludes the topic")
                {
                    auto const group =
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, topic_id);
                    REQUIRE(group.has_value());
                    auto const full_state =
                        merovingian::database::read_state_group_full_state(runtime.database.persistent_store, *group);
                    REQUIRE(full_state.has_value());
                    REQUIRE(std::ranges::none_of(*full_state,
                                                 [&](merovingian::database::PersistentStateGroupStateEntry const& e) {
                                                     return e.event_type == "m.room.topic";
                                                 }));
                }

                THEN("the follow-up PDU does not see the rejected topic in current state")
                {
                    auto const& state = runtime.database.persistent_store.state;
                    REQUIRE(std::ranges::none_of(state, [&](merovingian::database::PersistentStateEvent const& s) {
                        return s.room_id == room_id && s.event_type == "m.room.topic";
                    }));
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Checks performed on receipt of a PDU, steps 4 and 5
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
//
// A backfilled event that passes both its own auth_events and the state before
// it is stored as an outlier whose after-state includes it, so it can supply
// state to later events that reference it.
SCENARIO("A backfilled state event passing auth_events and state-before is stored with its after-state",
         "[pdu_ingestion][backfill]")
{
    GIVEN("a fresh runtime seeded with a permissive genesis")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-accepted-state:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);
        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";

        auto topic_content = canonicaljson::Object{};
        topic_content.push_back(
            canonicaljson::make_member("topic", canonicaljson::Value{std::string{"backfilled topic"}}));
        auto const topic_pdu =
            make_remote_event_pdu(room_id, "m.room.topic", std::string{}, "@bob:remote.example.org",
                                  std::move(topic_content), {pl_id}, {create_id, pl_id, member_bob_id}, 4, 10);
        auto const topic_id = topic_pdu.event_id;

        auto const followup_pdu =
            make_remote_message_pdu(room_id, {topic_id}, {create_id, pl_id, member_bob_id}, 5, 20);

        AND_GIVEN("a mock sending server that returns the topic event on /get_missing_events")
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

            auto const response_body = get_missing_events_response(topic_pdu.json);
            auto const http_response = merovingian::tests::tls_mock::json_http_response("200 OK", response_body);
            auto server_thread = std::thread{[&]() {
                run_body_aware_tls_server(acceptor, tls_context, http_response, nullptr);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the follow-up PDU referencing the missing topic is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, followup_pdu);

                THEN("the follow-up PDU is accepted")
                {
                    REQUIRE(result.status == PduIngestionStatus::accepted);
                }

                THEN("the backfilled topic is stored as an outlier")
                {
                    auto const* event = [&]() -> merovingian::database::PersistentEvent const* {
                        for (auto const& e : runtime.database.persistent_store.events)
                        {
                            if (e.event_id == topic_id)
                            {
                                return &e;
                            }
                        }
                        return nullptr;
                    }();
                    REQUIRE(event != nullptr);
                    REQUIRE(event->status == "outlier");
                }

                THEN("the outlier's after-state group includes the topic")
                {
                    auto const group =
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, topic_id);
                    REQUIRE(group.has_value());
                    auto const full_state =
                        merovingian::database::read_state_group_full_state(runtime.database.persistent_store, *group);
                    REQUIRE(full_state.has_value());
                    auto const topic_entry = std::ranges::find_if(
                        *full_state, [](merovingian::database::PersistentStateGroupStateEntry const& e) {
                            return e.event_type == "m.room.topic";
                        });
                    REQUIRE(topic_entry != full_state->end());
                    REQUIRE(topic_entry->event_id == topic_id);
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Backfilling and retrieving missing events
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#backfilling-and-retrieving-missing-events
//
// When /get_missing_events cannot fill the gap, the server falls back to
// /state_ids to obtain the state at the missing prev_event, fetches and
// verifies the named state events, and stores the missing event with an
// after-state group derived from the verified snapshot.
SCENARIO("ingest_pdu_event falls back to /state_ids when /get_missing_events cannot fill the gap",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with a room genesis state group")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-state-ids:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_id = room_id + ":member";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        // `old` is missing and unreachable, so `mid` cannot be verified through
        // the normal /event/{id} path. The /state_ids fallback supplies the
        // state before `mid` directly from the verified genesis snapshot.
        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {old_event_id}, auth_event_ids, 5, 11);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 6, 20);

        AND_GIVEN("a mock sending server that returns /state_ids for the missing prev_event")
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

            auto const state_ids_body = make_state_ids_response(auth_event_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            // The first /event/{id} fetch tries to store `mid` directly and
            // fails because `mid`'s own prev_event has no state group. The
            // /state_ids fallback then fetches `mid` a second time and stores
            // it against the verified snapshot. Both fetches need a response.
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
            };
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, path_responses, &captured_requests);
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

                THEN("the backfilled prev_event is stored as an outlier with a state group")
                {
                    auto const* event = [&]() -> merovingian::database::PersistentEvent const* {
                        for (auto const& e : runtime.database.persistent_store.events)
                        {
                            if (e.event_id == mid_event_id)
                            {
                                return &e;
                            }
                        }
                        return nullptr;
                    }();
                    REQUIRE(event != nullptr);
                    REQUIRE(event->status == "outlier");
                    REQUIRE(
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, mid_event_id)
                            .has_value());
                }

                THEN("all three fallback endpoints were called")
                {
                    auto has_get_missing = false;
                    auto has_state_ids = false;
                    auto has_event = false;
                    for (auto const& req : captured_requests)
                    {
                        if (req.find("POST /_matrix/federation/v1/get_missing_events/") != std::string::npos)
                        {
                            has_get_missing = true;
                        }
                        if (req.find("GET /_matrix/federation/v1/state_ids/") != std::string::npos)
                        {
                            has_state_ids = true;
                        }
                        if (req.find("GET /_matrix/federation/v1/event/") != std::string::npos)
                        {
                            has_event = true;
                        }
                    }
                    REQUIRE(has_get_missing);
                    REQUIRE(has_state_ids);
                    REQUIRE(has_event);
                }
            }

            std::filesystem::remove(path);
        }
    }
}
