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
#include "../support/remote_room_fixture.hpp"
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

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
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

// The room fixture, remote-signed event builders and the remote server's key
// live in tests/support/remote_room_fixture.hpp, shared with the worker relay
// signature tests.
using namespace merovingian::tests::remote_room;

[[nodiscard]] auto make_remote_event_pdu(std::string const& room_id, std::string const& type,
                                         std::optional<std::string> const& state_key, std::string const& sender,
                                         merovingian::canonicaljson::Object content,
                                         std::vector<std::string> const& prev_event_ids,
                                         std::vector<std::string> const& auth_event_ids, std::int64_t depth,
                                         std::int64_t ts, std::string_view key_seed = remote_key_seed)
    -> InboundPduEnvelope
{
    auto const signed_json = make_remote_event_json(room_id, type, state_key, sender, std::move(content),
                                                    prev_event_ids, auth_event_ids, depth, ts, key_seed);
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

// Spec: GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}
// Returns the "auth_chain" array of PDUs on success.
[[nodiscard]] auto make_event_auth_response(std::vector<std::string> const& event_jsons) -> std::string
{
    auto auth_chain = merovingian::canonicaljson::Array{};
    for (auto const& json : event_jsons)
    {
        auto parsed = merovingian::canonicaljson::parse_lossless(json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auth_chain.push_back(std::move(parsed.value));
    }
    auto obj = merovingian::canonicaljson::Object{};
    obj.push_back(merovingian::canonicaljson::make_member("auth_chain",
                                                          merovingian::canonicaljson::Value{std::move(auth_chain)}));
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
// Endpoint / Section: Checks performed on receipt of a PDU, step 5
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
//
// A backfilled event is authorised against the state before it, which needs
// its prev_events stored first. The /get_missing_events response order is the
// remote's choice, so a child listed before its parent must still be stored
// once the parent is (0.12.13 audit item 9: results are handled by ascending
// depth, not response order).
SCENARIO("Backfill stores a /get_missing_events child that the remote lists before its parent",
         "[pdu_ingestion][backfill][backfill_depth_order]")
{
    GIVEN("a fresh runtime seeded with a room genesis state group")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-depth-order:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);
        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_id = room_id + ":member";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        auto const parent = make_remote_message_pdu(room_id, {member_id}, auth_event_ids, 3, 10);
        auto const child = make_remote_message_pdu(room_id, {parent.event_id}, auth_event_ids, 4, 11);
        auto const pdu = make_remote_message_pdu(room_id, {child.event_id}, auth_event_ids, 5, 20);

        AND_GIVEN("a sending server whose /get_missing_events lists the child first and serves nothing else")
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

            auto events = canonicaljson::Array{};
            for (auto const* json : {&child.json, &parent.json})
            {
                auto parsed = canonicaljson::parse_lossless(*json);
                REQUIRE(parsed.error == canonicaljson::ParseError::none);
                events.push_back(std::move(parsed.value));
            }
            auto body = canonicaljson::Object{};
            body.push_back(canonicaljson::make_member("events", canonicaljson::Value{std::move(events)}));
            auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(body)});
            REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);

            auto const not_found = merovingian::tests::tls_mock::json_http_response(
                "404 Not Found", R"({"errcode":"M_NOT_FOUND","error":"not found"})");
            auto const responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", serialized.output)},
                {"GET /_matrix/federation/v1/event/", not_found},
                {"GET /_matrix/federation/v1/state_ids/", not_found},
            };
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, responses, nullptr);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("a PDU building on the child is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the PDU is accepted")
                {
                    REQUIRE(result.status == PduIngestionStatus::accepted);
                }

                THEN("both the parent and the child are stored with a state group")
                {
                    auto const& store = runtime.database.persistent_store;
                    REQUIRE(merovingian::database::find_event_state_group(store, parent.event_id).has_value());
                    REQUIRE(merovingian::database::find_event_state_group(store, child.event_id).has_value());
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: GET /_matrix/federation/v1/event/{eventId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1eventeventid
//
// "Retrieves a single event." The response is the origin's claim to be the
// requested event; an event with another ID answers a question nobody asked
// and must not be stored as if it did (it could be anything the origin wants
// pulled into this server's store).
SCENARIO("Backfill drops an /event/{eventId} response that is not the requested event",
         "[pdu_ingestion][backfill][event_id_mismatch]")
{
    GIVEN("a fresh runtime seeded with a room genesis state group")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-event-id-mismatch:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);
        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_id = room_id + ":member";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        auto const missing = make_remote_message_pdu(room_id, {member_id}, auth_event_ids, 3, 10);
        auto const substitute = make_remote_message_pdu(room_id, {member_id}, auth_event_ids, 3, 11);
        REQUIRE(substitute.event_id != missing.event_id);
        auto const pdu = make_remote_message_pdu(room_id, {missing.event_id}, auth_event_ids, 4, 20);

        AND_GIVEN("a sending server that answers /event/{missing} with a different, validly signed event")
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
            runtime.federation.remote_key_resolver = genuine_key_resolver();

            auto const not_found = merovingian::tests::tls_mock::json_http_response(
                "404 Not Found", R"({"errcode":"M_NOT_FOUND","error":"not found"})");
            auto const responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response(
                     "200 OK", make_event_transaction_response(substitute.json, std::string{remote_server}))},
                {"GET /_matrix/federation/v1/state_ids/", not_found},
            };
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, responses, nullptr);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("a PDU naming the missing event is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the substitute event is not stored")
                {
                    REQUIRE(std::ranges::none_of(runtime.database.persistent_store.events,
                                                 [&](merovingian::database::PersistentEvent const& e) {
                                                     return e.event_id == substitute.event_id;
                                                 }));
                }

                THEN("the PDU is not accepted, its prev_event still missing")
                {
                    REQUIRE(result.status != PduIngestionStatus::accepted);
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

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Backfilling and retrieving missing events
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#backfilling-and-retrieving-missing-events
//
// ADR-0064 phase C2 caps bound the size of a /state_ids response the server
// will accept. An oversized pdu_ids list is treated as an unverifiable
// snapshot and the fallback fails closed, leaving the PDU in
// missing_prev_state rather than materialising a potentially malicious state.
SCENARIO("ingest_pdu_event rejects an oversized /state_ids pdu_ids list during backfill",
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

        auto const room_id = std::string{"!backfill-state-ids-oversized:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {old_event_id}, auth_event_ids, 5, 11);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 6, 20);

        AND_GIVEN("a mock sending server that returns a /state_ids response exceeding the pdu_ids cap")
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

            auto oversized_pdu_ids = std::vector<std::string>{};
            oversized_pdu_ids.reserve(1001U);
            for (std::size_t i = 0U; i < 1001U; ++i)
            {
                oversized_pdu_ids.push_back(room_id + ":oversized:" + std::to_string(i));
            }
            auto const state_ids_body = make_state_ids_response(oversized_pdu_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
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

                THEN("the PDU is rejected with missing_prev_state")
                {
                    REQUIRE(result.status == PduIngestionStatus::missing_prev_state);
                }

                THEN("the /state_ids endpoint was still consulted")
                {
                    auto has_state_ids = false;
                    for (auto const& req : captured_requests)
                    {
                        if (req.find("GET /_matrix/federation/v1/state_ids/") != std::string::npos)
                        {
                            has_state_ids = true;
                        }
                    }
                    REQUIRE(has_state_ids);
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
// A /state_ids snapshot is only usable if every named event can be fetched and
// verified. A forged event whose signature does not validate must be dropped
// from the snapshot, causing the fallback to fail closed.
SCENARIO("ingest_pdu_event rejects a /state_ids snapshot containing a forged event",
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

        auto const room_id = std::string{"!backfill-state-ids-forged:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {old_event_id}, auth_event_ids, 5, 11);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 6, 20);

        AND_GIVEN("a mock sending server that returns a /state_ids snapshot with a forged state event")
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

            auto const wrong_seed = std::string{"pdu-backfill-test-forged-wrong-seed"};
            auto forged_pl_content = canonicaljson::Object{};
            forged_pl_content.push_back(canonicaljson::make_member(
                "users", canonicaljson::Value{canonicaljson::Object{canonicaljson::make_member(
                             "@bob:remote.example.org", canonicaljson::Value{std::int64_t{100}})}}));
            auto const forged_pl_pdu =
                make_remote_event_pdu(room_id, "m.room.power_levels", std::string{}, "@bob:remote.example.org",
                                      std::move(forged_pl_content), {pl_id}, auth_event_ids, 4, 10, wrong_seed);
            auto const forged_pl_id = forged_pl_pdu.event_id;

            auto const snapshot_pdu_ids = std::vector<std::string>{create_id, member_bob_id, forged_pl_id};
            auto const state_ids_body = make_state_ids_response(snapshot_pdu_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const forged_pl_body = make_event_transaction_response(forged_pl_pdu.json, remote_server);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", forged_pl_body)                          },
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

                THEN("the PDU is rejected with missing_prev_state")
                {
                    REQUIRE(result.status == PduIngestionStatus::missing_prev_state);
                }

                THEN("the forged snapshot event is not stored")
                {
                    auto const* event = [&]() -> merovingian::database::PersistentEvent const* {
                        for (auto const& e : runtime.database.persistent_store.events)
                        {
                            if (e.event_id == forged_pl_id)
                            {
                                return &e;
                            }
                        }
                        return nullptr;
                    }();
                    REQUIRE(event == nullptr);
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
// A /state_ids snapshot must only contain events that actually belong to the
// room being backfilled. A malicious origin can list an event from a different
// room where it holds power; if the snapshot accepted it, that foreign state
// would become local state. The whole snapshot must be rejected instead.
SCENARIO("ingest_pdu_event rejects a /state_ids snapshot containing an event from a different room",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with two rooms")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_a_id = std::string{"!backfill-state-ids-wrong-room-a:local.example.org"};
        auto const room_b_id = std::string{"!backfill-state-ids-wrong-room-b:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_a_id);
        seed_room_with_genesis_state_group(runtime, room_b_id);

        auto const create_a_id = room_a_id + ":create";
        auto const pl_a_id = room_a_id + ":pl";
        auto const member_bob_a_id = room_a_id + ":member:bob";
        auto const pl_b_id = room_b_id + ":pl";

        auto const auth_event_ids = std::vector<std::string>{create_a_id, pl_a_id, member_bob_a_id};

        auto const old_event = make_remote_message_pdu(room_a_id, {member_bob_a_id}, auth_event_ids, 4, 10);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_a_id, {old_event_id}, auth_event_ids, 5, 11);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_a_id, {mid_event_id}, auth_event_ids, 6, 20);

        AND_GIVEN("a mock sending server that returns a /state_ids snapshot with a foreign-room power_levels event")
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

            // pdu_ids names the foreign room's power_levels event instead of the
            // target room's. All three events are already in the store, so the
            // fallback will not try to fetch them.
            auto const snapshot_pdu_ids = std::vector<std::string>{create_a_id, member_bob_a_id, pl_b_id};
            auto const state_ids_body = make_state_ids_response(snapshot_pdu_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
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

                THEN("the PDU is rejected with missing_prev_state because the snapshot is malformed")
                {
                    REQUIRE(result.status == PduIngestionStatus::missing_prev_state);
                }

                THEN("the foreign-room event was not used as state in room A")
                {
                    auto const group =
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, mid_event_id);
                    REQUIRE(!group.has_value());
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Rejection
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#rejection
//
// A rejected event must never be used as state. A malicious /state_ids
// response can list an event that was previously rejected (for example one
// that failed the state-before check); if the snapshot accepted it, item 1
// would be reopened by another path. The whole snapshot must be rejected.
SCENARIO("ingest_pdu_event rejects a /state_ids snapshot containing a previously rejected event",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with a room that contains a rejected state event")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-state-ids-rejected:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        // Seed a topic event that was previously rejected. Its after-state is
        // the genesis state, so it is mapped to the same state group as the
        // genesis tip.
        auto topic_content = canonicaljson::Object{};
        topic_content.push_back(
            canonicaljson::make_member("topic", canonicaljson::Value{std::string{"rejected topic"}}));
        auto const rejected_topic_json =
            make_remote_event_json(room_id, "m.room.topic", std::string{}, "@bob:remote.example.org",
                                   std::move(topic_content), {pl_id}, auth_event_ids, 4, 10);
        auto const rejected_topic_id =
            merovingian::federation::parse_inbound_pdu_envelope(rejected_topic_json, room_version)->event_id;
        runtime.database.persistent_store.events.push_back({rejected_topic_id,
                                                            room_id,
                                                            "@bob:remote.example.org",
                                                            rejected_topic_json,
                                                            4U,
                                                            0U,
                                                            {pl_id},
                                                            auth_event_ids,
                                                            {},
                                                            "rejected"});
        auto const genesis_group =
            merovingian::database::find_event_state_group(runtime.database.persistent_store, member_bob_id);
        REQUIRE(genesis_group.has_value());
        REQUIRE(merovingian::database::set_event_state_group(runtime.database.persistent_store, rejected_topic_id,
                                                             *genesis_group));

        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {old_event_id}, auth_event_ids, 5, 11);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 6, 20);

        AND_GIVEN("a mock sending server that returns a /state_ids snapshot including the rejected event")
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

            auto const snapshot_pdu_ids = std::vector<std::string>{create_id, pl_id, member_bob_id, rejected_topic_id};
            auto const state_ids_body = make_state_ids_response(snapshot_pdu_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
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

                THEN("the PDU is rejected with missing_prev_state because the snapshot is malformed")
                {
                    REQUIRE(result.status == PduIngestionStatus::missing_prev_state);
                }

                THEN("the rejected event was not used as state for the backfilled event")
                {
                    auto const group =
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, mid_event_id);
                    REQUIRE(!group.has_value());
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
// A /state_ids response is a state map: each (type, state_key) must appear at
// most once. A duplicate entry lets the remote choose which event is kept by
// ordering. The whole response must be rejected instead of silently
// de-duplicating.
SCENARIO("ingest_pdu_event rejects a /state_ids snapshot with duplicate (type, state_key) entries",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with a room that has two power_levels events")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-state-ids-duplicate:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        // Seed a second power_levels event in the same room. Both have the same
        // (type, state_key) tuple, so a /state_ids response listing both is a
        // malformed state map.
        auto second_pl_content = canonicaljson::Object{};
        second_pl_content.push_back(canonicaljson::make_member("state_default", canonicaljson::Value{std::int64_t{0}}));
        auto second_pl_users = canonicaljson::Object{};
        second_pl_users.push_back(
            canonicaljson::make_member("@admin:local.example.org", canonicaljson::Value{std::int64_t{100}}));
        second_pl_content.push_back(
            canonicaljson::make_member("users", canonicaljson::Value{std::move(second_pl_users)}));
        auto const second_pl_json =
            make_remote_event_json(room_id, "m.room.power_levels", std::string{}, "@admin:local.example.org",
                                   std::move(second_pl_content), {pl_id}, auth_event_ids, 4, 10);
        auto const second_pl_id =
            merovingian::federation::parse_inbound_pdu_envelope(second_pl_json, room_version)->event_id;
        runtime.database.persistent_store.events.push_back({second_pl_id,
                                                            room_id,
                                                            "@admin:local.example.org",
                                                            second_pl_json,
                                                            4U,
                                                            0U,
                                                            {pl_id},
                                                            auth_event_ids,
                                                            {},
                                                            "accepted"});
        auto const genesis_group =
            merovingian::database::find_event_state_group(runtime.database.persistent_store, member_bob_id);
        REQUIRE(genesis_group.has_value());
        REQUIRE(merovingian::database::set_event_state_group(runtime.database.persistent_store, second_pl_id,
                                                             *genesis_group));

        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 5, 11);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {old_event_id}, auth_event_ids, 6, 12);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 7, 20);

        AND_GIVEN("a mock sending server that returns a /state_ids snapshot listing both power_levels events")
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

            auto const snapshot_pdu_ids = std::vector<std::string>{create_id, pl_id, second_pl_id, member_bob_id};
            auto const state_ids_body = make_state_ids_response(snapshot_pdu_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
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

                THEN("the PDU is rejected with missing_prev_state because the snapshot is malformed")
                {
                    REQUIRE(result.status == PduIngestionStatus::missing_prev_state);
                }

                THEN("the backfilled event was not stored from the malformed snapshot")
                {
                    auto const group =
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, mid_event_id);
                    REQUIRE(!group.has_value());
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
// A /state_ids response is a state map and must only name state events. A
// non-state entry is malformed and must cause the whole response to be
// rejected, not silently skipped.
SCENARIO("ingest_pdu_event rejects a /state_ids snapshot containing a non-state event",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with a room that has a non-state outlier")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-state-ids-nonstate:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        // Seed a non-state (message) event that has been stored as an outlier
        // with a state group, so the snapshot builder finds it in the store.
        auto const outlier_message_json = make_remote_message_json(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const outlier_message_id =
            merovingian::federation::parse_inbound_pdu_envelope(outlier_message_json, room_version)->event_id;
        runtime.database.persistent_store.events.push_back({outlier_message_id,
                                                            room_id,
                                                            "@bob:remote.example.org",
                                                            outlier_message_json,
                                                            4U,
                                                            0U,
                                                            {member_bob_id},
                                                            auth_event_ids,
                                                            {},
                                                            "outlier"});
        auto const genesis_group =
            merovingian::database::find_event_state_group(runtime.database.persistent_store, member_bob_id);
        REQUIRE(genesis_group.has_value());
        REQUIRE(merovingian::database::set_event_state_group(runtime.database.persistent_store, outlier_message_id,
                                                             *genesis_group));

        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 5, 11);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {old_event_id}, auth_event_ids, 6, 12);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 7, 20);

        AND_GIVEN("a mock sending server that returns a /state_ids snapshot including the non-state event")
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

            auto const snapshot_pdu_ids = std::vector<std::string>{create_id, pl_id, member_bob_id, outlier_message_id};
            auto const state_ids_body = make_state_ids_response(snapshot_pdu_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
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

                THEN("the PDU is rejected with missing_prev_state because the snapshot is malformed")
                {
                    REQUIRE(result.status == PduIngestionStatus::missing_prev_state);
                }

                THEN("the backfilled event was not stored from the malformed snapshot")
                {
                    auto const group =
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, mid_event_id);
                    REQUIRE(!group.has_value());
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
// ADR-0069: when a /state_ids snapshot names a historical state event whose
// prev_events have no recorded state groups, the fallback must still be able
// to verify and store that state event. It does so by batch-fetching the
// event's auth chain via /event_auth, verifying the state event as an outlier
// against that chain, and using the verified state as the snapshot for the
// missing target event.
SCENARIO("ingest_pdu_event verifies a /state_ids snapshot state event via /event_auth when its prev_events have no "
         "state groups",
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

        auto const room_id = std::string{"!backfill-state-ids-event-auth:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_id = room_id + ":member";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        // `old_event` is missing and has no recorded state group, so a normal
        // /event/{id} fetch for `historical_state` would fail: its prev_event
        // cannot supply a state-before. The /event_auth path supplies the auth
        // chain needed to verify `historical_state` as an outlier anyway.
        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const old_event_id = old_event.event_id;

        auto historical_state_content = canonicaljson::Object{};
        historical_state_content.push_back(
            canonicaljson::make_member("topic", canonicaljson::Value{std::string{"historical topic"}}));
        auto const historical_state_pdu =
            make_remote_event_pdu(room_id, "m.room.topic", std::string{}, "@bob:remote.example.org",
                                  std::move(historical_state_content), {old_event_id}, auth_event_ids, 5, 11);
        auto const historical_state_id = historical_state_pdu.event_id;

        auto const mid_event = make_remote_message_pdu(room_id, {historical_state_id}, auth_event_ids, 6, 12);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 7, 20);

        AND_GIVEN("a mock sending server that returns /state_ids, the snapshot state event, and /event_auth for it")
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

            // The auth chain for the snapshot state event is the genesis state
            // events, which are already in the store. Returning them here proves
            // the /event_auth path is being used.
            auto const lookup_json = [&](std::string const& id) -> std::string {
                for (auto const& e : runtime.database.persistent_store.events)
                {
                    if (e.event_id == id)
                    {
                        return e.json;
                    }
                }
                return id + ":json";
            };
            auto const genesis_auth_chain =
                std::vector<std::string>{lookup_json(create_id), lookup_json(pl_id), lookup_json(member_bob_id)};
            // /state_ids returns the complete resolved state at the target event,
            // not just the single state event that changed. The auth_chain is the
            // chain needed to authenticate those state events.
            auto const snapshot_pdu_ids =
                std::vector<std::string>{create_id, pl_id, member_bob_id, historical_state_id};
            auto const state_ids_body = make_state_ids_response(snapshot_pdu_ids, auth_event_ids);
            auto const historical_state_body =
                make_event_transaction_response(historical_state_pdu.json, remote_server);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const event_auth_body = make_event_auth_response(genesis_auth_chain);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", historical_state_body)                   },
                {"GET /_matrix/federation/v1/event_auth/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", event_auth_body)                         },
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

                // ADR-0070: an event verified only against its own auth_events
                // has no known state-before, so no after-state may be recorded
                // for it. It stays a true outlier.
                THEN("the snapshot state event is stored as an outlier with no recorded state group")
                {
                    auto const* event = [&]() -> merovingian::database::PersistentEvent const* {
                        for (auto const& e : runtime.database.persistent_store.events)
                        {
                            if (e.event_id == historical_state_id)
                            {
                                return &e;
                            }
                        }
                        return nullptr;
                    }();
                    REQUIRE(event != nullptr);
                    REQUIRE(event->status == "outlier");
                    REQUIRE_FALSE(merovingian::database::find_event_state_group(runtime.database.persistent_store,
                                                                                historical_state_id)
                                      .has_value());
                }

                THEN("the backfilled target event is stored as an outlier with a state group")
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

                THEN("/event_auth was called for the snapshot state event")
                {
                    auto has_event_auth = false;
                    for (auto const& req : captured_requests)
                    {
                        if (req.find("GET /_matrix/federation/v1/event_auth/") != std::string::npos)
                        {
                            has_event_auth = true;
                        }
                    }
                    REQUIRE(has_event_auth);
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Checks performed on receipt of a PDU (signatures)
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
//
// Every event taken from a remote server is checked before it is used. An
// event may skip that only when it is the very event already stored, not
// merely one whose "event_id" field names a stored event: the field is the
// origin's to write, and from room v3 an event's ID is its reference hash.
SCENARIO("An /event_auth entry reusing a stored event's ID with different content is verified, not trusted",
         "[pdu_ingestion][backfill][event_auth_forged_id]")
{
    GIVEN("a fresh runtime seeded with a room genesis state group")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-event-auth-forged-id:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_id = room_id + ":member";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        // `old_event` is missing and has no recorded state group, so a normal
        // /event/{id} fetch for `historical_state` would fail: its prev_event
        // cannot supply a state-before. The /event_auth path supplies the auth
        // chain needed to verify `historical_state` as an outlier anyway.
        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const old_event_id = old_event.event_id;

        auto historical_state_content = canonicaljson::Object{};
        historical_state_content.push_back(
            canonicaljson::make_member("topic", canonicaljson::Value{std::string{"historical topic"}}));
        auto const historical_state_pdu =
            make_remote_event_pdu(room_id, "m.room.topic", std::string{}, "@bob:remote.example.org",
                                  std::move(historical_state_content), {old_event_id}, auth_event_ids, 5, 11);
        auto const historical_state_id = historical_state_pdu.event_id;

        auto const mid_event = make_remote_message_pdu(room_id, {historical_state_id}, auth_event_ids, 6, 12);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 7, 20);

        AND_GIVEN("a mock sending server that returns /state_ids, the snapshot state event, and /event_auth for it")
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

            // The auth chain for the snapshot state event is the genesis state
            // events, which are already in the store. Returning them here proves
            // the /event_auth path is being used.
            auto const lookup_json = [&](std::string const& id) -> std::string {
                for (auto const& e : runtime.database.persistent_store.events)
                {
                    if (e.event_id == id)
                    {
                        return e.json;
                    }
                }
                return id + ":json";
            };
            // The chain's copy of Bob's membership keeps the stored event's
            // "event_id" but not its content: it turns the join into a ban, a
            // field the signature covers, so its signature no longer verifies.
            // Only an event identical to the stored one may skip verification.
            auto forged_member_bob = lookup_json(member_bob_id);
            auto const membership_at = forged_member_bob.find(R"("membership":"join")");
            REQUIRE(membership_at != std::string::npos);
            forged_member_bob.replace(membership_at, std::string_view{R"("membership":"join")"}.size(),
                                      R"("membership":"ban")");
            auto const genesis_auth_chain =
                std::vector<std::string>{lookup_json(create_id), lookup_json(pl_id), forged_member_bob};
            // /state_ids returns the complete resolved state at the target event,
            // not just the single state event that changed. The auth_chain is the
            // chain needed to authenticate those state events.
            auto const snapshot_pdu_ids =
                std::vector<std::string>{create_id, pl_id, member_bob_id, historical_state_id};
            auto const state_ids_body = make_state_ids_response(snapshot_pdu_ids, auth_event_ids);
            auto const historical_state_body =
                make_event_transaction_response(historical_state_pdu.json, remote_server);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const event_auth_body = make_event_auth_response(genesis_auth_chain);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", historical_state_body)                   },
                {"GET /_matrix/federation/v1/event_auth/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", event_auth_body)                         },
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

                THEN("the snapshot is refused, so the PDU is not accepted")
                {
                    REQUIRE(result.status != PduIngestionStatus::accepted);
                }

                THEN("the snapshot state event is not stored")
                {
                    REQUIRE(std::ranges::none_of(runtime.database.persistent_store.events,
                                                 [&](merovingian::database::PersistentEvent const& e) {
                                                     return e.event_id == historical_state_id;
                                                 }));
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// ADR-0070: an event stored through the /event_auth path was checked against
// its own auth_events only; the state before it is unknown. A later PDU that
// names it as a prev_event must therefore not inherit a state built from that
// event's auth_events. Spec: server-server-api.md, "Checks performed on receipt
// of a PDU", step 5 — the PDU must pass auth against the state before it, which
// is the state after its prev_events.
SCENARIO("ingest_pdu_event does not authorise a PDU against the auth_events of an /event_auth outlier",
         "[pdu_ingestion][backfill][event_auth_outlier]")
{
    GIVEN("a runtime that has stored a /state_ids snapshot state event through the /event_auth path")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-event-auth-outlier:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto historical_state_content = canonicaljson::Object{};
        historical_state_content.push_back(
            canonicaljson::make_member("topic", canonicaljson::Value{std::string{"historical topic"}}));
        auto const historical_state_pdu =
            make_remote_event_pdu(room_id, "m.room.topic", std::string{}, "@bob:remote.example.org",
                                  std::move(historical_state_content), {old_event.event_id}, auth_event_ids, 5, 11);
        auto const historical_state_id = historical_state_pdu.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {historical_state_id}, auth_event_ids, 6, 12);
        auto const first_pdu = make_remote_message_pdu(room_id, {mid_event.event_id}, auth_event_ids, 7, 20);

        // A second PDU whose only prev_event is the /event_auth outlier.
        auto const second_pdu = make_remote_message_pdu(room_id, {historical_state_id}, auth_event_ids, 6, 30);

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

        auto const lookup_json = [&](std::string const& id) -> std::string {
            for (auto const& e : runtime.database.persistent_store.events)
            {
                if (e.event_id == id)
                {
                    return e.json;
                }
            }
            return id + ":json";
        };
        auto const genesis_auth_chain =
            std::vector<std::string>{lookup_json(create_id), lookup_json(pl_id), lookup_json(member_bob_id)};
        using merovingian::tests::tls_mock::json_http_response;
        using PathResponses = std::vector<std::pair<std::string, std::string>>;
        auto const ok = [](std::string const& body) {
            return json_http_response("200 OK", body);
        };
        auto const not_found = json_http_response("404 Not Found", R"({"errcode":"M_NOT_FOUND","error":"not found"})");
        // Serves `responses` for exactly one ingestion, then joins the mock so
        // `requests` is read on this thread only after the mock has finished.
        auto const ingest_with_origin = [&](InboundPduEnvelope const& pdu, PathResponses const& responses,
                                            std::vector<std::string>& requests) {
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, responses, &requests);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;
            return merovingian::homeserver::ingest_pdu_event(runtime, pdu);
        };
        auto const count_requests = [](std::vector<std::string> const& requests, std::string_view prefix) {
            return static_cast<std::size_t>(std::ranges::count_if(requests, [&](std::string const& req) {
                return req.find(prefix) != std::string::npos;
            }));
        };

        auto const snapshot_with_outlier_body = make_state_ids_response(
            std::vector<std::string>{create_id, pl_id, member_bob_id, historical_state_id}, auth_event_ids);
        auto const historical_state_body = make_event_transaction_response(historical_state_pdu.json, remote_server);
        auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);

        auto first_requests = std::vector<std::string>{};
        auto const first_result = ingest_with_origin(
            first_pdu,
            PathResponses{
                {"POST /_matrix/federation/v1/get_missing_events/", ok(make_empty_get_missing_events_response())    },
                {"GET /_matrix/federation/v1/event/",               ok(mid_event_body)                              },
                {"GET /_matrix/federation/v1/state_ids/",           ok(snapshot_with_outlier_body)                  },
                {"GET /_matrix/federation/v1/event/",               ok(historical_state_body)                       },
                {"GET /_matrix/federation/v1/event_auth/",          ok(make_event_auth_response(genesis_auth_chain))},
                {"GET /_matrix/federation/v1/event/",               ok(mid_event_body)                              },
        },
            first_requests);
        REQUIRE(first_result.status == PduIngestionStatus::accepted);
        REQUIRE(count_requests(first_requests, "GET /_matrix/federation/v1/event_auth/") == 1U);

        WHEN("a PDU naming that outlier as its only prev_event is ingested and the origin cannot supply its state")
        {
            auto requests = std::vector<std::string>{};
            auto const result = ingest_with_origin(second_pdu,
                                                   PathResponses{
                                                       {"POST /_matrix/federation/v1/get_missing_events/", not_found},
                                                       {"GET /_matrix/federation/v1/event/",               not_found},
                                                       {"GET /_matrix/federation/v1/state_ids/",           not_found},
            },
                                                   requests);

            THEN("the PDU is held for missing state rather than accepted on the outlier's auth_events")
            {
                REQUIRE(result.status == PduIngestionStatus::missing_prev_state);
            }

            THEN("the server asked the origin for the state at the outlier")
            {
                REQUIRE(count_requests(requests, "GET /_matrix/federation/v1/state_ids/") == 1U);
            }
        }

        WHEN("a PDU naming that outlier as its only prev_event is ingested and the origin supplies its state")
        {
            // The state before the topic event: the genesis state.
            auto const state_before_outlier_body =
                make_state_ids_response(std::vector<std::string>{create_id, pl_id, member_bob_id}, auth_event_ids);
            auto requests = std::vector<std::string>{};
            auto const result = ingest_with_origin(
                second_pdu,
                PathResponses{
                    {"POST /_matrix/federation/v1/get_missing_events/", ok(make_empty_get_missing_events_response())},
                    {"GET /_matrix/federation/v1/event/",               ok(historical_state_body)                   },
                    {"GET /_matrix/federation/v1/state_ids/",           ok(state_before_outlier_body)               },
                    {"GET /_matrix/federation/v1/event/",               ok(historical_state_body)                   },
            },
                requests);

            THEN("the PDU is accepted")
            {
                REQUIRE(result.status == PduIngestionStatus::accepted);
            }

            THEN("the outlier now has a recorded state group")
            {
                REQUIRE(merovingian::database::find_event_state_group(runtime.database.persistent_store,
                                                                      historical_state_id)
                            .has_value());
            }
        }

        WHEN("a later /state_ids snapshot names the stored outlier again")
        {
            auto const later_mid_event = make_remote_message_pdu(room_id, {historical_state_id}, auth_event_ids, 6, 40);
            auto const third_pdu = make_remote_message_pdu(room_id, {later_mid_event.event_id}, auth_event_ids, 7, 41);
            auto const later_mid_body = make_event_transaction_response(later_mid_event.json, remote_server);
            auto requests = std::vector<std::string>{};
            auto const result = ingest_with_origin(
                third_pdu,
                PathResponses{
                    {"POST /_matrix/federation/v1/get_missing_events/", ok(make_empty_get_missing_events_response())},
                    {"GET /_matrix/federation/v1/event/",               ok(later_mid_body)                          },
                    {"GET /_matrix/federation/v1/state_ids/",           ok(snapshot_with_outlier_body)              },
                    {"GET /_matrix/federation/v1/event/",               ok(later_mid_body)                          },
            },
                requests);

            THEN("the PDU is accepted")
            {
                REQUIRE(result.status == PduIngestionStatus::accepted);
            }

            THEN("the stored outlier is not fetched or verified through /event_auth again")
            {
                REQUIRE(count_requests(requests, "GET /_matrix/federation/v1/event_auth/") == 0U);
                REQUIRE(requests.size() == 4U);
            }
        }

        std::filesystem::remove(path);
    }
}
