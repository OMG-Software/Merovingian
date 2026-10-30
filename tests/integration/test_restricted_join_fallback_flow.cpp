// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../federation_signing_test_support.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

// Complement run 12, restricted-room joins (ADR-0287). A restricted room this server is
// resident in, whose only local member has no power to invite, so no user of this server
// can authorise a join (rooms/v10.md 4.3.5.2). A local user who meets an allow condition
// then joins through another resident server: make_join and send_join (server-server-api.md
// "Joining Rooms", "Restricted rooms"). The resident's co-signature is checked like any
// join_authorised_via_users_server (ADR-0171) before the event is stored.
//
// Every scenario drives join_room against a real TLS resident that this process serves.

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <sodium.h>

namespace
{

namespace cj = merovingian::canonicaljson;
namespace tls = merovingian::tests::tls_mock;
using merovingian::homeserver::HomeserverRuntime;

auto constexpr local_server = std::string_view{"local.example.org"};
auto constexpr resident_server = std::string_view{"resident.example.org"};
auto constexpr resident_key_id = std::string_view{"ed25519:auto"};
auto constexpr resident_key_seed = std::string_view{"restricted-join-fallback-resident-seed"};
auto constexpr other_key_seed = std::string_view{"restricted-join-fallback-impostor-seed"};
auto constexpr admin = std::string_view{"@admin:local.example.org"};
auto constexpr resident_user = std::string_view{"@bob:resident.example.org"};
auto constexpr restricted_room = std::string_view{"!r:local.example.org"};
auto constexpr allowed_room = std::string_view{"!a:local.example.org"};

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("merovingian-restricted-fallback-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto fallback_config(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = std::string{local_server};
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.federation.enabled = true;
    merovingian::tests::enable_token_registration(security);
    return {server,   merovingian::config::ListenersConfig{},        database,
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
}

[[nodiscard]] auto event_json(std::string const& room_id, std::string const& type,
                              std::optional<std::string> const& state_key, std::string const& sender,
                              std::string const& content_json, std::vector<std::string> const& prev_event_ids,
                              std::vector<std::string> const& auth_event_ids, std::int64_t depth) -> std::string
{
    auto const content = cj::parse_lossless(content_json);
    REQUIRE(content.error == cj::ParseError::none);
    auto obj = cj::Object{};
    obj.push_back(cj::make_member("type", cj::Value{type}));
    if (state_key.has_value())
    {
        obj.push_back(cj::make_member("state_key", cj::Value{*state_key}));
    }
    obj.push_back(cj::make_member("room_id", cj::Value{room_id}));
    obj.push_back(cj::make_member("sender", cj::Value{sender}));
    obj.push_back(cj::make_member("content", content.value));
    obj.push_back(cj::make_member("origin_server_ts", cj::Value{depth + 100}));
    obj.push_back(cj::make_member("depth", cj::Value{depth}));
    auto prev = cj::Array{};
    for (auto const& id : prev_event_ids)
    {
        prev.push_back(cj::Value{id});
    }
    obj.push_back(cj::make_member("prev_events", cj::Value{std::move(prev)}));
    auto auth = cj::Array{};
    for (auto const& id : auth_event_ids)
    {
        auth.push_back(cj::Value{id});
    }
    obj.push_back(cj::make_member("auth_events", cj::Value{std::move(auth)}));
    auto const hash = merovingian::events::make_content_hash(cj::Value{obj});
    REQUIRE(hash.error.empty());
    auto hashes = cj::Object{};
    hashes.push_back(cj::make_member("sha256", cj::Value{hash.sha256}));
    obj.push_back(cj::make_member("hashes", cj::Value{std::move(hashes)}));
    auto const serialized = cj::serialize_canonical(cj::Value{std::move(obj)});
    REQUIRE(serialized.error == cj::CanonicalJsonError::none);
    return serialized.output;
}

// Stores a state event of a v10 room the way a server holds one it has accepted: the
// event, its current-state row, its state group and its membership row.
auto seed(HomeserverRuntime& runtime, std::string const& room_id, std::string const& event_id, std::string const& type,
          std::optional<std::string> const& state_key, std::string const& sender, std::string const& content_json,
          std::vector<std::string> const& prev_event_ids, std::vector<std::string> const& auth_event_ids,
          std::uint64_t depth) -> void
{
    using namespace merovingian;
    auto const* policy = rooms::find_room_version_policy("10");
    REQUIRE(policy != nullptr);
    auto& store = runtime.database.persistent_store;
    auto const json = event_json(room_id, type, state_key, sender, content_json, prev_event_ids, auth_event_ids,
                                 static_cast<std::int64_t>(depth));
    store.events.push_back({event_id, room_id, sender, json, depth, 0U, prev_event_ids, auth_event_ids, {}});
    if (state_key.has_value())
    {
        store.state.push_back({room_id, type, *state_key, event_id});
    }
    auto const before = homeserver::compute_state_before(store, room_id, *policy, prev_event_ids);
    REQUIRE(before.ok);
    auto const after = homeserver::compute_state_after(before.state, event_id, type, state_key);
    REQUIRE(homeserver::record_event_state(store, room_id, event_id, prev_event_ids, after, true).has_value());
    REQUIRE(homeserver::recompute_current_state(store, room_id, *policy));
    if (type == "m.room.member" && state_key.has_value())
    {
        auto const parsed = canonicaljson::parse_lossless(json);
        store.memberships.push_back(
            {room_id, *state_key, std::string{events::extract_content_membership(parsed.value)}, 0U});
    }
}

struct SeededRoom final
{
    std::string create_id{};
    std::string pl_id{};
    std::string join_rules_id{};
    std::string resident_member_id{};
};

// A v10 room on this server with the local admin joined and a user of the resident server
// joined. `power_levels` decides who may invite.
[[nodiscard]] auto seed_room(HomeserverRuntime& runtime, std::string const& room_id, std::string const& power_levels,
                             std::string const& join_rules) -> SeededRoom
{
    auto const a = std::string{admin};
    auto const r = std::string{resident_user};
    runtime.database.persistent_store.rooms.push_back({room_id, a});
    runtime.database.rooms.push_back({room_id, a, {}, {}, false});
    auto ids = SeededRoom{room_id + "/create", room_id + "/pl", room_id + "/join_rules", room_id + "/resident"};
    auto const admin_member = room_id + "/admin";
    seed(runtime, room_id, ids.create_id, "m.room.create", std::string{}, a,
         R"({"creator":"@admin:local.example.org","room_version":"10"})", {}, {}, 1U);
    seed(runtime, room_id, admin_member, "m.room.member", a, a, R"({"membership":"join"})", {ids.create_id},
         {ids.create_id}, 2U);
    seed(runtime, room_id, ids.pl_id, "m.room.power_levels", std::string{}, a, power_levels, {admin_member},
         {ids.create_id, admin_member}, 3U);
    seed(runtime, room_id, ids.join_rules_id, "m.room.join_rules", std::string{}, a, join_rules, {ids.pl_id},
         {ids.create_id, ids.pl_id, admin_member}, 4U);
    seed(runtime, room_id, ids.resident_member_id, "m.room.member", r, r, R"({"membership":"join"})",
         {ids.join_rules_id}, {ids.create_id, ids.pl_id, ids.join_rules_id}, 5U);
    return ids;
}

[[nodiscard]] auto request_body(std::string const& request) -> std::string
{
    auto const separator = request.find("\r\n\r\n");
    return separator == std::string::npos ? std::string{} : request.substr(separator + 4U);
}

// Reads one HTTP request (headers and Content-Length body) from a TLS connection.
[[nodiscard]] auto read_request(merovingian::homeserver::TlsConnection& connection) -> std::string
{
    auto buffer = std::array<char, 8192>{};
    auto request = std::string{};
    auto expected = std::size_t{0U};
    while (true)
    {
        auto const header_end = request.find("\r\n\r\n");
        if (header_end != std::string::npos)
        {
            if (expected == 0U)
            {
                auto length = std::size_t{0U};
                auto const marker = request.find("Content-Length:");
                if (marker != std::string::npos)
                {
                    auto begin = marker + std::string_view{"Content-Length:"}.size();
                    while (begin < request.size() && request[begin] == ' ')
                    {
                        ++begin;
                    }
                    std::ignore = std::from_chars(request.data() + begin, request.data() + request.size(), length);
                }
                expected = header_end + 4U + length;
            }
            if (request.size() >= expected)
            {
                return request;
            }
        }
        auto const bytes = connection.read(buffer.data(), buffer.size());
        if (bytes <= 0)
        {
            return request;
        }
        request.append(buffer.data(), static_cast<std::size_t>(bytes));
    }
}

// Serves `count` sequential requests as the resident: `respond` maps each raw request to the
// raw HTTP response. Bounded by accept and handshake timeouts, so the thread always ends.
auto serve_resident(merovingian::net::TcpAcceptor& acceptor, merovingian::homeserver::TlsServerContext& context,
                    std::size_t count, std::function<std::string(std::string const&)> const& respond,
                    std::vector<std::string>& captured) -> void
{
    for (auto served = std::size_t{0U}; served < count; ++served)
    {
        auto const client_fd = tls::accept_loopback(acceptor, 5000);
        if (client_fd < 0)
        {
            return;
        }
        auto const owned = merovingian::core::SocketHandle{client_fd};
        auto accepted = merovingian::homeserver::accept_tls_connection(context, client_fd, 5000);
        if (!accepted.connection.has_value())
        {
            continue;
        }
        auto request = read_request(*accepted.connection);
        captured.push_back(request);
        std::ignore = accepted.connection->write(respond(request));
    }
}

// The same event with one more signature, by `server` under `key_id`, made with `seed_text`'s
// key: what a resident does to a join it authorises (server-server-api.md PUT /send_join:
// "the signature must be added before sending or persisting the event to other servers").
[[nodiscard]] auto co_sign(std::string const& event_json_text, std::string_view server, std::string_view key_id,
                           std::string_view seed_text) -> std::string
{
    auto const parsed = cj::parse_lossless(event_json_text);
    REQUIRE(parsed.error == cj::ParseError::none);
    auto const* policy = merovingian::rooms::find_room_version_policy("10");
    REQUIRE(policy != nullptr);
    auto const payload = merovingian::events::make_event_signing_payload(parsed.value, *policy);
    REQUIRE(payload.error == cj::CanonicalJsonError::none);
    auto const keypair = merovingian::federation::test::keypair_from_seed(seed_text);
    auto signature = std::array<unsigned char, crypto_sign_BYTES>{};
    crypto_sign_detached(signature.data(), nullptr, reinterpret_cast<unsigned char const*>(payload.output.data()),
                         payload.output.size(), reinterpret_cast<unsigned char const*>(keypair.secret_key.data()));
    auto const encoded = merovingian::events::matrix_base64_from_bytes(
        {reinterpret_cast<char const*>(signature.data()), signature.size()});
    auto const attached =
        merovingian::events::attach_event_signature(parsed.value, {std::string{server}, std::string{key_id}}, encoded);
    REQUIRE(attached.error == cj::CanonicalJsonError::none);
    return attached.output;
}

[[nodiscard]] auto make_join_response(std::string const& user, SeededRoom const& room) -> std::string
{
    auto const event = std::string{R"({"type":"m.room.member","state_key":")"} + user + R"(","room_id":")" +
                       std::string{restricted_room} + R"(","sender":")" + user +
                       R"(","depth":6,"origin_server_ts":1000,"prev_events":[")" + room.resident_member_id +
                       R"("],"auth_events":[")" + room.create_id + R"(",")" + room.pl_id + R"(",")" +
                       room.join_rules_id + R"(",")" + room.resident_member_id +
                       R"("],"content":{"join_authorised_via_users_server":")" + std::string{resident_user} +
                       R"(","membership":"join"}})";
    return tls::json_http_response("200 OK", std::string{R"({"room_version":"10","event":)"} + event + "}");
}

[[nodiscard]] auto send_join_response(std::string const& signed_event) -> std::string
{
    return tls::json_http_response("200 OK",
                                   std::string{R"({"auth_chain":[],"event":)"} + signed_event + R"(,"state":[]})");
}

} // namespace

// Spec: server-server-api.md "Restricted rooms" — "The resident server uses a 400
// `M_UNABLE_TO_GRANT_JOIN` error on `/make_join` and `/send_join` to denote that the joining
// server should try a different server. This is typically because the resident server can see
// that the joining user satisfies one of the conditions, though the resident server would be
// unable to meet the auth rules governing `join_authorised_via_users_server`." The same
// server, joining its own user to a room it is resident in, is the joining server of that
// sentence. "Joining Rooms": make_join, then send_join, to a resident. ADR-0287.
SCENARIO("A local user who meets a condition joins through another resident when no local user can authorise it",
         "[homeserver][federation][join][restricted_join][fallback][adr-0287][integration]")
{
    GIVEN("a restricted room whose only local member cannot invite, a user who meets its condition, and one who "
          "does not")
    {
        REQUIRE(sodium_init() >= 0);
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(fallback_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const carol_reg = merovingian::homeserver::register_local_user(runtime, "carol", "CorrectHorse7!",
                                                                            merovingian::tests::registration_token);
        REQUIRE(carol_reg.ok);
        auto const carol_login =
            merovingian::homeserver::login_local_user(runtime, carol_reg.value, "CorrectHorse7!", "CAROL1");
        REQUIRE(carol_login.ok);
        auto const dave_reg = merovingian::homeserver::register_local_user(runtime, "dave", "CorrectHorse7!",
                                                                           merovingian::tests::registration_token);
        REQUIRE(dave_reg.ok);
        auto const dave_login =
            merovingian::homeserver::login_local_user(runtime, dave_reg.value, "CorrectHorse7!", "DAVE1");
        REQUIRE(dave_login.ok);

        // The allowed room: this server is resident (the admin is joined), carol is joined, dave is not.
        auto const allowed = seed_room(runtime, std::string{allowed_room},
                                       R"({"users":{"@admin:local.example.org":100}})", R"({"join_rule":"public"})");
        seed(runtime, std::string{allowed_room}, "!a/carol", "m.room.member", carol_reg.value, carol_reg.value,
             R"({"membership":"join"})", {allowed.resident_member_id},
             {allowed.create_id, allowed.pl_id, allowed.join_rules_id}, 6U);
        // The restricted room: inviting needs 50; only the resident server's user has that.
        auto const room = seed_room(
            runtime, std::string{restricted_room},
            R"({"invite":50,"users":{"@admin:local.example.org":0,"@bob:resident.example.org":100}})",
            R"({"allow":[{"room_id":"!a:local.example.org","type":"m.room_membership"}],"join_rule":"restricted"})");

        auto const certificate = tls::write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);
        runtime.test_forced_outbound_resolution[std::string{resident_server}] =
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
            auto remote = merovingian::federation::FederationRemoteRuntime{};
            remote.server_name = std::string{resident_server};
            remote.signing_key = {std::string{resident_server}, std::string{resident_key_id}, 4'102'444'800'000U,
                                  merovingian::federation::test::keypair_from_seed(resident_key_seed).public_key};
            remote.discovery.server_name = std::string{resident_server};
            remote.trust.reputation_score = 100U;
            return remote;
        };

        auto const joined = [&](std::string const& user) {
            auto const lock = std::lock_guard{runtime.mutex};
            return std::ranges::any_of(runtime.database.persistent_store.memberships, [&](auto const& membership) {
                return membership.room_id == restricted_room && membership.user_id == user &&
                       membership.membership == "join";
            });
        };

        WHEN("the user who meets the condition joins, and the resident authorises and co-signs the join")
        {
            auto captured = std::vector<std::string>{};
            auto const responder = [&](std::string const& request) {
                if (request.find("/make_join/") != std::string::npos)
                {
                    return make_join_response(carol_reg.value, room);
                }
                // Co-sign the join exactly as it was submitted.
                return send_join_response(
                    co_sign(request_body(request), resident_server, resident_key_id, resident_key_seed));
            };
            auto server = std::thread{[&] {
                serve_resident(acceptor, *tls_context.context, 2U, responder, captured);
            }};
            auto const joiner = tls::ScopedThreadJoin{server};
            auto const result = merovingian::homeserver::join_room(
                runtime, carol_login.value, std::string{restricted_room}, {std::string{resident_server}});
            server.join();

            THEN("the join succeeds, after a make_join and a send_join to the resident")
            {
                CAPTURE(result.reason);
                REQUIRE(result.ok);
                REQUIRE(captured.size() == 2U);
                REQUIRE(captured[0].find("/make_join/") != std::string::npos);
                REQUIRE(captured[1].find("/send_join/") != std::string::npos);
            }

            THEN("the user is joined, and the stored join names the resident's user as its authoriser")
            {
                REQUIRE(joined(carol_reg.value));
                auto const lock = std::lock_guard{runtime.mutex};
                auto const& store = runtime.database.persistent_store;
                auto const state = std::ranges::find_if(store.state, [&](auto const& row) {
                    return row.room_id == restricted_room && row.event_type == "m.room.member" &&
                           row.state_key == carol_reg.value;
                });
                REQUIRE(state != store.state.end());
                auto const event = store.events.find(state->event_id);
                REQUIRE(event != store.events.end());
                REQUIRE(event->json.find(R"("join_authorised_via_users_server":"@bob:resident.example.org")") !=
                        std::string::npos);
                // The stored copy is the co-signed one.
                REQUIRE(event->json.find(R"("resident.example.org":{"ed25519:auto")") != std::string::npos);
            }
        }

        WHEN("an event giving the local admin the power to invite is being applied when the join arrives")
        {
            // ADR-0288: ingestion applies a received event under the room's stripe mutex. Hold it as
            // that event's ingestion does, and let the join run into it.
            auto const stripe = std::hash<std::string>{}(std::string{restricted_room}) %
                                merovingian::homeserver::room_mutex_stripe_count;
            auto in_flight = std::unique_lock{runtime.room_stripe_mutexes[stripe]};
            auto result = merovingian::homeserver::OperationResult{};
            auto joiner = std::thread{[&] {
                result = merovingian::homeserver::join_room(runtime, carol_login.value, std::string{restricted_room},
                                                            {std::string{resident_server}});
            }};
            auto const waiting = [&] {
                for (auto attempt = 0; attempt < 500; ++attempt)
                {
                    {
                        auto const lock = std::lock_guard{runtime.mutex};
                        if (runtime.membership_exchanges.contains({std::string{restricted_room}, carol_reg.value}))
                        {
                            return true;
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds{10});
                }
                return false;
            }();
            // The event is applied: the admin may now invite.
            {
                auto const lock = std::lock_guard{runtime.mutex};
                auto& store = runtime.database.persistent_store;
                auto const row = store.events.find(room.pl_id);
                REQUIRE(row != store.events.end());
                store.events.modify(row, [](merovingian::database::PersistentEvent& event) {
                    auto const at = event.json.find(R"("@admin:local.example.org":0)");
                    REQUIRE(at != std::string::npos);
                    event.json.replace(at + std::string_view{R"("@admin:local.example.org":)"}.size(), 1U, "100");
                });
            }
            in_flight.unlock();
            joiner.join();

            THEN("the join is decided after it: a local user authorises it and no other server is asked")
            {
                CAPTURE(result.reason);
                REQUIRE(waiting);
                REQUIRE(result.ok);
                REQUIRE(joined(carol_reg.value));
                REQUIRE(tls::accept_loopback(acceptor, 0) < 0);
                auto const lock = std::lock_guard{runtime.mutex};
                auto const& store = runtime.database.persistent_store;
                auto const state = std::ranges::find_if(store.state, [&](auto const& row) {
                    return row.room_id == restricted_room && row.event_type == "m.room.member" &&
                           row.state_key == carol_reg.value;
                });
                REQUIRE(state != store.state.end());
                auto const event = store.events.find(state->event_id);
                REQUIRE(event != store.events.end());
                REQUIRE(event->json.find(R"("join_authorised_via_users_server":"@admin:local.example.org")") !=
                        std::string::npos);
            }
        }

        WHEN("a user who meets no condition joins")
        {
            auto const result = merovingian::homeserver::join_room(
                runtime, dave_login.value, std::string{restricted_room}, {std::string{resident_server}});

            THEN("the join is refused with 403, no other server was asked, and the user is not joined")
            {
                CAPTURE(result.reason);
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 403U);
                // A connection attempt would be waiting in the listener's backlog.
                REQUIRE(tls::accept_loopback(acceptor, 0) < 0);
                REQUIRE_FALSE(joined(dave_reg.value));
            }
        }

        WHEN("the resident answers the make_join with a refusal")
        {
            auto captured = std::vector<std::string>{};
            auto const responder = [&](std::string const&) {
                return tls::json_http_response("403 Forbidden", R"({"errcode":"M_FORBIDDEN","error":"no"})");
            };
            auto server = std::thread{[&] {
                serve_resident(acceptor, *tls_context.context, 1U, responder, captured);
            }};
            auto const joiner = tls::ScopedThreadJoin{server};
            auto const result = merovingian::homeserver::join_room(
                runtime, carol_login.value, std::string{restricted_room}, {std::string{resident_server}});
            server.join();

            THEN("the client gets the refusal and the user is not joined")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 403U);
                REQUIRE(captured.size() == 1U);
                REQUIRE_FALSE(joined(carol_reg.value));
            }
        }

        WHEN("the resident returns the join without its co-signature, or with one that does not verify")
        {
            auto const forgery = GENERATE(as<std::string>{}, "no signature", "wrong key");
            auto captured = std::vector<std::string>{};
            auto const responder = [&](std::string const& request) {
                if (request.find("/make_join/") != std::string::npos)
                {
                    return make_join_response(carol_reg.value, room);
                }
                if (forgery == "no signature")
                {
                    return send_join_response(request_body(request));
                }
                return send_join_response(
                    co_sign(request_body(request), resident_server, resident_key_id, other_key_seed));
            };
            auto server = std::thread{[&] {
                serve_resident(acceptor, *tls_context.context, 2U, responder, captured);
            }};
            auto const joiner = tls::ScopedThreadJoin{server};
            auto const result = merovingian::homeserver::join_room(
                runtime, carol_login.value, std::string{restricted_room}, {std::string{resident_server}});
            server.join();

            THEN("the join is not accepted, nothing is stored for it, and the user is not joined")
            {
                CAPTURE(forgery, result.reason);
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(joined(carol_reg.value));
                auto const lock = std::lock_guard{runtime.mutex};
                REQUIRE_FALSE(std::ranges::any_of(runtime.database.persistent_store.events, [&](auto const& event) {
                    return event.room_id == restricted_room && event.sender_user_id == carol_reg.value;
                }));
            }
        }

        WHEN("the resident returns a different join event from the one it was sent")
        {
            auto captured = std::vector<std::string>{};
            auto const responder = [&](std::string const& request) {
                if (request.find("/make_join/") != std::string::npos)
                {
                    return make_join_response(carol_reg.value, room);
                }
                // The same join with another depth: depth is kept by redaction, so this is another
                // event with another event ID (rooms/v10.md "Event IDs"), whoever signs it.
                auto altered = request_body(request);
                auto const at = altered.find(R"("depth":6)");
                REQUIRE(at != std::string::npos);
                altered.replace(at, std::string_view{R"("depth":6)"}.size(), R"("depth":7)");
                return send_join_response(co_sign(altered, resident_server, resident_key_id, resident_key_seed));
            };
            auto server = std::thread{[&] {
                serve_resident(acceptor, *tls_context.context, 2U, responder, captured);
            }};
            auto const joiner = tls::ScopedThreadJoin{server};
            auto const result = merovingian::homeserver::join_room(
                runtime, carol_login.value, std::string{restricted_room}, {std::string{resident_server}});
            server.join();

            THEN("the join is not accepted and the user is not joined")
            {
                CAPTURE(result.reason);
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(joined(carol_reg.value));
            }
        }

        WHEN("the resident changes a field of the join that its signature does not cover")
        {
            // The join's display name is not kept by redaction, so the resident's signature and the
            // reference-hash event ID are the same whatever it says (rooms/v10.md 4.2.1, "Event IDs").
            {
                auto const lock = std::lock_guard{runtime.mutex};
                REQUIRE(merovingian::database::store_profile(runtime.database.persistent_store,
                                                             {carol_reg.value, "Carol", {}}));
            }
            auto captured = std::vector<std::string>{};
            auto const responder = [&](std::string const& request) {
                if (request.find("/make_join/") != std::string::npos)
                {
                    return make_join_response(carol_reg.value, room);
                }
                auto altered = request_body(request);
                auto const at = altered.find(R"("displayname":"Carol")");
                REQUIRE(at != std::string::npos);
                altered.replace(at, std::string_view{R"("displayname":"Carol")"}.size(), R"("displayname":"Mallory")");
                return send_join_response(co_sign(altered, resident_server, resident_key_id, resident_key_seed));
            };
            auto server = std::thread{[&] {
                serve_resident(acceptor, *tls_context.context, 2U, responder, captured);
            }};
            auto const joiner = tls::ScopedThreadJoin{server};
            auto const result = merovingian::homeserver::join_room(
                runtime, carol_login.value, std::string{restricted_room}, {std::string{resident_server}});
            server.join();

            THEN("the join stored is this server's own, with the resident's co-signature added to it")
            {
                CAPTURE(result.reason);
                REQUIRE(result.ok);
                REQUIRE(joined(carol_reg.value));
                auto const lock = std::lock_guard{runtime.mutex};
                auto const& store = runtime.database.persistent_store;
                auto const state = std::ranges::find_if(store.state, [&](auto const& row) {
                    return row.room_id == restricted_room && row.event_type == "m.room.member" &&
                           row.state_key == carol_reg.value;
                });
                REQUIRE(state != store.state.end());
                auto const event = store.events.find(state->event_id);
                REQUIRE(event != store.events.end());
                CAPTURE(event->json);
                REQUIRE(event->json.find(R"("displayname":"Carol")") != std::string::npos);
                REQUIRE(event->json.find("Mallory") == std::string::npos);
                REQUIRE(event->json.find(R"("resident.example.org":{"ed25519:auto")") != std::string::npos);
                REQUIRE(event->json.find(R"("local.example.org":{")") != std::string::npos);
                REQUIRE(event->status == "accepted");
            }
        }

        WHEN("the co-signed join reached this server by another path before the resident answered the send_join")
        {
            auto captured = std::vector<std::string>{};
            auto const responder = [&](std::string const& request) {
                if (request.find("/make_join/") != std::string::npos)
                {
                    return make_join_response(carol_reg.value, room);
                }
                auto const cosigned =
                    co_sign(request_body(request), resident_server, resident_key_id, resident_key_seed);
                // The resident also sends the join to this server in a transaction (PUT /send).
                auto arrived = merovingian::federation::parse_inbound_pdu_envelope(cosigned, "10");
                REQUIRE(arrived.has_value());
                arrived->origin = std::string{resident_server};
                auto const earlier = runtime.federation.pdu_sink(*arrived);
                REQUIRE(earlier.status == merovingian::federation::PduIngestionStatus::accepted);
                return send_join_response(cosigned);
            };
            auto server = std::thread{[&] {
                serve_resident(acceptor, *tls_context.context, 2U, responder, captured);
            }};
            auto const joiner = tls::ScopedThreadJoin{server};
            auto const result = merovingian::homeserver::join_room(
                runtime, carol_login.value, std::string{restricted_room}, {std::string{resident_server}});
            server.join();

            THEN("the join succeeds: the user is joined by the copy that arrived first")
            {
                CAPTURE(result.reason);
                REQUIRE(result.ok);
                REQUIRE(joined(carol_reg.value));
            }
        }

        WHEN("the join's event ID is already stored but it did not make the user a member")
        {
            auto captured = std::vector<std::string>{};
            auto const responder = [&](std::string const& request) {
                if (request.find("/make_join/") != std::string::npos)
                {
                    return make_join_response(carol_reg.value, room);
                }
                // An earlier copy of the join was stored as an outlier: it has an event row, and no
                // state, so it produced no membership.
                auto const submitted = cj::parse_lossless(request_body(request));
                auto const* policy = merovingian::rooms::find_room_version_policy("10");
                REQUIRE(policy != nullptr);
                auto const id = merovingian::events::make_reference_hash_event_id(submitted.value, *policy);
                REQUIRE(id.error.empty());
                {
                    auto const lock = std::lock_guard{runtime.mutex};
                    auto row = merovingian::database::PersistentEvent{};
                    row.event_id = id.event_id;
                    row.room_id = std::string{restricted_room};
                    row.sender_user_id = carol_reg.value;
                    row.json = request_body(request);
                    row.depth = 6U;
                    row.status = "outlier";
                    runtime.database.persistent_store.events.push_back(std::move(row));
                }
                return send_join_response(
                    co_sign(request_body(request), resident_server, resident_key_id, resident_key_seed));
            };
            auto server = std::thread{[&] {
                serve_resident(acceptor, *tls_context.context, 2U, responder, captured);
            }};
            auto const joiner = tls::ScopedThreadJoin{server};
            auto const result = merovingian::homeserver::join_room(
                runtime, carol_login.value, std::string{restricted_room}, {std::string{resident_server}});
            server.join();

            THEN("the join is not reported as done and the user is not joined")
            {
                CAPTURE(result.reason);
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(joined(carol_reg.value));
            }
        }

        std::filesystem::remove(path);
    }
}
