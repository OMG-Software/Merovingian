// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{

using RatePolicies = std::unordered_map<std::string, merovingian::http::RateLimitPolicy>;

[[nodiscard]] auto start_with_limits(RatePolicies per_ip = {}, RatePolicies per_user = {}, RatePolicies tier = {})
    -> merovingian::homeserver::ClientServerStartResult
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    merovingian::config::Config config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        std::move(security),
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
    config.client_rate_limits().per_ip = std::move(per_ip);
    config.client_rate_limits().per_user = std::move(per_user);
    config.client_rate_limits().tier = std::move(tier);
    return merovingian::homeserver::start_client_server(config);
}

[[nodiscard]] auto request(merovingian::homeserver::ClientServerRuntime& runtime, std::string target,
                           std::string access_token = {}) -> std::uint16_t
{
    auto req = merovingian::homeserver::LocalHttpRequest{"GET", std::move(target), std::move(access_token), {}};
    req.remote_addr = "192.0.2.44";
    return merovingian::homeserver::handle_client_server_request(runtime, req).response.status;
}

[[nodiscard]] auto access_token(std::string const& body) -> std::string
{
    auto constexpr key = std::string_view{"\"access_token\":\""};
    auto const start = body.find(key);
    REQUIRE(start != std::string::npos);
    auto const begin = start + key.size();
    auto const end = body.find('"', begin);
    REQUIRE(end != std::string::npos);
    return body.substr(begin, end - begin);
}

} // namespace

SCENARIO("HTTP-3 coalesces variable path components into their route bucket", "[security][http][http-3]")
{
    GIVEN("a runtime with operator caps on normalized media and directory route prefixes")
    {
        auto started = start_with_limits({
            {"/_matrix/media/v3/download/{server}/{mediaId}",        {2U, 60U}},
            {"/_matrix/client/v1/media/download/{server}/{mediaId}", {2U, 60U}},
            {"/_matrix/client/v3/directory/room/{roomAlias}",        {2U, 60U}},
        });
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("legacy media IDs, authenticated-media paths, or aliases vary")
        {
            auto const legacy_first = request(runtime, "/_matrix/media/v3/download/example.org/one");
            auto const legacy_second = request(runtime, "/_matrix/media/v3/download/example.org/two");
            auto const legacy_third = request(runtime, "/_matrix/media/v3/download/example.org/three");

            auto const client_first = request(runtime, "/_matrix/client/v1/media/download/example.org/one");
            auto const client_second = request(runtime, "/_matrix/client/v1/media/download/example.org/two");
            auto const client_third = request(runtime, "/_matrix/client/v1/media/download/example.org/three");

            auto const alias_first = request(runtime, "/_matrix/client/v3/directory/room/%23one%3Aexample.org");
            auto const alias_second = request(runtime, "/_matrix/client/v3/directory/room/%23two%3Aexample.org");
            auto const alias_third = request(runtime, "/_matrix/client/v3/directory/room/%23three%3Aexample.org");

            THEN("each route's operator prefix cap applies across every path value")
            {
                CHECK(legacy_first != 429U);
                CHECK(legacy_second != 429U);
                CHECK(legacy_third == 429U);
                CHECK(client_first != 429U);
                CHECK(client_second != 429U);
                CHECK(client_third == 429U);
                CHECK(alias_first != 429U);
                CHECK(alias_second != 429U);
                CHECK(alias_third == 429U);
            }
        }
    }
}

SCENARIO("HTTP-3 coalesces event and user-data parameters while preserving route boundaries",
         "[security][http][http-3]")
{
    GIVEN("a runtime with prefix caps for event mutations, relations, to-device and user account data")
    {
        auto started = start_with_limits({
            {"/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}",                  {2U, 60U}},
            {"/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}",              {2U, 60U}},
            {"/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}",                  {2U, 60U}},
            {"/_matrix/client/v3/rooms/{roomId}/event/{eventId}",                           {2U, 60U}},
            {"/_matrix/client/v1/rooms/{roomId}/relations/{eventId}/{relType}/{eventType}", {2U, 60U}},
            {"/_matrix/client/v3/sendToDevice/{eventType}/{txnId}",                         {2U, 60U}},
            {"/_matrix/client/v3/user/{userId}/account_data/{type}",                        {2U, 60U}},
        });
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the same route is called with distinct event, transaction, state, or data types")
        {
            auto const send_one =
                request(runtime, "/_matrix/client/v3/rooms/%21one%3Aexample.org/send/m.room.message/one");
            auto const send_two =
                request(runtime, "/_matrix/client/v3/rooms/%21two%3Aexample.org/send/m.room.message/two");
            auto const send_three =
                request(runtime, "/_matrix/client/v3/rooms/%21three%3Aexample.org/send/m.room.message/three");

            auto const state_one =
                request(runtime, "/_matrix/client/v3/rooms/%21state%3Aexample.org/state/m.room.name/one");
            auto const state_two =
                request(runtime, "/_matrix/client/v3/rooms/%21state%3Aexample.org/state/m.room.topic/two");
            auto const state_three =
                request(runtime, "/_matrix/client/v3/rooms/%21state%3Aexample.org/state/m.room.avatar/three");

            auto const redact_one =
                request(runtime, "/_matrix/client/v3/rooms/%21redact%3Aexample.org/redact/%24event1/txn1");
            auto const redact_two =
                request(runtime, "/_matrix/client/v3/rooms/%21redact%3Aexample.org/redact/%24event2/txn2");
            auto const redact_three =
                request(runtime, "/_matrix/client/v3/rooms/%21redact%3Aexample.org/redact/%24event3/txn3");

            auto const event_one = request(runtime, "/_matrix/client/v3/rooms/%21event%3Aexample.org/event/%24event1");
            auto const event_two = request(runtime, "/_matrix/client/v3/rooms/%21event%3Aexample.org/event/%24event2");
            auto const event_three =
                request(runtime, "/_matrix/client/v3/rooms/%21event%3Aexample.org/event/%24event3");

            auto const rel_one = request(
                runtime, "/_matrix/client/v1/rooms/%21rel%3Aexample.org/relations/%24e1/m.annotation/m.reaction");
            auto const rel_two = request(
                runtime, "/_matrix/client/v1/rooms/%21rel%3Aexample.org/relations/%24e2/m.annotation/m.reaction");
            auto const rel_three = request(
                runtime, "/_matrix/client/v1/rooms/%21rel%3Aexample.org/relations/%24e3/m.annotation/m.reaction");

            auto const to_device_one = request(runtime, "/_matrix/client/v3/sendToDevice/m.room.encrypted/one");
            auto const to_device_two = request(runtime, "/_matrix/client/v3/sendToDevice/m.room.encrypted/two");
            auto const to_device_three = request(runtime, "/_matrix/client/v3/sendToDevice/m.room.encrypted/three");

            auto const data_one = request(runtime, "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.fav");
            auto const data_two = request(runtime, "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.tag");
            auto const data_three =
                request(runtime, "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.push_rules");

            THEN("each matched route shares a bucket across its variable path components")
            {
                CHECK(send_one != 429U);
                CHECK(send_two != 429U);
                CHECK(send_three == 429U);
                CHECK(state_one != 429U);
                CHECK(state_two != 429U);
                CHECK(state_three == 429U);
                CHECK(redact_one != 429U);
                CHECK(redact_two != 429U);
                CHECK(redact_three == 429U);
                CHECK(event_one != 429U);
                CHECK(event_two != 429U);
                CHECK(event_three == 429U);
                CHECK(rel_one != 429U);
                CHECK(rel_two != 429U);
                CHECK(rel_three == 429U);
                CHECK(to_device_one != 429U);
                CHECK(to_device_two != 429U);
                CHECK(to_device_three == 429U);
                CHECK(data_one != 429U);
                CHECK(data_two != 429U);
                CHECK(data_three == 429U);
            }
        }
    }
}

SCENARIO("HTTP-3 applies a per-user cap across distinct send transaction IDs", "[security][http][http-3][per-user]")
{
    GIVEN("an authenticated user and a per-user policy on the send route template")
    {
        auto started = start_with_limits(
            {
        },
            {{"/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}", {2U, 60U}}});
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registration = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("http3-user", "CorrectHorse7!")});
        REQUIRE(registration.response.status == 200U);
        auto const token = access_token(registration.response.body);

        WHEN("the user sends requests with different transaction IDs and room IDs")
        {
            auto const first =
                request(runtime, "/_matrix/client/v3/rooms/%21one%3Aexample.org/send/m.room.message/one", token);
            auto const second =
                request(runtime, "/_matrix/client/v3/rooms/%21two%3Aexample.org/send/m.room.message/two", token);
            auto const third =
                request(runtime, "/_matrix/client/v3/rooms/%21three%3Aexample.org/send/m.room.message/three", token);

            THEN("the per-user tier uses the same normalized route key")
            {
                REQUIRE(first != 429U);
                REQUIRE(second != 429U);
                REQUIRE(third == 429U);
            }
        }
    }
}

SCENARIO("HTTP-3 puts unmatched targets in one shared bucket and keeps known endpoints separate",
         "[security][http][http-3]")
{
    GIVEN("a runtime with a two-request generic policy and independent static endpoint overrides")
    {
        auto started = start_with_limits(
            {
                {"/_matrix/client/versions",                                   {2U, 60U}},
                {"/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}", {2U, 60U}},
                {"/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}", {2U, 60U}},
        },
            {}, {{"generic", {2U, 60U}}});
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("unmatched paths vary, and send and redact calls alternate")
        {
            auto const unknown_one = request(runtime, "/_matrix/client/v3/mystery/one");
            auto const unknown_two = request(runtime, "/_matrix/client/v3/mystery/two");
            auto const unknown_three = request(runtime, "/_matrix/client/v3/mystery/three");

            auto const versions_one = request(runtime, "/_matrix/client/versions");
            auto const versions_two = request(runtime, "/_matrix/client/versions");
            auto const versions_three = request(runtime, "/_matrix/client/versions");

            auto const send_one = request(runtime, "/_matrix/client/v3/rooms/%21r%3Aexample.org/send/m.room.message/1");
            auto const redact_one = request(runtime, "/_matrix/client/v3/rooms/%21r%3Aexample.org/redact/%24e1/1");
            auto const send_two = request(runtime, "/_matrix/client/v3/rooms/%21r%3Aexample.org/send/m.room.message/2");

            THEN("unknown routes share one cap, while static endpoints keep separate caps")
            {
                CHECK(unknown_one != 429U);
                CHECK(unknown_two != 429U);
                CHECK(unknown_three == 429U);
                CHECK(versions_one != 429U);
                CHECK(versions_two != 429U);
                CHECK(versions_three == 429U);
                CHECK(send_one != 429U);
                CHECK(redact_one != 429U);
                CHECK(send_two != 429U);
            }
        }
    }
}

SCENARIO("HTTP-3 keeps valid room actions separate and coalesces unknown room actions", "[security][http][http-3]")
{
    GIVEN("a generic per-IP tier capped at two requests")
    {
        auto started = start_with_limits(
            {
        },
            {}, {{"generic", {2U, 60U}}});
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("send, state, and unknown room actions vary their identifiers")
        {
            auto const send_one =
                request(runtime, "/_matrix/client/v3/rooms/%21one%3Aexample.org/send/m.room.message/one");
            auto const state_one = request(runtime, "/_matrix/client/v3/rooms/%21one%3Aexample.org/state/m.room.name");
            auto const send_two =
                request(runtime, "/_matrix/client/v3/rooms/%21two%3Aexample.org/send/m.room.message/two");
            auto const state_two = request(runtime, "/_matrix/client/v3/rooms/%21two%3Aexample.org/state/m.room.topic");
            auto const send_three =
                request(runtime, "/_matrix/client/v3/rooms/%21three%3Aexample.org/send/m.room.message/three");
            auto const state_three =
                request(runtime, "/_matrix/client/v3/rooms/%21three%3Aexample.org/state/m.room.avatar");

            auto const unknown_one =
                request(runtime, "/_matrix/client/v3/rooms/%21one%3Aexample.org/future_action/one");
            auto const unknown_two =
                request(runtime, "/_matrix/client/v3/rooms/%21two%3Aexample.org/another_unknown/two");
            auto const unknown_three =
                request(runtime, "/_matrix/client/v3/rooms/%21three%3Aexample.org/third_unknown/three");

            THEN("each known action owns its cap and all unknown actions use one shared fallback bucket")
            {
                CHECK(send_one != 429U);
                CHECK(send_two != 429U);
                CHECK(send_three == 429U);
                CHECK(state_one != 429U);
                CHECK(state_two != 429U);
                CHECK(state_three == 429U);
                CHECK(unknown_one != 429U);
                CHECK(unknown_two != 429U);
                CHECK(unknown_three == 429U);
            }
        }
    }
}

SCENARIO("HTTP-3 keeps the built-in device-key cap on each E2EE key route in its own bucket",
         "[security][http][http-3][rate-limit]")
{
    GIVEN("a runtime with only the built-in rate limits, which cap /_matrix/client/v3/keys/ at 120 per minute")
    {
        auto started = start_with_limits();
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("one address sends 121 key-claim requests, then one key-upload and one unrelated unknown request")
        {
            auto claim_statuses = std::vector<std::uint16_t>{};
            for (auto attempt = 0U; attempt < 121U; ++attempt)
            {
                claim_statuses.push_back(request(runtime, "/_matrix/client/v3/keys/claim"));
            }
            auto const upload = request(runtime, "/_matrix/client/v3/keys/upload");
            auto const unknown = request(runtime, "/_matrix/client/v3/mystery/route");

            THEN("key claims stop at the built-in cap, while key upload and the fallback keep their own budgets")
            {
                CHECK(std::ranges::none_of(claim_statuses.begin(), claim_statuses.end() - 1, [](std::uint16_t status) {
                    return status == 429U;
                }));
                CHECK(claim_statuses.back() == 429U);
                CHECK(upload != 429U);
                CHECK(unknown != 429U);
            }
        }
    }
}

SCENARIO("HTTP-3 gives every implemented dynamic client route its own coalesced bucket",
         "[security][http][http-3][rate-limit]")
{
    struct RouteCase
    {
        std::string route_template;
        std::string first_path;
        std::string second_path;
    };
    auto const cases = std::vector<RouteCase>{
        {"/_matrix/client/v3/keys/claim",                                           "/_matrix/client/v3/keys/claim",                         "/_matrix/client/v3/keys/claim"                                                  },
        {"/_matrix/client/v3/keys/upload",                                          "/_matrix/client/v3/keys/upload",                        "/_matrix/client/v3/keys/upload"                                                 },
        {"/_matrix/client/v3/room_keys/version/{version}",                          "/_matrix/client/v3/room_keys/version/1",
         "/_matrix/client/v3/room_keys/version/2"                                                                                                                                                                             },
        {"/_matrix/client/v3/room_keys/keys/{roomId}",                              "/_matrix/client/v3/room_keys/keys/%21a%3Aexample.org",
         "/_matrix/client/v3/room_keys/keys/%21b%3Aexample.org"                                                                                                                                                               },
        {"/_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}",
         "/_matrix/client/v3/room_keys/keys/%21a%3Aexample.org/session-one",                                                                 "/_matrix/client/v3/room_keys/keys/%21b%3Aexample.org/session-two"               },
        {"/_matrix/client/v3/rooms/{roomId}/unban",                                 "/_matrix/client/v3/rooms/%21a%3Aexample.org/unban",
         "/_matrix/client/v3/rooms/%21b%3Aexample.org/unban"                                                                                                                                                                  },
        {"/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags",
         "/_matrix/client/v3/user/%40a%3Aexample.org/rooms/%21a%3Aexample.org/tags",                                                         "/_matrix/client/v3/user/%40b%3Aexample.org/rooms/%21b%3Aexample.org/tags"       },
        {"/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}",
         "/_matrix/client/v3/user/%40a%3Aexample.org/rooms/%21a%3Aexample.org/tags/m.favourite",                                             "/_matrix/client/v3/user/%40b%3Aexample.org/rooms/%21b%3Aexample.org/tags/u.work"},
        {"/_matrix/client/v3/presence/{userId}/status",                             "/_matrix/client/v3/presence/%40a%3Aexample.org/status",
         "/_matrix/client/v3/presence/%40b%3Aexample.org/status"                                                                                                                                                              },
        {"/_matrix/client/v3/login/sso/redirect/{idpId}",                           "/_matrix/client/v3/login/sso/redirect/one",
         "/_matrix/client/v3/login/sso/redirect/two"                                                                                                                                                                          },
        {"/_matrix/client/unstable/im.nheko.summary/summary/{roomIdOrAlias}",
         "/_matrix/client/unstable/im.nheko.summary/summary/%21a%3Aexample.org",                                                             "/_matrix/client/unstable/im.nheko.summary/summary/%21b%3Aexample.org"           },
        {"/_matrix/client/unstable/im.nheko.summary/rooms/{roomIdOrAlias}/summary",
         "/_matrix/client/unstable/im.nheko.summary/rooms/%21a%3Aexample.org/summary",                                                       "/_matrix/client/unstable/im.nheko.summary/rooms/%21b%3Aexample.org/summary"     },
    };

    GIVEN("a one-request operator cap keyed on each route template")
    {
        auto policies = RatePolicies{};
        for (auto const& route : cases)
        {
            policies.emplace(route.route_template, merovingian::http::RateLimitPolicy{1U, 60U});
        }
        auto started = start_with_limits(std::move(policies));
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("each route is called twice with different identifiers in its variable segments")
        {
            THEN("the template cap admits the first call and refuses the second, so the route neither falls back "
                 "nor mints a bucket per identifier")
            {
                for (auto const& route : cases)
                {
                    INFO(route.route_template);
                    CHECK(request(runtime, route.first_path) != 429U);
                    CHECK(request(runtime, route.second_path) == 429U);
                }
            }
        }
    }
}

SCENARIO("HTTP-3 applies a built-in prefix cap to a path that normalizes to the shared fallback",
         "[security][http][http-3][rate-limit]")
{
    GIVEN("a runtime with only the built-in rate limits")
    {
        auto started = start_with_limits();
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("one address sends 121 requests to an unrecognised path beneath /_matrix/client/v3/keys/")
        {
            auto statuses = std::vector<std::uint16_t>{};
            for (auto attempt = 0U; attempt < 121U; ++attempt)
            {
                statuses.push_back(request(runtime, "/_matrix/client/v3/keys/not-a-route"));
            }

            THEN("the built-in 120-per-minute keys cap is matched against the original path")
            {
                CHECK(std::ranges::none_of(statuses.begin(), statuses.end() - 1, [](std::uint16_t status) {
                    return status == 429U;
                }));
                CHECK(statuses.back() == 429U);
            }
        }
    }
}

SCENARIO("HTTP-3 bucket eviction keeps recently used buckets and removes the least-recently-used one",
         "[security][http][http-3][rate-limit]")
{
    GIVEN("a small bounded rate-limit engine with a two-request cap")
    {
        struct ManualClock final
        {
            std::chrono::steady_clock::time_point now{};
            [[nodiscard]] auto operator()() const noexcept -> std::chrono::steady_clock::time_point
            {
                return now;
            }
        };
        auto clock = ManualClock{};
        auto config = merovingian::http::default_client_rate_limit_config();
        config.default_per_ip = {2U, 60U};
        auto engine = merovingian::http::RateLimitEngine<ManualClock, 3U>{config, clock};
        CHECK(engine.check("ip-a", "/unknown", {}).allowed);
        CHECK(engine.check("ip-b", "/unknown", {}).allowed);
        CHECK(engine.check("ip-c", "/unknown", {}).allowed);

        WHEN("a bucket is touched before a new key arrives at capacity")
        {
            CHECK(engine.check("ip-a", "/unknown", {}).allowed);
            CHECK(engine.check("ip-d", "/unknown", {}).allowed);

            THEN("the active bucket retains its count and the least-recently-used key is evicted")
            {
                CHECK_FALSE(engine.check("ip-a", "/unknown", {}).allowed);
                CHECK(engine.check("ip-b", "/unknown", {}).allowed);
                CHECK(engine.ip_bucket_count() == 3U);
            }
        }
    }
}
