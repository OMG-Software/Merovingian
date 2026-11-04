// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// G5 (ADR-0504, ADR-0505, ADR-0506): the operator account and review routes under /_merovingian/admin.
// These are choices of this server, not Matrix spec, so they are integration tests and not conformance tests.
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/sqlite_insert_fault.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/observability/observability.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{

using merovingian::homeserver::ClientServerRuntime;
using merovingian::homeserver::LocalHttpRequest;

constexpr auto password = std::string_view{"CorrectHorse7!"};
constexpr auto alice_path = std::string_view{"/_merovingian/admin/accounts/%40alice%3Aexample.org"};

[[nodiscard]] auto make_config(std::unordered_map<std::string, merovingian::http::RateLimitPolicy> per_ip = {},
                               std::unordered_map<std::string, merovingian::http::RateLimitPolicy> tier = {},
                               merovingian::config::DatabaseConfig database =
                                   merovingian::tests::in_memory_database_config()) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        std::move(database),
        std::move(security),
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
    config.client_rate_limits().per_ip = std::move(per_ip);
    config.client_rate_limits().tier = std::move(tier);
    return config;
}

[[nodiscard]] auto send(ClientServerRuntime& runtime, std::string method, std::string target, std::string token = {},
                        std::string body = {}) -> merovingian::homeserver::LocalHttpResponse
{
    auto req = LocalHttpRequest{std::move(method), std::move(target), std::move(token), std::move(body)};
    req.remote_addr = "192.0.2.44";
    return merovingian::homeserver::handle_client_server_request(runtime, req).response;
}

[[nodiscard]] auto login_body(std::string_view localpart, std::string_view device) -> std::string
{
    return std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} +
           std::string{localpart} + R"(:example.org"},"password":")" + std::string{password} + R"(","device_id":")" +
           std::string{device} + R"("})";
}

[[nodiscard]] auto login(ClientServerRuntime& runtime, std::string_view localpart, std::string_view device)
    -> std::string
{
    auto const response = send(runtime, "POST", "/_matrix/client/v3/login", {}, login_body(localpart, device));
    REQUIRE(response.status == 200U);
    auto const body = merovingian::tests::parse_object(response.body);
    auto const* token = merovingian::tests::string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto register_and_login(ClientServerRuntime& runtime, std::string_view localpart) -> std::string
{
    REQUIRE(send(runtime, "POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json(localpart, password))
                .status == 200U);
    return login(runtime, localpart, std::string{localpart} + "_DEV");
}

[[nodiscard]] auto admin_login(ClientServerRuntime& runtime, std::string_view localpart) -> std::string
{
    REQUIRE(
        merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, std::string{localpart}, std::string{password})
            .ok);
    return login(runtime, localpart, std::string{localpart} + "_DEV");
}

struct World final
{
    merovingian::homeserver::ClientServerStartResult started;
    std::string admin;
    std::string ops;
    std::string alice;
    std::string bob;

    [[nodiscard]] auto runtime() -> ClientServerRuntime&
    {
        return started.runtime;
    }
};

[[nodiscard]] auto make_world(merovingian::config::Config config) -> World
{
    auto world = World{merovingian::homeserver::start_client_server(config), {}, {}, {}, {}};
    REQUIRE(world.started.started);
    world.admin = admin_login(world.runtime(), "admin");
    world.ops = admin_login(world.runtime(), "ops");
    world.alice = register_and_login(world.runtime(), "alice");
    world.bob = register_and_login(world.runtime(), "bob");
    return world;
}

[[nodiscard]] auto account_path(std::string_view encoded_user) -> std::string
{
    return "/_merovingian/admin/accounts/" + std::string{encoded_user};
}

[[nodiscard]] auto action_body(std::string_view action) -> std::string
{
    return R"({"action":")" + std::string{action} + R"("})";
}

[[nodiscard]] auto find_user(ClientServerRuntime& runtime, std::string_view user_id)
    -> merovingian::homeserver::LocalUser const*
{
    auto const& users = runtime.homeserver.database.users;
    auto const it = std::ranges::find(users, user_id, &merovingian::homeserver::LocalUser::user_id);
    return it == users.end() ? nullptr : &*it;
}

// The persistent copy of the flags must say what the in-memory copy says.
[[nodiscard]] auto memory_and_store_agree(ClientServerRuntime& runtime, std::string_view user_id) -> bool
{
    auto const* memory = find_user(runtime, user_id);
    auto const& stored = runtime.homeserver.database.persistent_store.users;
    auto const row = std::ranges::find(stored, user_id, &merovingian::database::PersistentUser::user_id);
    return memory != nullptr && row != stored.end() && memory->locked == row->locked &&
           memory->suspended == row->suspended && memory->deactivated == row->deactivated;
}

[[nodiscard]] auto audit_rows(ClientServerRuntime& runtime, std::string_view actor, std::string_view target)
    -> std::vector<merovingian::observability::AuditLogEvent>
{
    auto rows = std::vector<merovingian::observability::AuditLogEvent>{};
    for (auto const& event : runtime.homeserver.database.audit_events)
    {
        if (event.actor == actor && event.target == target)
        {
            rows.push_back(event);
        }
    }
    return rows;
}

[[nodiscard]] auto reason_of(std::vector<merovingian::observability::AuditLogEvent> const& rows,
                             std::string_view reason) -> bool
{
    return std::ranges::any_of(rows, [reason](auto const& row) {
        return row.reason_code == reason;
    });
}

} // namespace

SCENARIO("The server cannot be stopped over HTTP", "[g5][operator-admin]")
{
    GIVEN("a running server and an administrator's token")
    {
        auto world = make_world(make_config());

        WHEN("the administrator posts to the former shutdown route")
        {
            auto const shutdown = send(world.runtime(), "POST", "/_merovingian/admin/shutdown", world.admin);
            auto const shutdown_get = send(world.runtime(), "GET", "/_merovingian/admin/shutdown", world.admin);
            auto const shutdown_unauthenticated = send(world.runtime(), "POST", "/_merovingian/admin/shutdown");

            THEN("it is not found, whatever the method or token, and the server keeps serving")
            {
                REQUIRE(shutdown.status == 404U);
                REQUIRE(shutdown_get.status == 404U);
                REQUIRE(shutdown_unauthenticated.status == 404U);
                REQUIRE(send(world.runtime(), "GET", "/_merovingian/admin/health", world.admin).status == 200U);
                REQUIRE(send(world.runtime(), "GET", "/_matrix/client/v3/account/whoami", world.alice).status == 200U);
            }
        }
    }
}

SCENARIO("Operator routes refuse callers before they reveal anything about an account", "[g5][operator-admin][auth]")
{
    GIVEN("an administrator, two ordinary users and one operator route per method")
    {
        auto world = make_world(make_config());
        struct Route
        {
            std::string method;
            std::string path;
            std::string body;
        };
        auto const real = std::string{"%40bob%3Aexample.org"};
        auto const routes = std::vector<Route>{
            {"GET",  account_path(real),                        {}                 },
            {"POST", account_path(real),                        action_body("lock")},
            {"POST", "/_merovingian/admin/review/media/media1", {}                 },
        };

        WHEN("no token, an unknown token and an ordinary user's token are presented")
        {
            THEN("the answers are 401, 401 and 403 for every route and method")
            {
                for (auto const& route : routes)
                {
                    INFO(route.method << ' ' << route.path);
                    REQUIRE(send(world.runtime(), route.method, route.path, {}, route.body).status == 401U);
                    REQUIRE(send(world.runtime(), route.method, route.path, "not-a-token", route.body).status == 401U);
                    REQUIRE(send(world.runtime(), route.method, route.path, world.alice, route.body).status == 403U);
                }
            }
        }

        WHEN("an ordinary user asks about a real user, an unknown user and a user on another server")
        {
            auto const as_alice = [&](std::string const& method, std::string const& user, std::string const& body) {
                return send(world.runtime(), method, account_path(user), world.alice, body);
            };

            THEN("every question is answered the same way, so nothing is learned about who exists")
            {
                for (auto const* method : {"GET", "POST"})
                {
                    auto const body = std::string{method} == "POST" ? action_body("lock") : std::string{};
                    auto const real_answer = as_alice(method, real, body);
                    auto const unknown_answer = as_alice(method, "%40nobody%3Aexample.org", body);
                    auto const remote_answer = as_alice(method, "%40bob%3Aelsewhere.example", body);
                    auto const garbage_answer = as_alice(method, "not-a-user", body);
                    REQUIRE(real_answer.status == 403U);
                    REQUIRE(unknown_answer.status == real_answer.status);
                    REQUIRE(unknown_answer.body == real_answer.body);
                    REQUIRE(remote_answer.status == real_answer.status);
                    REQUIRE(remote_answer.body == real_answer.body);
                    REQUIRE(garbage_answer.status == real_answer.status);
                    REQUIRE(garbage_answer.body == real_answer.body);
                }
                REQUIRE_FALSE(find_user(world.runtime(), "@bob:example.org")->locked);
            }
        }
    }
}

SCENARIO("An administrator reads an account summary that holds no credential", "[g5][operator-admin][summary]")
{
    GIVEN("an administrator and a user with two devices")
    {
        auto world = make_world(make_config());
        std::ignore = login(world.runtime(), "alice", "SECOND");
        auto const alice_hash = find_user(world.runtime(), "@alice:example.org")->password_hash;

        WHEN("the administrator asks for the summary of that user")
        {
            auto const response = send(world.runtime(), "GET", std::string{alice_path}, world.admin);

            THEN("it states the flags and the device count and carries no hash and no token")
            {
                REQUIRE(response.status == 200U);
                auto const body = merovingian::tests::parse_object(response.body);
                REQUIRE(*merovingian::tests::bool_member(body, "deactivated") == false);
                REQUIRE(*merovingian::tests::bool_member(body, "locked") == false);
                REQUIRE(*merovingian::tests::bool_member(body, "suspended") == false);
                REQUIRE(*merovingian::tests::bool_member(body, "admin") == false);
                // Registration opens a device too: count what the store holds for the user.
                auto const stored_devices =
                    std::ranges::count(world.runtime().homeserver.database.persistent_store.devices,
                                       "@alice:example.org", &merovingian::database::PersistentDevice::user_id);
                REQUIRE(stored_devices >= 2);
                REQUIRE(*merovingian::tests::int_member(body, "devices") == stored_devices);
                REQUIRE(response.body.find(alice_hash) == std::string::npos);
                REQUIRE(response.body.find(world.alice) == std::string::npos);
                REQUIRE(response.body.find("hash") == std::string::npos);
                REQUIRE(response.body.find("token") == std::string::npos);
                REQUIRE(response.body.find("password") == std::string::npos);
            }
        }

        WHEN("the administrator asks for the summary of the administrator's own account")
        {
            auto const response = send(world.runtime(), "GET", account_path("%40admin%3Aexample.org"), world.admin);

            THEN("it is allowed and says the account is an administrator's")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*merovingian::tests::bool_member(merovingian::tests::parse_object(response.body), "admin"));
            }
        }
    }
}

SCENARIO("Account routes refuse the targets the lock endpoint refuses", "[g5][operator-admin][guards]")
{
    GIVEN("an administrator, a second administrator and an ordinary user")
    {
        auto world = make_world(make_config());

        WHEN("the target is not a valid user ID, or is not on this server")
        {
            THEN("it is 400, before any lookup")
            {
                for (auto const* user : {"not-a-user", "%40bob%3Aelsewhere.example", "%40%3Aexample.org", "%40nobody"})
                {
                    INFO(user);
                    REQUIRE(send(world.runtime(), "GET", account_path(user), world.admin).status == 400U);
                    REQUIRE(
                        send(world.runtime(), "POST", account_path(user), world.admin, action_body("lock")).status ==
                        400U);
                }
            }
        }

        WHEN("the identifier is encoded twice")
        {
            auto const response = send(world.runtime(), "GET", account_path("%2540bob%253Aexample.org"), world.admin);

            THEN("it is decoded once and so is not a user ID")
            {
                REQUIRE(response.status == 400U);
            }
        }

        WHEN("the target is a local user who does not exist")
        {
            auto const response = send(world.runtime(), "POST", account_path("%40nobody%3Aexample.org"), world.admin,
                                       action_body("lock"));

            THEN("it is 404")
            {
                REQUIRE(response.status == 404U);
            }
        }

        WHEN("the administrator acts on their own account")
        {
            auto const response = send(world.runtime(), "POST", account_path("%40admin%3Aexample.org"), world.admin,
                                       R"({"action":"deactivate","confirm":true})");

            THEN("it is refused and the account is untouched")
            {
                REQUIRE(response.status == 403U);
                REQUIRE_FALSE(find_user(world.runtime(), "@admin:example.org")->deactivated);
                REQUIRE(send(world.runtime(), "GET", "/_merovingian/admin/health", world.admin).status == 200U);
            }
        }

        WHEN("the administrator acts on, or reads, another administrator")
        {
            auto const act =
                send(world.runtime(), "POST", account_path("%40ops%3Aexample.org"), world.admin, action_body("lock"));
            auto const read = send(world.runtime(), "GET", account_path("%40ops%3Aexample.org"), world.admin);

            THEN("both are refused and the other administrator is not locked")
            {
                REQUIRE(act.status == 403U);
                REQUIRE(read.status == 403U);
                REQUIRE_FALSE(find_user(world.runtime(), "@ops:example.org")->locked);
                REQUIRE(audit_rows(world.runtime(), "@admin:example.org", "@ops:example.org").empty());
            }
        }

        WHEN("a percent-encoded identifier names an existing user")
        {
            auto const response =
                send(world.runtime(), "POST", account_path("%40bob%3Aexample.org"), world.admin, action_body("lock"));

            THEN("the decoded user is the one acted on")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(find_user(world.runtime(), "@bob:example.org")->locked);
            }
        }
    }
}

// The dispatcher sends /_merovingian/admin/* to require_admin before the general user-token gate, so the check
// that stops a locked or suspended account on every other route does not run for these: it has to be here.
SCENARIO("A locked or suspended administrator cannot use the operator routes", "[g5][operator-admin][auth]")
{
    GIVEN("an administrator whose account has been locked or suspended, and who still holds a token")
    {
        auto world = make_world(make_config());
        auto const suspended = GENERATE(false, true);
        auto const locked = !suspended;
        REQUIRE(merovingian::homeserver::set_local_user_moderation(world.runtime().homeserver, "@admin:example.org",
                                                                   "@ops:example.org", suspended, locked,
                                                                   "account.locked", "locked")
                    .ok);

        WHEN("that administrator acts on another account")
        {
            auto const response =
                send(world.runtime(), "POST", account_path("%40bob%3Aexample.org"), world.ops, action_body("lock"));

            THEN("it is refused and the other account is unchanged")
            {
                REQUIRE(response.status == 403U);
                REQUIRE_FALSE(find_user(world.runtime(), "@bob:example.org")->locked);
            }
        }

        WHEN("that administrator asks for any other operator route")
        {
            THEN("each is refused")
            {
                REQUIRE(send(world.runtime(), "GET", "/_merovingian/admin/health", world.ops).status == 403U);
                REQUIRE(send(world.runtime(), "GET", account_path("%40bob%3Aexample.org"), world.ops).status == 403U);
                REQUIRE(send(world.runtime(), "POST", "/_merovingian/admin/review/room/%21room%3Aexample.org",
                             world.ops, "{}")
                            .status == 403U);
            }
        }

        WHEN("an administrator in good standing uses the same route")
        {
            auto const response =
                send(world.runtime(), "POST", account_path("%40bob%3Aexample.org"), world.admin, action_body("lock"));

            THEN("it works")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(find_user(world.runtime(), "@bob:example.org")->locked);
            }
        }
    }
}

SCENARIO("A malformed account request body is a 400 and changes nothing", "[g5][operator-admin][body]")
{
    GIVEN("an administrator and an ordinary user")
    {
        auto world = make_world(make_config());
        auto const bodies = std::vector<std::pair<std::string, std::string>>{
            {"no body",                    {}                                      },
            {"not JSON",                   "lock"                                  },
            {"truncated JSON",             R"({"action":"lock")"                   },
            {"an array",                   R"(["lock"])"                           },
            {"a bare string",              R"("lock")"                             },
            {"an empty object",            "{}"                                    },
            {"a non-string action",        R"({"action":1})"                       },
            {"an unknown action",          R"({"action":"explode"})"               },
            {"an empty action",            R"({"action":""})"                      },
            {"a differently-cased action", R"({"action":"LOCK"})"                  },
            {"a repeated key",             R"({"action":"lock","action":"unlock"})"},
            {"invalid UTF-8",              std::string{"{\"action\":\"lo\xff\"}"}  },
        };

        WHEN("each is posted")
        {
            THEN("each is 400 and the user is neither locked nor suspended nor deactivated")
            {
                for (auto const& [name, body] : bodies)
                {
                    INFO(name);
                    REQUIRE(send(world.runtime(), "POST", std::string{alice_path}, world.admin, body).status == 400U);
                }
                auto const* alice = find_user(world.runtime(), "@alice:example.org");
                REQUIRE_FALSE(alice->locked);
                REQUIRE_FALSE(alice->suspended);
                REQUIRE_FALSE(alice->deactivated);
                REQUIRE(audit_rows(world.runtime(), "@admin:example.org", "@alice:example.org").empty());
            }
        }

        WHEN("a body far larger than any request needs is posted")
        {
            auto const response = send(world.runtime(), "POST", std::string{alice_path}, world.admin,
                                       R"({"action":"lock","note":")" + std::string(100'000U, 'x') + R"("})");

            THEN("it is refused unread as too large")
            {
                REQUIRE(response.status == 413U);
                REQUIRE_FALSE(find_user(world.runtime(), "@alice:example.org")->locked);
            }
        }

        WHEN("deactivation is requested without an explicit confirmation")
        {
            auto const missing =
                send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("deactivate"));
            auto const refused = send(world.runtime(), "POST", std::string{alice_path}, world.admin,
                                      R"({"action":"deactivate","confirm":false})");
            auto const wrong_type = send(world.runtime(), "POST", std::string{alice_path}, world.admin,
                                         R"({"action":"deactivate","confirm":"true"})");

            THEN("each is 400 and the account stays usable")
            {
                REQUIRE(missing.status == 400U);
                REQUIRE(refused.status == 400U);
                REQUIRE(wrong_type.status == 400U);
                REQUIRE_FALSE(find_user(world.runtime(), "@alice:example.org")->deactivated);
                REQUIRE(send(world.runtime(), "GET", "/_matrix/client/v3/account/whoami", world.alice).status == 200U);
            }
        }
    }
}

SCENARIO("Each account action has its effect, and a repeat has a defined result", "[g5][operator-admin][actions]")
{
    GIVEN("an administrator and a user who is signed in")
    {
        auto world = make_world(make_config());
        auto const whoami = std::string{"/_matrix/client/v3/account/whoami"};

        WHEN("the user is locked")
        {
            auto const first = send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("lock"));
            auto const again = send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("lock"));
            auto const next_request = send(world.runtime(), "GET", whoami, world.alice);

            THEN("the user's next request is M_USER_LOCKED, a repeat is 200, and memory and store agree")
            {
                REQUIRE(first.status == 200U);
                REQUIRE(again.status == 200U);
                REQUIRE(next_request.status == 401U);
                REQUIRE(*merovingian::tests::string_member(merovingian::tests::parse_object(next_request.body),
                                                           "errcode") == "M_USER_LOCKED");
                REQUIRE(memory_and_store_agree(world.runtime(), "@alice:example.org"));
                REQUIRE(*merovingian::tests::bool_member(
                    merovingian::tests::parse_object(
                        send(world.runtime(), "GET", std::string{alice_path}, world.admin).body),
                    "locked"));
                REQUIRE(reason_of(audit_rows(world.runtime(), "@admin:example.org", "@alice:example.org"), "locked"));
            }
        }

        WHEN("a locked user is unlocked, twice")
        {
            std::ignore = send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("lock"));
            auto const first =
                send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("unlock"));
            auto const again =
                send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("unlock"));

            THEN("the user can use the account again and the repeat is 200")
            {
                REQUIRE(first.status == 200U);
                REQUIRE(again.status == 200U);
                REQUIRE(send(world.runtime(), "GET", whoami, world.alice).status == 200U);
                REQUIRE(reason_of(audit_rows(world.runtime(), "@admin:example.org", "@alice:example.org"), "unlocked"));
            }
        }

        WHEN("the user is suspended, and then unsuspended")
        {
            auto const suspend =
                send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("suspend"));
            auto const suspended_send =
                send(world.runtime(), "POST", "/_matrix/client/v3/createRoom", world.alice, "{}");
            auto const flags = merovingian::tests::parse_object(
                send(world.runtime(), "GET", std::string{alice_path}, world.admin).body);
            auto const unsuspend =
                send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("unsuspend"));
            auto const resumed = send(world.runtime(), "POST", "/_matrix/client/v3/createRoom", world.alice, "{}");

            THEN("the suspended user is refused with M_USER_SUSPENDED and can act again afterwards")
            {
                REQUIRE(suspend.status == 200U);
                REQUIRE(suspended_send.status == 403U);
                REQUIRE(*merovingian::tests::string_member(merovingian::tests::parse_object(suspended_send.body),
                                                           "errcode") == "M_USER_SUSPENDED");
                REQUIRE(*merovingian::tests::bool_member(flags, "suspended"));
                REQUIRE(unsuspend.status == 200U);
                REQUIRE(resumed.status == 200U);
                REQUIRE(memory_and_store_agree(world.runtime(), "@alice:example.org"));
                auto const rows = audit_rows(world.runtime(), "@admin:example.org", "@alice:example.org");
                REQUIRE(reason_of(rows, "suspended"));
                REQUIRE(reason_of(rows, "unsuspended"));
            }
        }

        WHEN("locking leaves the other moderation flag as it was")
        {
            std::ignore = send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("suspend"));
            std::ignore = send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("lock"));
            std::ignore = send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("unlock"));

            THEN("the user is still suspended")
            {
                REQUIRE(find_user(world.runtime(), "@alice:example.org")->suspended);
                REQUIRE_FALSE(find_user(world.runtime(), "@alice:example.org")->locked);
            }
        }
    }
}

SCENARIO("Deactivation by an administrator closes the account completely", "[g5][operator-admin][deactivate]")
{
    GIVEN("a user with a token, a refresh path, an email-style pusher and a second device")
    {
        auto world = make_world(make_config());
        std::ignore = login(world.runtime(), "alice", "SECOND");
        REQUIRE(
            send(
                world.runtime(), "POST", "/_matrix/client/v3/pushers/set", world.alice,
                R"({"app_display_name":"A","app_id":"org.example.app","data":{"url":"https://push.example.org/_matrix/push/v1/notify"},)"
                R"("device_display_name":"D","kind":"http","lang":"en","pushkey":"pk1"})")
                .status == 200U);
        REQUIRE_FALSE(merovingian::database::list_pushers_for_user(world.runtime().homeserver.database.persistent_store,
                                                                   "@alice:example.org")
                          .empty());

        WHEN("the administrator deactivates the user with confirmation")
        {
            auto const response = send(world.runtime(), "POST", std::string{alice_path}, world.admin,
                                       R"({"action":"deactivate","confirm":true})");

            THEN("the user's tokens stop working, login is refused, pushers are gone and the state is durable")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(send(world.runtime(), "GET", "/_matrix/client/v3/account/whoami", world.alice).status == 401U);
                REQUIRE(
                    send(world.runtime(), "POST", "/_matrix/client/v3/login", {}, login_body("alice", "AFTER")).status ==
                    403U);
                REQUIRE(merovingian::database::list_pushers_for_user(
                            world.runtime().homeserver.database.persistent_store, "@alice:example.org")
                            .empty());
                REQUIRE(find_user(world.runtime(), "@alice:example.org")->deactivated);
                REQUIRE(memory_and_store_agree(world.runtime(), "@alice:example.org"));
                REQUIRE(*merovingian::tests::bool_member(
                    merovingian::tests::parse_object(
                        send(world.runtime(), "GET", std::string{alice_path}, world.admin).body),
                    "deactivated"));
                auto const rows = audit_rows(world.runtime(), "@admin:example.org", "@alice:example.org");
                REQUIRE(std::ranges::any_of(rows, [](auto const& row) {
                    return row.event_type == "auth.account_deactivated";
                }));
                REQUIRE(send(world.runtime(), "GET", "/_matrix/client/v3/account/whoami", world.bob).status == 200U);
            }
        }

        WHEN("a deactivated user is deactivated again, or has another action applied")
        {
            std::ignore = send(world.runtime(), "POST", std::string{alice_path}, world.admin,
                               R"({"action":"deactivate","confirm":true})");
            auto const repeat = send(world.runtime(), "POST", std::string{alice_path}, world.admin,
                                     R"({"action":"deactivate","confirm":true})");
            auto const lock = send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("lock"));
            auto const unlock =
                send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("unlock"));
            auto const summary = send(world.runtime(), "GET", std::string{alice_path}, world.admin);

            THEN("the repeat is 200, the other actions are 409, and the account is unchanged and readable")
            {
                REQUIRE(repeat.status == 200U);
                REQUIRE(lock.status == 409U);
                REQUIRE(unlock.status == 409U);
                REQUIRE(summary.status == 200U);
                REQUIRE_FALSE(find_user(world.runtime(), "@alice:example.org")->locked);
                REQUIRE(find_user(world.runtime(), "@alice:example.org")->deactivated);
            }
        }
    }
}

SCENARIO("A state write that fails leaves memory and the database in agreement", "[g5][operator-admin][durability]")
{
    GIVEN("a SQLite store whose user rows cannot be updated")
    {
        auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
        auto const path = merovingian::tests::temporary_directory() /
                          ("merovingian-operator-admin-" + std::to_string(now) + ".sqlite3");
        {
            auto database = merovingian::config::DatabaseConfig{};
            database.backend = merovingian::config::DatabaseBackend::sqlite;
            database.sqlite_path = path.string();
            auto world = make_world(make_config({}, {}, database));
            auto fault = merovingian::tests::SqliteInsertFault{path, "users", "users_update_failure", {}, "UPDATE"};

            WHEN("an administrator locks, suspends and deactivates the user")
            {
                auto const lock =
                    send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("lock"));
                auto const suspend =
                    send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("suspend"));
                auto const deactivate = send(world.runtime(), "POST", std::string{alice_path}, world.admin,
                                             R"({"action":"deactivate","confirm":true})");

                THEN("each is a 500, nothing changed in memory, and the user is not locked out")
                {
                    REQUIRE(lock.status == 500U);
                    REQUIRE(suspend.status == 500U);
                    REQUIRE(deactivate.status == 500U);
                    REQUIRE(memory_and_store_agree(world.runtime(), "@alice:example.org"));
                    auto const* alice = find_user(world.runtime(), "@alice:example.org");
                    REQUIRE_FALSE(alice->locked);
                    REQUIRE_FALSE(alice->suspended);
                    REQUIRE_FALSE(alice->deactivated);
                    REQUIRE(send(world.runtime(), "GET", "/_matrix/client/v3/account/whoami", world.alice).status ==
                            200U);
                }
            }

            WHEN("the fault is lifted and the same action is retried")
            {
                std::ignore = send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("lock"));
                fault.clear();
                auto const retry =
                    send(world.runtime(), "POST", std::string{alice_path}, world.admin, action_body("lock"));

                THEN("it succeeds")
                {
                    REQUIRE(retry.status == 200U);
                    REQUIRE(memory_and_store_agree(world.runtime(), "@alice:example.org"));
                    REQUIRE(find_user(world.runtime(), "@alice:example.org")->locked);
                }
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("The operator review route and the client review route share one implementation",
         "[g5][operator-admin][review]")
{
    GIVEN("an administrator")
    {
        auto world = make_world(make_config());
        auto const& rules = [&]() -> auto const& {
            return world.runtime().homeserver.database.persistent_store.policy_rules;
        };
        auto const find_rule = [&](std::string_view id) {
            return std::ranges::find(rules(), id, &merovingian::database::PersistentPolicyRule::rule_id);
        };

        WHEN("the same kind of target is reviewed through each route, with an encoded identifier")
        {
            auto const via_client = send(world.runtime(), "POST",
                                         "/_matrix/client/v3/admin/safety/review/room/%21one%3Aexample.org?notify=1",
                                         world.admin, R"({"reason":"spam"})");
            auto const via_operator =
                send(world.runtime(), "POST", "/_merovingian/admin/review/room/%21two%3Aexample.org?notify=1",
                     world.admin, R"({"reason":"spam"})");

            THEN("both succeed and store a rule of the same scope, action and reason under the decoded identifier")
            {
                REQUIRE(via_client.status == 200U);
                REQUIRE(via_operator.status == 200U);
                auto const client_rule = find_rule("room:!one:example.org");
                auto const operator_rule = find_rule("room:!two:example.org");
                REQUIRE(client_rule != rules().end());
                REQUIRE(operator_rule != rules().end());
                REQUIRE(client_rule->scope == operator_rule->scope);
                REQUIRE(client_rule->action == operator_rule->action);
                REQUIRE(client_rule->reason == operator_rule->reason);
                auto const client_audit = audit_rows(world.runtime(), "@admin:example.org", "!one:example.org");
                auto const operator_audit = audit_rows(world.runtime(), "@admin:example.org", "!two:example.org");
                REQUIRE_FALSE(client_audit.empty());
                REQUIRE(operator_audit.size() == client_audit.size());
                REQUIRE(operator_audit.front().event_type == client_audit.front().event_type);
                REQUIRE(operator_audit.front().category == client_audit.front().category);
            }
        }

        WHEN("each target type the client route knows is reviewed through the operator route")
        {
            THEN("media, room, federation and federation_server are accepted and anything else is 400")
            {
                for (auto const* type : {"media", "room", "federation", "federation_server"})
                {
                    INFO(type);
                    REQUIRE(send(world.runtime(), "POST", std::string{"/_merovingian/admin/review/"} + type + "/abc",
                                 world.admin)
                                .status == 200U);
                }
                REQUIRE(send(world.runtime(), "POST", "/_merovingian/admin/review/user/abc", world.admin).status ==
                        400U);
                REQUIRE(send(world.runtime(), "POST", "/_matrix/client/v3/admin/safety/review/user/abc", world.admin)
                            .status == 400U);
            }
        }

        WHEN("a malformed body is sent through each route")
        {
            auto const via_client =
                send(world.runtime(), "POST", "/_matrix/client/v3/admin/safety/review/room/r", world.admin, "[1]");
            auto const via_operator =
                send(world.runtime(), "POST", "/_merovingian/admin/review/room/r", world.admin, "[1]");

            THEN("both are 400 and store nothing")
            {
                REQUIRE(via_client.status == 400U);
                REQUIRE(via_operator.status == 400U);
                REQUIRE(find_rule("room:r") == rules().end());
            }
        }

        WHEN("an ordinary user tries either route")
        {
            THEN("both are 403")
            {
                REQUIRE(send(world.runtime(), "POST", "/_matrix/client/v3/admin/safety/review/room/r", world.alice)
                            .status == 403U);
                REQUIRE(send(world.runtime(), "POST", "/_merovingian/admin/review/room/r", world.alice).status == 403U);
            }
        }
    }
}

SCENARIO("Every declared operator route is served, and counts under a fixed key", "[g5][operator-admin][table]")
{
    GIVEN("an administrator and a concrete path for each declared route")
    {
        auto world = make_world(make_config());
        auto const concrete = [](std::string path_template, std::string_view value) {
            for (auto const* name : {"{userId}", "{targetType}", "{targetId}", "{mediaId}"})
            {
                auto const at = path_template.find(name);
                if (at != std::string::npos)
                {
                    auto const replacement = std::string_view{name} == "{userId}"       ? "%40alice%3Aexample.org"
                                             : std::string_view{name} == "{targetType}" ? "media"
                                                                                        : value;
                    path_template.replace(at, std::string_view{name}.size(), replacement);
                }
            }
            return path_template;
        };

        WHEN("an administrator calls each declared method and path")
        {
            THEN("none is answered as a route that does not exist")
            {
                for (auto const& route : merovingian::observability::admin_routes())
                {
                    auto const path = concrete(route.path_template, "abc");
                    INFO(route.method << ' ' << path);
                    auto const response = send(world.runtime(), route.method, path, world.admin);
                    // A media identifier that is unknown is a 404 from the media handler, which names the
                    // media; a path the router did not recognise says "route not found".
                    REQUIRE(response.body.find("route not found") == std::string::npos);
                    if (route.path_template.find("/media/") == std::string::npos ||
                        route.path_template.find("metrics") != std::string::npos)
                    {
                        REQUIRE(response.status != 404U);
                    }
                }
            }
        }
    }

    GIVEN("a one-request allowance on every declared route key")
    {
        auto per_ip = std::unordered_map<std::string, merovingian::http::RateLimitPolicy>{};
        for (auto const& route : merovingian::observability::admin_routes())
        {
            per_ip.emplace(route.path_template, merovingian::http::RateLimitPolicy{1U, 60U});
        }
        auto world = make_world(make_config(std::move(per_ip)));

        WHEN("two different identifiers are used on each templated route")
        {
            THEN("the second request to the same route is limited, so identifiers share one counter")
            {
                auto const user = [](std::string_view name) {
                    return account_path("%40" + std::string{name} + "%3Aexample.org");
                };
                REQUIRE(send(world.runtime(), "GET", user("one"), world.admin).status != 429U);
                REQUIRE(send(world.runtime(), "GET", user("two"), world.admin).status == 429U);
                REQUIRE(send(world.runtime(), "POST", "/_merovingian/admin/review/media/one", world.admin).status !=
                        429U);
                REQUIRE(send(world.runtime(), "POST", "/_merovingian/admin/review/room/two", world.admin).status ==
                        429U);
            }
        }
    }

    GIVEN("an administrator allowance of two requests that other paths must not spend")
    {
        auto world = make_world(make_config(
            {
        },
            {{"admin", {2U, 60U}}}));

        WHEN("paths with an extra segment, a missing segment or an invented name are tried")
        {
            auto const extra = send(world.runtime(), "GET", std::string{alice_path} + "/extra", world.admin);
            auto const missing = send(world.runtime(), "POST", "/_merovingian/admin/review/media", world.admin);
            auto const invented = send(world.runtime(), "POST", "/_merovingian/admin/accounts-x/alice", world.admin);
            auto const real = send(world.runtime(), "GET", std::string{alice_path}, world.admin);

            THEN("each is 404, they share one counter that is spent, and a real route is not")
            {
                REQUIRE(extra.status == 404U);
                REQUIRE(missing.status == 404U);
                REQUIRE(invented.status == 429U);
                REQUIRE(real.status == 200U);
            }
        }
    }
}
