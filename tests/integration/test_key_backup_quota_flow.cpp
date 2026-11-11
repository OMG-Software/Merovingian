// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit release gate (ADR-0606). One PUT /room_keys/keys of ~100000 tiny sessions cost quadratic time under
// the global mutex (each session scanned the whole session table, which grew during the batch), and a user could
// store any number of sessions and versions. Sessions are now indexed by (user, version) and by (user, version,
// room, session); server.client_api.max_key_backup_sessions_per_user and max_key_backup_versions_per_user refuse,
// with 400 M_TOO_LARGE and before any write, a request that would take a user over a cap, counting only the
// sessions the request would add.

#include "../support/E2eeCapsSupport.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto backup_config(std::uint32_t sessions, std::uint32_t versions) -> merovingian::config::Config
{
    auto config = merovingian::tests::caps_config(100U, 100U, 100U);
    config.server().client_api.max_key_backup_sessions_per_user = sessions;
    config.server().client_api.max_key_backup_versions_per_user = versions;
    return config;
}

[[nodiscard]] auto call(ClientServerRuntime& runtime, std::string const& token, std::string method, std::string target,
                        std::string body = {}) -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {std::move(method), std::move(target), token, std::move(body)})
        .response;
}

constexpr auto algorithm_body = std::string_view{R"({"algorithm":"m.megolm_backup.v1","auth_data":{}})"};

[[nodiscard]] auto create_version(ClientServerRuntime& runtime, std::string const& token)
    -> merovingian::homeserver::LocalHttpResponse
{
    return call(runtime, token, "POST", "/_matrix/client/v3/room_keys/version", std::string{algorithm_body});
}

// {"rooms":{"!r:x":{"sessions":{"<prefix>0":{...},...}}}} with `count` sessions.
[[nodiscard]] auto batch_of(std::string_view prefix, std::size_t count, std::string_view value = "{}") -> std::string
{
    auto body = std::string{R"({"rooms":{"!r:example.org":{"sessions":{)"};
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        if (index != 0U)
        {
            body += ",";
        }
        body += "\"" + std::string{prefix} + std::to_string(index) + "\":" + std::string{value};
    }
    return body + "}}}}";
}

[[nodiscard]] auto session_count(ClientServerRuntime const& runtime) -> std::size_t
{
    return runtime.homeserver.database.persistent_store.key_backup_sessions.size();
}

[[nodiscard]] auto put_batch(ClientServerRuntime& runtime, std::string const& token, std::string body)
    -> merovingian::homeserver::LocalHttpResponse
{
    return call(runtime, token, "PUT", "/_matrix/client/v3/room_keys/keys?version=1", std::move(body));
}

} // namespace

SCENARIO("a key backup upload that would take the user over the session cap is refused and stores nothing",
         "[integration][key-backup][quota][adr-0606]")
{
    GIVEN("a runtime capped at 5 backup sessions per user and a user with a backup version")
    {
        auto started = merovingian::homeserver::start_client_server(backup_config(5U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        REQUIRE(create_version(runtime, token).status == 200U);

        WHEN("a batch of exactly the cap is uploaded")
        {
            auto const response = put_batch(runtime, token, batch_of("s", 5U));

            THEN("it is accepted and the response counts 5 sessions")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("\"count\":5") != std::string::npos);
                REQUIRE(session_count(runtime) == 5U);
            }
        }

        WHEN("a batch one over the cap is uploaded")
        {
            auto const response = put_batch(runtime, token, batch_of("s", 6U));

            THEN("it is refused with M_TOO_LARGE and not one of its sessions is stored")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(session_count(runtime) == 0U);
            }
        }

        WHEN("the user is at the cap and a batch replaces held sessions and adds none")
        {
            REQUIRE(put_batch(runtime, token, batch_of("s", 5U)).status == 200U);
            auto const response = put_batch(runtime, token, batch_of("s", 5U, R"({"first_message_index":0})"));

            THEN("it is accepted: replacing a session is not counted as an addition")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(session_count(runtime) == 5U);
            }
        }

        WHEN("the user is at the cap and a batch replaces 3 held sessions and adds 1 new one")
        {
            REQUIRE(put_batch(runtime, token, batch_of("s", 5U)).status == 200U);
            auto const mixed = put_batch(
                runtime, token, R"({"rooms":{"!r:example.org":{"sessions":{"s0":{},"s1":{},"s2":{},"new":{}}}}})");

            THEN("it is refused, since net of the replaced rows it still adds one, and nothing changes")
            {
                REQUIRE(mixed.status == 400U);
                REQUIRE(mixed.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(session_count(runtime) == 5U);
            }
        }

        WHEN("the user is one under the cap and a batch replaces 3 held sessions and adds 1 new one")
        {
            REQUIRE(put_batch(runtime, token, batch_of("s", 4U)).status == 200U);
            auto const mixed = put_batch(
                runtime, token, R"({"rooms":{"!r:example.org":{"sessions":{"s0":{},"s1":{},"s2":{},"new":{}}}}})");

            THEN("it is accepted: the net addition fits")
            {
                REQUIRE(mixed.status == 200U);
                REQUIRE(session_count(runtime) == 5U);
            }
        }

        WHEN("the user is at the cap and uploads one new session by room and by session")
        {
            REQUIRE(put_batch(runtime, token, batch_of("s", 5U)).status == 200U);
            auto const by_room =
                call(runtime, token, "PUT", "/_matrix/client/v3/room_keys/keys/!r:example.org?version=1",
                     R"({"sessions":{"extra":{}}})");
            auto const by_session =
                call(runtime, token, "PUT", "/_matrix/client/v3/room_keys/keys/!r:example.org/extra2?version=1", "{}");
            auto const replace_one =
                call(runtime, token, "PUT", "/_matrix/client/v3/room_keys/keys/!r:example.org/s0?version=1", "{}");

            THEN("both additions are refused and replacing a held session still works")
            {
                REQUIRE(by_room.status == 400U);
                REQUIRE(by_room.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(by_session.status == 400U);
                REQUIRE(replace_one.status == 200U);
                REQUIRE(session_count(runtime) == 5U);
            }
        }

        WHEN("sessions are deleted at the cap")
        {
            REQUIRE(put_batch(runtime, token, batch_of("s", 5U)).status == 200U);
            REQUIRE(call(runtime, token, "DELETE", "/_matrix/client/v3/room_keys/keys/!r:example.org/s0?version=1")
                        .status == 200U);
            auto const added =
                call(runtime, token, "PUT", "/_matrix/client/v3/room_keys/keys/!r:example.org/again?version=1", "{}");

            THEN("room is made for a new session")
            {
                REQUIRE(added.status == 200U);
                REQUIRE(session_count(runtime) == 5U);
            }
        }
    }
}

SCENARIO("the session cap counts all of a user's versions, and another user's sessions do not count",
         "[integration][key-backup][quota][adr-0606]")
{
    GIVEN("a runtime capped at 4 backup sessions per user, with 3 sessions in version 1")
    {
        auto started = merovingian::homeserver::start_client_server(backup_config(4U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        REQUIRE(create_version(runtime, token).status == 200U);
        REQUIRE(put_batch(runtime, token, batch_of("s", 3U)).status == 200U);

        WHEN("a second version is created and 2 sessions are uploaded to it")
        {
            REQUIRE(create_version(runtime, token).status == 200U);
            auto const response =
                call(runtime, token, "PUT", "/_matrix/client/v3/room_keys/keys?version=2", batch_of("t", 2U));

            THEN("they are refused, because 3 + 2 is over 4")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_TOO_LARGE") != std::string::npos);
            }
        }
    }
}

SCENARIO("a user may hold only the configured number of key backup versions",
         "[integration][key-backup][quota][adr-0606]")
{
    GIVEN("a runtime capped at 2 backup versions per user")
    {
        auto started = merovingian::homeserver::start_client_server(backup_config(100U, 2U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        REQUIRE(create_version(runtime, token).status == 200U);
        REQUIRE(create_version(runtime, token).status == 200U);

        WHEN("a third version is created")
        {
            auto const response = create_version(runtime, token);

            THEN("it is refused with M_TOO_LARGE and no version is added")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(runtime.homeserver.database.persistent_store.key_backup_versions.size() == 2U);
            }
        }

        WHEN("a version is deleted and a new one created")
        {
            REQUIRE(call(runtime, token, "DELETE", "/_matrix/client/v3/room_keys/version/1").status == 200U);
            auto const response = create_version(runtime, token);

            THEN("it is accepted with a number that was not issued before")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("\"version\":\"3\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("a large key backup batch costs one index lookup per session and reads back exactly",
         "[integration][key-backup][index][adr-0606]")
{
    GIVEN("a runtime with a backup version and a batch of 3000 sessions")
    {
        auto started = merovingian::homeserver::start_client_server(backup_config(500000U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        REQUIRE(create_version(runtime, token).status == 200U);
        auto const& store = runtime.homeserver.database.persistent_store;

        WHEN("the batch is uploaded")
        {
            auto const before = store.key_backup_rows_examined.value();
            auto const response = put_batch(runtime, token, batch_of("s", 3000U));
            auto const rows = store.key_backup_rows_examined.value() - before;

            THEN("the work is a few lookups per session, where a scan per session would read millions of rows")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("\"count\":3000") != std::string::npos);
                REQUIRE(session_count(runtime) == 3000U);
                REQUIRE(rows <= 6U * 3000U);
            }
        }

        WHEN("the batch is uploaded, some sessions deleted, and the indexes rebuilt as after a restart")
        {
            REQUIRE(put_batch(runtime, token, batch_of("s", 300U)).status == 200U);
            REQUIRE(call(runtime, token, "DELETE", "/_matrix/client/v3/room_keys/keys/!r:example.org/s7?version=1")
                        .status == 200U);
            auto const before_reload = call(runtime, token, "GET", "/_matrix/client/v3/room_keys/keys?version=1");
            auto const version_before = call(runtime, token, "GET", "/_matrix/client/v3/room_keys/version");
            merovingian::database::rebuild_key_indexes(started.runtime.homeserver.database.persistent_store);
            auto const after_reload = call(runtime, token, "GET", "/_matrix/client/v3/room_keys/keys?version=1");
            auto const version_after = call(runtime, token, "GET", "/_matrix/client/v3/room_keys/version");

            THEN("the same sessions, count and etag are read back")
            {
                REQUIRE(before_reload.status == 200U);
                REQUIRE(before_reload.body == after_reload.body);
                REQUIRE(before_reload.body.find("\"s7\"") == std::string::npos);
                REQUIRE(before_reload.body.find("\"s8\"") != std::string::npos);
                REQUIRE(version_before.body == version_after.body);
                REQUIRE(version_after.body.find("\"count\":299") != std::string::npos);
            }
        }
    }
}
