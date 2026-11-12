// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Run-3 C22 (ADR-0673). Every GET /room_keys/version and every PUT /room_keys/keys answer recomputed the backup's
// `etag` by collecting, sorting and hashing every stored session of the version under the runtime lock, and a session
// could be as large as the 1 MiB body. Policy: the etag comes from a digest of the version's sessions that every writer
// keeps (so a request reads no session), and a session over 16 KiB is refused with 400 M_TOO_LARGE before anything is
// stored.
//
// Spec: client-server-api.md, GET /room_keys/version ("etag: Opaque identifier describing the current contents of the
// backup, which can be used to detect if the contents have changed") and PUT /room_keys/keys.

#include "../support/E2eeCapsSupport.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace
{

namespace hs = merovingian::homeserver;
namespace db = merovingian::database;

[[nodiscard]] auto call(hs::ClientServerRuntime& runtime, std::string const& token, std::string method,
                        std::string target, std::string body = {}) -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(runtime, {std::move(method), std::move(target), token, std::move(body)})
        .response;
}

[[nodiscard]] auto make_runtime_and_version(hs::ClientServerStartResult& started) -> std::string
{
    REQUIRE(started.started);
    auto const token = merovingian::tests::register_and_login_alice(started.runtime);
    REQUIRE(call(started.runtime, token, "POST", "/_matrix/client/v3/room_keys/version",
                 R"({"algorithm":"m.megolm_backup.v1","auth_data":{}})")
                .status == 200U);
    return token;
}

[[nodiscard]] auto etag_of(hs::ClientServerRuntime& runtime, std::string const& token) -> std::string
{
    auto const response = call(runtime, token, "GET", "/_matrix/client/v3/room_keys/version");
    REQUIRE(response.status == 200U);
    return merovingian::tests::string_field(response.body, "etag");
}

// {"rooms":{"!r:example.org":{"sessions":{"s0":<value>, ...}}}} naming the given session IDs.
[[nodiscard]] auto batch_of(std::initializer_list<std::pair<std::string, std::string>> sessions) -> std::string
{
    auto body = std::string{R"({"rooms":{"!r:example.org":{"sessions":{)"};
    auto first = true;
    for (auto const& [id, value] : sessions)
    {
        body += first ? "" : ",";
        first = false;
        body += "\"" + id + "\":" + value;
    }
    return body + "}}}}";
}

[[nodiscard]] auto put_batch(hs::ClientServerRuntime& runtime, std::string const& token, std::string body)
    -> hs::LocalHttpResponse
{
    return call(runtime, token, "PUT", "/_matrix/client/v3/room_keys/keys?version=1", std::move(body));
}

constexpr auto limit = std::size_t{16384U};

// A JSON object of exactly `size` bytes.
[[nodiscard]] auto object_of_size(std::size_t size) -> std::string
{
    constexpr auto frame = std::string_view{R"({"p":""})"};
    return std::string{R"({"p":")"} + std::string(size - frame.size(), 'x') + R"("})";
}

} // namespace

SCENARIO("a backup's etag changes exactly when its content does, and survives a reload",
         "[homeserver][client-server][e2ee][key-backup][security][c22]")
{
    GIVEN("a user with a backup version holding three sessions")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        auto const token = make_runtime_and_version(started);
        auto& runtime = started.runtime;
        REQUIRE(put_batch(runtime, token,
                          batch_of({
                              {"s0", R"({"a":1})"},
                              {"s1", R"({"a":2})"},
                              {"s2", R"({"a":3})"}
        }))
                    .status == 200U);
        auto const initial = etag_of(runtime, token);

        WHEN("the same sessions are uploaded again")
        {
            REQUIRE(put_batch(runtime, token,
                              batch_of({
                                  {"s0", R"({"a":1})"},
                                  {"s1", R"({"a":2})"},
                                  {"s2", R"({"a":3})"}
            }))
                        .status == 200U);

            THEN("the etag is unchanged")
            {
                REQUIRE(etag_of(runtime, token) == initial);
            }
        }

        WHEN("one session is replaced, another is added and then removed")
        {
            REQUIRE(put_batch(runtime, token,
                              batch_of({
                                  {"s1", R"({"a":99})"}
            }))
                        .status == 200U);
            auto const replaced = etag_of(runtime, token);
            REQUIRE(put_batch(runtime, token,
                              batch_of({
                                  {"s3", R"({"a":4})"}
            }))
                        .status == 200U);
            auto const added = etag_of(runtime, token);
            REQUIRE(call(runtime, token, "DELETE", "/_matrix/client/v3/room_keys/keys/%21r%3Aexample.org/s3?version=1")
                        .status == 200U);
            auto const removed = etag_of(runtime, token);

            THEN("each change moves the etag, and removing the added session returns to the replaced content's etag")
            {
                REQUIRE(replaced != initial);
                REQUIRE(added != replaced);
                REQUIRE(removed == replaced);
            }
        }

        WHEN("the in-memory indexes are rebuilt, as after a restart")
        {
            db::rebuild_key_indexes(runtime.homeserver.database.persistent_store);

            THEN("the etag is the same")
            {
                REQUIRE(etag_of(runtime, token) == initial);
            }
        }
    }
}

SCENARIO("reading a backup's version reads no session", "[homeserver][client-server][e2ee][key-backup][cost][c22]")
{
    GIVEN("a backup holding 150 sessions")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        auto const token = make_runtime_and_version(started);
        auto& runtime = started.runtime;
        auto body = std::string{R"({"rooms":{"!r:example.org":{"sessions":{)"};
        for (auto index = std::size_t{0U}; index < 150U; ++index)
        {
            body += (index == 0U ? "\"s" : ",\"s") + std::to_string(index) + R"(":{"a":1})";
        }
        REQUIRE(put_batch(runtime, token, body + "}}}}").status == 200U);
        auto const& store = runtime.homeserver.database.persistent_store;

        WHEN("the version is read")
        {
            auto const before = store.key_backup_rows_examined.value();
            auto const response = call(runtime, token, "GET", "/_matrix/client/v3/room_keys/version");

            THEN("it answers the count and an etag and counts two index lookups, not 150 sessions")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("\"count\":150") != std::string::npos);
                // Two index lookups (the session count, asked twice by the answer), whatever the number of sessions.
                REQUIRE(store.key_backup_rows_examined.value() - before == 2U);
            }
        }
    }
}

SCENARIO("a backup session over the size limit is refused and stores nothing",
         "[homeserver][client-server][e2ee][key-backup][security][c22]")
{
    GIVEN("a user with an empty backup version")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        auto const token = make_runtime_and_version(started);
        auto& runtime = started.runtime;
        auto const sessions = [&runtime]() {
            return runtime.homeserver.database.persistent_store.key_backup_sessions.size();
        };

        WHEN("a session of exactly the limit is uploaded alone and in a batch")
        {
            auto const single =
                call(runtime, token, "PUT", "/_matrix/client/v3/room_keys/keys/%21r%3Aexample.org/a?version=1",
                     object_of_size(limit));
            auto const batch = put_batch(runtime, token,
                                         batch_of({
                                             {"b", object_of_size(limit)}
            }));

            THEN("both are stored")
            {
                REQUIRE(single.status == 200U);
                REQUIRE(batch.status == 200U);
                REQUIRE(sessions() == 2U);
            }
        }

        WHEN("a session one byte over the limit is uploaded alone, in a room and in a batch")
        {
            auto const single =
                call(runtime, token, "PUT", "/_matrix/client/v3/room_keys/keys/%21r%3Aexample.org/a?version=1",
                     object_of_size(limit + 1U));
            auto const room =
                call(runtime, token, "PUT", "/_matrix/client/v3/room_keys/keys/%21r%3Aexample.org?version=1",
                     R"({"sessions":{"c":)" + object_of_size(limit + 1U) + "}}");
            auto const batch = put_batch(runtime, token,
                                         batch_of({
                                             {"ok",  R"({"a":1})"              },
                                             {"big", object_of_size(limit + 1U)}
            }));

            THEN("each is 400 M_TOO_LARGE and nothing is stored, the small session of the batch included")
            {
                for (auto const* response : {&single, &room, &batch})
                {
                    REQUIRE(response->status == 400U);
                    REQUIRE(response->body.find("M_TOO_LARGE") != std::string::npos);
                }
                REQUIRE(sessions() == 0U);
            }
        }
    }
}
