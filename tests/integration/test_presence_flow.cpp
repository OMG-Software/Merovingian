// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// Presence end to end: the switch that turns it off, the m.presence EDU this server sends, and the
// m.presence EDU it accepts.
//
// Spec: Matrix Client-Server API v1.19, Presence
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#presence
// Spec: Matrix Server-Server API v1.19, m.presence
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#mpresence
//   "An EDU representing presence updates for users of the sending homeserver." and "Servers should
//   only send presence updates for users that the receiving server would be interested in. Such as
//   the receiving server sharing a room with a given user."

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/presence_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <sodium.h>

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

namespace
{

constexpr auto remote_server = std::string_view{"remote.example.org"};
constexpr auto remote_bob = std::string_view{"@bob:remote.example.org"};
constexpr auto local_alice = std::string_view{"@alice:example.org"};
constexpr auto shared_room = std::string_view{"!shared:example.org"};

[[nodiscard]] auto presence_config(bool enabled = true) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
    config.presence().enabled = enabled;
    return config;
}

[[nodiscard]] auto call(ClientServerRuntime& runtime, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {std::move(method), std::move(target), token, std::move(body)})
        .response;
}

[[nodiscard]] auto register_alice(ClientServerRuntime& runtime) -> std::string
{
    auto const registration = call(runtime, "POST", "/_matrix/client/v3/register", {},
                                   merovingian::tests::registration_json("alice", "CorrectHorse7!"));
    REQUIRE(registration.status == 200U);
    auto const body = parse_object(registration.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// alice (local) shares a room with bob on another server. Both views of membership are filled:
// the room's roster (where outbound destinations come from) and the membership rows (what
// decides who may see whose presence).
auto share_room_with_remote_bob(ClientServerRuntime& runtime) -> void
{
    runtime.homeserver.database.rooms.push_back({
        std::string{shared_room},
        std::string{local_alice},
        {std::string{local_alice}, std::string{remote_bob}},
        {}
    });
    auto& store = runtime.homeserver.database.persistent_store;
    store.memberships.push_back({std::string{shared_room}, std::string{local_alice}, "join", 1U});
    store.memberships.push_back({std::string{shared_room}, std::string{remote_bob}, "join", 2U});
}

// A dispatch worker that is never started, so every EDU the server enqueues stays in its durable
// queue (store.federation_transactions) for the test to read.
auto install_unstarted_dispatch_worker(ClientServerRuntime& runtime) -> void
{
    REQUIRE(runtime.homeserver.outbound_client != nullptr);
    auto config = merovingian::federation::DispatchWorkerConfig{};
    config.origin = runtime.homeserver.config.server().server_name;
    config.key_id = "ed25519:test";
    runtime.homeserver.dispatch_worker = std::make_unique<merovingian::federation::DispatchWorker>(
        std::move(config), *runtime.homeserver.outbound_client,
        [](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        },
        merovingian::federation::DispatchClock{}, merovingian::federation::DispatchSleep{},
        &runtime.homeserver.database.persistent_store);
}

[[nodiscard]] auto queued_presence_edus(ClientServerRuntime const& runtime) -> std::vector<std::string>
{
    auto const marker = std::string{R"("edu_type":"m.presence")"};
    auto bodies = std::vector<std::string>{};
    for (auto const& transaction : runtime.homeserver.database.persistent_store.federation_transactions)
    {
        if (transaction.server_name == remote_server && transaction.body.find(marker) != std::string::npos)
        {
            bodies.push_back(transaction.body);
        }
    }
    return bodies;
}

// The one push entry of a queued presence transaction.
[[nodiscard]] auto push_entry_of(std::string const& transaction_body) -> merovingian::canonicaljson::Object
{
    auto const transaction = parse_object(transaction_body);
    auto const* edus = object_member_as_array(transaction, "edus");
    REQUIRE(edus != nullptr);
    REQUIRE(edus->size() == 1U);
    auto const* edu = std::get_if<merovingian::canonicaljson::Object>(&edus->front().storage());
    REQUIRE(edu != nullptr);
    auto const* content = object_member_as_object(*edu, "content");
    REQUIRE(content != nullptr);
    auto const* push = object_member_as_array(*content, "push");
    REQUIRE(push != nullptr);
    REQUIRE(push->size() == 1U);
    auto const* entry = std::get_if<merovingian::canonicaljson::Object>(&push->front().storage());
    REQUIRE(entry != nullptr);
    return *entry;
}

[[nodiscard]] auto put_alice_presence(ClientServerRuntime& runtime, std::string const& token, std::string body)
    -> merovingian::homeserver::LocalHttpResponse
{
    return call(runtime, "PUT", "/_matrix/client/v3/presence/%40alice%3Aexample.org/status", token, std::move(body));
}

[[nodiscard]] auto stored_presence(ClientServerRuntime const& runtime, std::string_view user_id)
    -> std::optional<merovingian::database::PersistentPresence>
{
    auto const& rows = runtime.homeserver.database.persistent_store.presence_states;
    auto const found = std::ranges::find_if(rows, [user_id](auto const& row) {
        return row.user_id == user_id;
    });
    if (found == rows.end())
    {
        return std::nullopt;
    }
    return *found;
}

[[nodiscard]] auto deliver_presence_edu(ClientServerRuntime& runtime, std::string_view origin, std::string content)
    -> merovingian::federation::EduDispositionResult
{
    auto envelope = merovingian::federation::InboundEduEnvelope{};
    envelope.type = merovingian::federation::EduType::presence;
    envelope.edu_type = "m.presence";
    envelope.origin = std::string{origin};
    envelope.content_json = std::move(content);
    merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
    REQUIRE(runtime.homeserver.federation.edu_sink != nullptr);
    return runtime.homeserver.federation.edu_sink(envelope);
}

[[nodiscard]] auto push_content(std::string_view user_id, std::string_view presence, std::string_view extra = {})
    -> std::string
{
    return std::string{R"({"push":[{"user_id":")"} + std::string{user_id} + R"(","presence":")" +
           std::string{presence} + R"(","last_active_ago":5000)" + std::string{extra} + "}]}";
}

[[nodiscard]] auto sync_presence_senders(ClientServerRuntime& runtime, std::string const& token)
    -> std::vector<std::string>
{
    auto const synced = call(runtime, "GET", "/_matrix/client/v3/sync?timeout=0&set_presence=offline", token);
    REQUIRE(synced.status == 200U);
    auto const body = parse_object(synced.body);
    auto const* presence = object_member_as_object(body, "presence");
    REQUIRE(presence != nullptr);
    auto const* events = object_member_as_array(*presence, "events");
    REQUIRE(events != nullptr);
    auto senders = std::vector<std::string>{};
    for (auto const& value : *events)
    {
        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        REQUIRE(event != nullptr);
        auto const* sender = string_member(*event, "sender");
        REQUIRE(sender != nullptr);
        senders.push_back(*sender);
    }
    return senders;
}

} // namespace

// presence.enabled=false: the server does not track presence. The spec's GET answers 404 for
// "no presence state for this user"; PUT has only 200 and 429, so it answers 200 and keeps nothing.
SCENARIO("A server with presence turned off tracks no presence", "[integration][presence]")
{
    GIVEN("a server with presence.enabled=false, a registered user and a remote room member")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const token = register_alice(runtime);
        share_room_with_remote_bob(runtime);

        WHEN("the user sets a presence, syncs without set_presence, and reads their presence")
        {
            auto const put = put_alice_presence(runtime, token, R"({"presence":"online","status_msg":"here"})");
            auto const synced = call(runtime, "GET", "/_matrix/client/v3/sync?timeout=0", token);
            auto const read = call(runtime, "GET", "/_matrix/client/v3/presence/%40alice%3Aexample.org/status", token);

            THEN("PUT is answered 200 and GET 404, and nothing is stored or sent")
            {
                REQUIRE(put.status == 200U);
                REQUIRE(synced.status == 200U);
                REQUIRE(read.status == 404U);
                auto const body = parse_object(read.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_NOT_FOUND");
                REQUIRE(runtime.homeserver.database.persistent_store.presence_states.empty());
                REQUIRE(queued_presence_edus(runtime).empty());
            }
        }

        WHEN("a remote server sends a presence EDU for a user in the shared room")
        {
            auto const result = deliver_presence_edu(runtime, remote_server, push_content(remote_bob, "online"));

            THEN("it is dropped: nothing is stored and local users are shown nothing")
            {
                REQUIRE(result.status == merovingian::federation::EduDispositionStatus::accepted);
                REQUIRE_FALSE(stored_presence(runtime, remote_bob).has_value());
                REQUIRE(sync_presence_senders(runtime, token).empty());
            }
        }
    }
}

SCENARIO("A presence update is sent to the servers of the users who share a room",
         "[integration][presence][federation][edu]")
{
    GIVEN("alice shares a room with bob on another server")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const token = register_alice(runtime);
        share_room_with_remote_bob(runtime);

        WHEN("alice sets her presence")
        {
            REQUIRE(put_alice_presence(runtime, token, R"({"presence":"unavailable","status_msg":"away"})").status ==
                    200U);

            THEN("bob's server is sent one m.presence EDU describing alice and nobody else")
            {
                auto const edus = queued_presence_edus(runtime);
                REQUIRE(edus.size() == 1U);
                auto const entry = push_entry_of(edus.front());
                // Spec MUST: `user_id` and `presence` are required in a push entry.
                auto const* user_id = string_member(entry, "user_id");
                REQUIRE(user_id != nullptr);
                REQUIRE(*user_id == local_alice);
                auto const* presence = string_member(entry, "presence");
                REQUIRE(presence != nullptr);
                REQUIRE(*presence == "unavailable");
                // Spec MUST: `last_active_ago` is required.
                auto const* last_active_ago = int_member(entry, "last_active_ago");
                REQUIRE(last_active_ago != nullptr);
                REQUIRE(*last_active_ago >= 0);
                auto const* status_msg = string_member(entry, "status_msg");
                REQUIRE(status_msg != nullptr);
                REQUIRE(*status_msg == "away");
            }
        }

        WHEN("alice syncs twice without set_presence")
        {
            REQUIRE(call(runtime, "GET", "/_matrix/client/v3/sync?timeout=0", token).status == 200U);
            REQUIRE(call(runtime, "GET", "/_matrix/client/v3/sync?timeout=0", token).status == 200U);

            THEN("her coming online is sent once, not once per sync")
            {
                auto const edus = queued_presence_edus(runtime);
                REQUIRE(edus.size() == 1U);
                auto const entry = push_entry_of(edus.front());
                auto const* presence = string_member(entry, "presence");
                REQUIRE(presence != nullptr);
                REQUIRE(*presence == "online");
            }
        }

        WHEN("alice has no room in common with any other server and sets her presence")
        {
            runtime.homeserver.database.rooms.clear();
            REQUIRE(put_alice_presence(runtime, token, R"({"presence":"online"})").status == 200U);

            THEN("no EDU is sent")
            {
                REQUIRE(queued_presence_edus(runtime).empty());
            }
        }
    }
}

SCENARIO("A presence change wakes long-polling syncs", "[integration][presence][sync]")
{
    GIVEN("a runtime whose sync notifier has seen the current stream position")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_alice(runtime);
        share_room_with_remote_bob(runtime);
        auto& notifier = merovingian::homeserver::ensure_sync_notifier(runtime);
        auto const before = notifier.current_sync_stream_id();

        WHEN("a local user sets their presence")
        {
            REQUIRE(put_alice_presence(runtime, token, R"({"presence":"online"})").status == 200U);

            THEN("a poll parked at the earlier position is woken")
            {
                REQUIRE(notifier.wait_for_change(0U, before, std::chrono::milliseconds{0}));
                REQUIRE(notifier.current_sync_stream_id() > before);
            }
        }

        WHEN("a remote server reports a presence for a user who shares a room")
        {
            std::ignore = deliver_presence_edu(runtime, remote_server, push_content(remote_bob, "online"));

            THEN("a poll parked at the earlier position is woken")
            {
                REQUIRE(notifier.wait_for_change(0U, before, std::chrono::milliseconds{0}));
                REQUIRE(notifier.current_sync_stream_id() > before);
            }
        }
    }
}

SCENARIO("A presence EDU is accepted only for the sending server's users who share a room with a local user",
         "[integration][presence][federation][edu][security]")
{
    GIVEN("alice shares a room with bob on remote.example.org")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_alice(runtime);
        // Bob counts as sharing a room only once his join is in this server's store; every case
        // below starts from that, so only the EDU's own content decides what is kept.
        share_room_with_remote_bob(runtime);

        WHEN("remote.example.org reports bob's presence")
        {
            auto const result = deliver_presence_edu(
                runtime, remote_server,
                push_content(remote_bob, "online", R"(,"status_msg":"hi","currently_active":true)"));

            THEN("it is stored and alice is shown it in her next sync")
            {
                REQUIRE(result.status == merovingian::federation::EduDispositionStatus::accepted);
                auto const stored = stored_presence(runtime, remote_bob);
                REQUIRE(stored.has_value());
                REQUIRE(stored->presence == "online");
                REQUIRE(stored->status_msg == "hi");
                REQUIRE(stored->currently_active);
                REQUIRE(sync_presence_senders(runtime, token) == std::vector<std::string>{std::string{remote_bob}});
            }

            AND_THEN("alice can read it with GET, with the server-computed last_active_ago")
            {
                auto const read =
                    call(runtime, "GET", "/_matrix/client/v3/presence/%40bob%3Aremote.example.org/status", token);
                REQUIRE(read.status == 200U);
                auto const body = parse_object(read.body);
                auto const* presence = string_member(body, "presence");
                REQUIRE(presence != nullptr);
                REQUIRE(*presence == "online");
                auto const* last_active_ago = int_member(body, "last_active_ago");
                REQUIRE(last_active_ago != nullptr);
                // The EDU said 5000 ms; the row has aged since, never shrunk.
                REQUIRE(*last_active_ago >= 5000);
            }
        }

        WHEN("another server reports bob's presence")
        {
            // The EDU's origin is the authenticated sending server; bob belongs to another one.
            auto const result = deliver_presence_edu(runtime, "evil.example.net", push_content(remote_bob, "online"));

            THEN("it is refused and nothing is stored: only a user's own server speaks for them")
            {
                REQUIRE(result.status == merovingian::federation::EduDispositionStatus::rejected_invalid);
                REQUIRE_FALSE(stored_presence(runtime, remote_bob).has_value());
            }
        }

        WHEN("remote.example.org reports a user who shares no room with anyone here")
        {
            auto const stranger = std::string{"@stranger:remote.example.org"};
            std::ignore = deliver_presence_edu(runtime, remote_server, push_content(stranger, "online"));

            THEN("nothing is stored, so a server cannot make this one keep rows for users it has no use for")
            {
                REQUIRE_FALSE(stored_presence(runtime, stranger).has_value());
            }
        }

        WHEN("remote.example.org reports a presence outside the enumeration")
        {
            auto const result = deliver_presence_edu(runtime, remote_server, push_content(remote_bob, "busy"));

            THEN("it is refused and nothing is stored")
            {
                REQUIRE(result.status == merovingian::federation::EduDispositionStatus::rejected_invalid);
                REQUIRE_FALSE(stored_presence(runtime, remote_bob).has_value());
            }
        }

        WHEN("remote.example.org reports a status message over the byte limit")
        {
            auto const too_long = std::string{R"(,"status_msg":")"} +
                                  std::string(merovingian::homeserver::max_presence_status_msg_bytes + 1U, 'x') +
                                  R"(")";
            auto const result =
                deliver_presence_edu(runtime, remote_server, push_content(remote_bob, "online", too_long));

            THEN("it is refused and nothing is stored")
            {
                REQUIRE(result.status == merovingian::federation::EduDispositionStatus::rejected_invalid);
                REQUIRE_FALSE(stored_presence(runtime, remote_bob).has_value());
            }
        }

        WHEN("remote.example.org reports a negative last_active_ago")
        {
            // Written out in full: push_content always supplies a valid last_active_ago.
            std::ignore = deliver_presence_edu(
                runtime, remote_server,
                R"({"push":[{"user_id":"@bob:remote.example.org","presence":"online","last_active_ago":-9}]})");

            THEN("the value is not kept")
            {
                auto const stored = stored_presence(runtime, remote_bob);
                REQUIRE(stored.has_value());
                REQUIRE(stored->last_active_ago >= 0);
            }
        }
    }

    GIVEN("remote users who all share a room with alice, more than one EDU may carry")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        std::ignore = register_alice(runtime);
        share_room_with_remote_bob(runtime);
        // One more EDU entry than the limit allows, each for a user who shares the room, so the
        // only reason any is dropped is the per-EDU limit itself.
        auto const entries = merovingian::homeserver::max_inbound_presence_entries + 5U;
        auto content = std::string{R"({"push":[)"};
        auto& store = runtime.homeserver.database.persistent_store;
        for (auto index = std::size_t{0U}; index < entries; ++index)
        {
            auto const user_id = "@user" + std::to_string(index) + ":remote.example.org";
            store.memberships.push_back({std::string{shared_room}, user_id, "join", 10U + index});
            if (index != 0U)
            {
                content += ",";
            }
            content += R"({"user_id":")" + user_id + R"(","presence":"online","last_active_ago":1})";
        }
        content += "]}";

        WHEN("one EDU names more users than the limit")
        {
            std::ignore = deliver_presence_edu(runtime, remote_server, content);

            THEN("no more than the limit are stored")
            {
                auto stored = std::size_t{0U};
                for (auto const& row : store.presence_states)
                {
                    if (row.user_id.starts_with("@user"))
                    {
                        ++stored;
                    }
                }
                REQUIRE(stored == merovingian::homeserver::max_inbound_presence_entries);
            }
        }
    }
}
