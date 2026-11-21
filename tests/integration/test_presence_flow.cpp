// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"
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

#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentPresence.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/DispatchWorker.hpp"
#include "merovingian/federation/DispatchWorkerConfig.hpp"
#include "merovingian/federation/EduDispositionResult.hpp"
#include "merovingian/federation/EduDispositionStatus.hpp"
#include "merovingian/federation/EduType.hpp"
#include "merovingian/federation/InboundEduEnvelope.hpp"
#include "merovingian/homeserver/AccountPresenceTracker.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/DispatchResult.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/PresenceService.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

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

// The clock of the presence change window and of the devices' freshness moves on without a sleep (ADR-0871, ADR-0872).
auto advance_presence_clock(ClientServerRuntime& runtime, std::int64_t by_ms) -> void
{
    runtime.homeserver.test_presence_clock_advance_ms += by_ms;
}

// Lets the window opened by the last presence change end, so the next change is kept.
auto let_presence_window_end(ClientServerRuntime& runtime) -> void
{
    advance_presence_clock(runtime, merovingian::homeserver::AccountPresenceTracker::change_window_ms);
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

namespace
{

constexpr auto minute_ms = std::int64_t{60 * 1000};

// Presence rows hold when they were last observed; moving that back is the passage of time without a
// sleep. The row is changed in place, as `record_presence` would restamp it. The clock of the change window and of
// the devices' freshness (ADR-0871, ADR-0872) moves on by as much.
auto age_presence(ClientServerRuntime& runtime, std::string_view user_id, std::int64_t by_ms) -> void
{
    for (auto& row : runtime.homeserver.database.persistent_store.presence_states)
    {
        if (row.user_id == user_id)
        {
            row.observed_at_ms -= by_ms;
        }
    }
    advance_presence_clock(runtime, by_ms);
}

[[nodiscard]] auto read_alice_presence(ClientServerRuntime& runtime, std::string const& token) -> std::string
{
    auto const read = call(runtime, "GET", "/_matrix/client/v3/presence/%40alice%3Aexample.org/status", token);
    REQUIRE(read.status == 200U);
    auto const body = parse_object(read.body);
    auto const* presence = string_member(body, "presence");
    REQUIRE(presence != nullptr);
    return *presence;
}

} // namespace

// Spec: Matrix Client-Server API v1.19, Presence, "Idle timeout":
//   "The server will automatically set a user's presence to `unavailable` if their last active time
//   was over a threshold value (e.g. 5 minutes). [...] Any activity that bumps the last active time on
//   any of the user's clients will cause the server to automatically set their presence to `online`."
// The spec leaves the threshold open; this server uses five minutes (ADR-0492).
SCENARIO("A user idle past the presence threshold is set unavailable", "[integration][presence][idle][c11]")
{
    GIVEN("alice is online and shares a room with bob on another server")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const token = register_alice(runtime);
        share_room_with_remote_bob(runtime);
        REQUIRE(put_alice_presence(runtime, token, R"({"presence":"online"})").status == 200U);
        REQUIRE(queued_presence_edus(runtime).size() == 1U);

        WHEN("six minutes pass with no activity and the idle sweep runs")
        {
            age_presence(runtime, local_alice, 6 * minute_ms);
            std::ignore = merovingian::homeserver::run_presence_idle_sweep(runtime);

            THEN("alice reads as unavailable and no longer currently active")
            {
                REQUIRE(read_alice_presence(runtime, token) == "unavailable");
                auto const row = stored_presence(runtime, local_alice);
                REQUIRE(row.has_value());
                REQUIRE_FALSE(row->currently_active);
            }
            THEN("bob's server is told once, with her last active time")
            {
                auto const edus = queued_presence_edus(runtime);
                REQUIRE(edus.size() == 2U);
                auto const entry = push_entry_of(edus.back());
                auto const* presence = string_member(entry, "presence");
                REQUIRE(presence != nullptr);
                REQUIRE(*presence == "unavailable");
                auto const* last_active_ago = int_member(entry, "last_active_ago");
                REQUIRE(last_active_ago != nullptr);
                REQUIRE(*last_active_ago >= 6 * minute_ms);
            }
            THEN("a second sweep changes nothing")
            {
                std::ignore = merovingian::homeserver::run_presence_idle_sweep(runtime);
                REQUIRE(queued_presence_edus(runtime).size() == 2U);
            }
            THEN("her next sync marks her online again")
            {
                REQUIRE(call(runtime, "GET", "/_matrix/client/v3/sync?timeout=0", token).status == 200U);
                REQUIRE(read_alice_presence(runtime, token) == "online");
            }
        }

        WHEN("four minutes pass and the idle sweep runs")
        {
            age_presence(runtime, local_alice, 4 * minute_ms);
            std::ignore = merovingian::homeserver::run_presence_idle_sweep(runtime);

            THEN("alice is still online and nothing more is sent")
            {
                REQUIRE(read_alice_presence(runtime, token) == "online");
                REQUIRE(queued_presence_edus(runtime).size() == 1U);
            }
        }

        WHEN("alice set herself offline, a long time ago, and the idle sweep runs")
        {
            let_presence_window_end(runtime);
            REQUIRE(put_alice_presence(runtime, token, R"({"presence":"offline"})").status == 200U);
            age_presence(runtime, local_alice, 60 * minute_ms);
            std::ignore = merovingian::homeserver::run_presence_idle_sweep(runtime);

            THEN("she is still offline: only an online user can be idle")
            {
                REQUIRE(read_alice_presence(runtime, token) == "offline");
                REQUIRE(queued_presence_edus(runtime).size() == 2U);
            }
        }

        WHEN("bob's server last reported him online long ago and the idle sweep runs")
        {
            REQUIRE(deliver_presence_edu(runtime, remote_server, push_content(remote_bob, "online")).status ==
                    merovingian::federation::EduDispositionStatus::accepted);
            age_presence(runtime, remote_bob, 60 * minute_ms);
            std::ignore = merovingian::homeserver::run_presence_idle_sweep(runtime);

            THEN("his presence is left as his server reported it: a server speaks only for its own users")
            {
                auto const row = stored_presence(runtime, remote_bob);
                REQUIRE(row.has_value());
                REQUIRE(row->presence == "online");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, Presence, "Last active ago": "A pro-active event may be sending a message
// to a room or changing presence state to `online`." A user who keeps sending is active, so the idle sweep must not
// set them unavailable (ADR-0492).
SCENARIO("A user who keeps sending messages is not set unavailable", "[integration][presence][idle][c11]")
{
    GIVEN("alice is online and has a room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_alice(runtime);
        REQUIRE(put_alice_presence(runtime, token, R"({"presence":"online"})").status == 200U);
        auto const created =
            call(runtime, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"private_chat"})");
        REQUIRE(created.status == 200U);
        auto const room_body = parse_object(created.body);
        auto const* room_id = string_member(room_body, "room_id");
        REQUIRE(room_id != nullptr);
        auto const send = [&](int number) {
            return call(runtime, "PUT",
                        "/_matrix/client/v3/rooms/" + *room_id + "/send/m.room.message/t" + std::to_string(number),
                        token, R"({"msgtype":"m.text","body":"hi"})");
        };

        WHEN("she sends a message every four minutes for twelve minutes, with the idle sweep running")
        {
            for (auto number = 1; number <= 3; ++number)
            {
                age_presence(runtime, local_alice, 4 * minute_ms);
                REQUIRE(send(number).status == 200U);
                std::ignore = merovingian::homeserver::run_presence_idle_sweep(runtime);
            }

            THEN("she is still online and currently active")
            {
                REQUIRE(read_alice_presence(runtime, token) == "online");
                auto const row = stored_presence(runtime, local_alice);
                REQUIRE(row.has_value());
                REQUIRE(row->currently_active);
            }
        }

        WHEN("she is unavailable by her own choice and sends a message")
        {
            let_presence_window_end(runtime);
            REQUIRE(put_alice_presence(runtime, token, R"({"presence":"unavailable"})").status == 200U);
            REQUIRE(send(1).status == 200U);

            THEN("she is still unavailable: a send does not change a state she chose")
            {
                REQUIRE(read_alice_presence(runtime, token) == "unavailable");
            }
        }
    }

    GIVEN("a user who has never had a presence row")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_alice(runtime);
        auto const created =
            call(runtime, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"private_chat"})");
        REQUIRE(created.status == 200U);
        auto const room_body = parse_object(created.body);
        auto const* room_id = string_member(room_body, "room_id");
        REQUIRE(room_id != nullptr);

        WHEN("she sends a message")
        {
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/rooms/" + *room_id + "/send/m.room.message/t1", token,
                         R"({"msgtype":"m.text","body":"hi"})")
                        .status == 200U);

            THEN("no presence row is made for her")
            {
                REQUIRE_FALSE(stored_presence(runtime, local_alice).has_value());
            }
        }
    }
}

// After a restart a row loaded from the database has `observed_at_ms` 0, so its stored `last_active_ago` is never
// advanced. The sweep starts that clock the first time it sees such a row (ADR-0492).
SCENARIO("An online user loaded without an observation time is swept once the clock has run",
         "[integration][presence][idle][c11]")
{
    GIVEN("a local user stored online with last_active_ago 0 and no observation time, as after a restart")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto row = merovingian::database::PersistentPresence{};
        row.user_id = std::string{local_alice};
        row.presence = "online";
        row.currently_active = true;
        REQUIRE(merovingian::database::upsert_presence(runtime.homeserver.database.persistent_store, row));
        REQUIRE(stored_presence(runtime, local_alice)->observed_at_ms == 0);

        WHEN("a sweep runs")
        {
            std::ignore = merovingian::homeserver::run_presence_idle_sweep(runtime);

            THEN("it leaves her online and starts her clock")
            {
                REQUIRE(stored_presence(runtime, local_alice)->presence == "online");
                REQUIRE(stored_presence(runtime, local_alice)->observed_at_ms > 0);
            }

            AND_WHEN("six minutes then pass and another sweep runs")
            {
                age_presence(runtime, local_alice, 6 * minute_ms);
                std::ignore = merovingian::homeserver::run_presence_idle_sweep(runtime);

                THEN("she is unavailable")
                {
                    REQUIRE(stored_presence(runtime, local_alice)->presence == "unavailable");
                }
            }
        }
    }
}

// A pass is bounded by presence_idle_max_per_pass because each user costs a commit and a scan of the rooms under
// runtime.mutex; what a pass leaves, the next one takes after a short sleep (ADR-0492).
SCENARIO("A pass of the idle sweep is bounded and the rest follow", "[integration][presence][idle][c11]")
{
    GIVEN("more online local users than one pass may set unavailable, all idle")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const total = merovingian::homeserver::presence_idle_max_per_pass + 5U;
        for (auto number = std::size_t{0U}; number < total; ++number)
        {
            auto row = merovingian::database::PersistentPresence{};
            row.user_id = "@idle" + std::to_string(number) + ":example.org";
            row.presence = "online";
            row.observed_at_ms = merovingian::homeserver::presence_now_ms() - 10 * minute_ms;
            REQUIRE(merovingian::database::upsert_presence(runtime.homeserver.database.persistent_store, row));
        }
        auto const unavailable_count = [&runtime] {
            return static_cast<std::size_t>(
                std::ranges::count_if(runtime.homeserver.database.persistent_store.presence_states, [](auto const& s) {
                    return s.presence == "unavailable";
                }));
        };
        auto const ordinary_sleep = std::chrono::duration_cast<std::chrono::milliseconds>(
            merovingian::homeserver::presence_idle_sweep_interval);

        WHEN("the sweep runs once")
        {
            auto const first_sleep = merovingian::homeserver::run_presence_idle_sweep(runtime);

            THEN("it sets at most the bound and asks to come back sooner than the ordinary interval")
            {
                REQUIRE(unavailable_count() == merovingian::homeserver::presence_idle_max_per_pass);
                REQUIRE(first_sleep < ordinary_sleep);
            }

            AND_WHEN("it runs again")
            {
                auto const second_sleep = merovingian::homeserver::run_presence_idle_sweep(runtime);

                THEN("the rest are set and it sleeps the ordinary interval")
                {
                    REQUIRE(unavailable_count() == total);
                    REQUIRE(second_sleep == ordinary_sleep);
                }
            }
        }
    }
}

// MSC4186, request body: `set_presence`, "Same as in /v3/sync, controls whether the client is automatically marked as
// online by polling this API". Omitted marks the user online; an unknown value is 400 M_INVALID_PARAM. The proposal's
// changelog calls it a URL parameter, so both are read and the body takes precedence (ADR-0495).
SCENARIO("Sliding sync honours set_presence", "[integration][presence][sliding-sync][c11]")
{
    GIVEN("a registered user with no presence row")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_alice(runtime);
        auto const poll = [&](std::string const& query, std::string const& body) {
            return call(runtime, "POST", "/_matrix/client/unstable/org.matrix.msc4186/sync" + query, token, body);
        };
        auto const state = [&runtime]() -> std::string {
            auto const row = stored_presence(runtime, local_alice);
            return row.has_value() ? row->presence : std::string{"none"};
        };

        WHEN("set_presence is omitted")
        {
            REQUIRE(poll("", "{}").status == 200U);
            THEN("she is marked online")
            {
                REQUIRE(state() == "online");
            }
        }
        WHEN("the body says unavailable")
        {
            REQUIRE(poll("", R"({"set_presence":"unavailable"})").status == 200U);
            THEN("she is marked unavailable")
            {
                REQUIRE(state() == "unavailable");
            }
        }
        WHEN("the body says offline")
        {
            REQUIRE(poll("", R"({"set_presence":"offline"})").status == 200U);
            THEN("her presence is not touched")
            {
                REQUIRE(state() == "none");
            }
        }
        WHEN("only the URL says unavailable")
        {
            REQUIRE(poll("?set_presence=unavailable", "{}").status == 200U);
            THEN("she is marked unavailable")
            {
                REQUIRE(state() == "unavailable");
            }
        }
        WHEN("the URL says unavailable and the body says offline")
        {
            REQUIRE(poll("?set_presence=unavailable", R"({"set_presence":"offline"})").status == 200U);
            THEN("the body wins and her presence is not touched")
            {
                REQUIRE(state() == "none");
            }
        }
        WHEN("the body names a value that is not a presence mode")
        {
            auto const response = poll("", R"({"set_presence":"busy"})");
            THEN("the answer is 400 M_INVALID_PARAM and nothing is stored")
            {
                REQUIRE(response.status == 400U);
                auto const body = parse_object(response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_INVALID_PARAM");
                REQUIRE(state() == "none");
            }
        }
        WHEN("the URL names a value that is not a presence mode")
        {
            THEN("the answer is 400")
            {
                REQUIRE(poll("?set_presence=busy", "{}").status == 400U);
            }
        }
    }
}

namespace
{

// A second device of alice's, for the scenarios where two clients of one account sync at once.
[[nodiscard]] auto log_alice_in_on(ClientServerRuntime& runtime, std::string_view device_id) -> std::string
{
    auto const login = call(runtime, "POST", "/_matrix/client/v3/login", {},
                            R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},)"
                            R"("password":"CorrectHorse7!","device_id":")" +
                                std::string{device_id} + R"("})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// A /sync that answers at once, asking for `mode` (online, unavailable or offline).
auto sync_once(ClientServerRuntime& runtime, std::string const& token, std::string_view mode) -> void
{
    REQUIRE(call(runtime, "GET", "/_matrix/client/v3/sync?timeout=0&set_presence=" + std::string{mode}, token).status ==
            200U);
}

[[nodiscard]] auto alice_presence_state(ClientServerRuntime const& runtime) -> std::string
{
    auto const row = stored_presence(runtime, local_alice);
    return row.has_value() ? row->presence : std::string{"none"};
}

} // namespace

// Spec: Matrix Client-Server API v1.19, Presence, "Idle timeout": "Any activity that bumps the last active time on any
// of the user's clients will cause the server to automatically set their presence to `online`."
//
// ADR-0871: a device that syncs online holds the account online for AccountPresenceTracker::device_fresh_ms, so another
// device syncing unavailable does not set it unavailable in between. Without this, a client in the foreground and one
// in the background set the presence back and forth on every sync, each change waking the other's sync and queueing an
// EDU for every server in the user's rooms.
SCENARIO("Two devices of one account syncing online and unavailable do not set its presence back and forth",
         "[integration][presence][sync][devices]")
{
    GIVEN("alice shares a room with bob on another server and her desktop has synced online")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const desktop = register_alice(runtime);
        auto const phone = log_alice_in_on(runtime, "PHONE");
        share_room_with_remote_bob(runtime);
        sync_once(runtime, desktop, "online");
        REQUIRE(alice_presence_state(runtime) == "online");
        REQUIRE(queued_presence_edus(runtime).size() == 1U);

        WHEN("her phone syncs unavailable and her desktop online, in turn, with every change window ended")
        {
            for (auto round = 0; round < 10; ++round)
            {
                let_presence_window_end(runtime);
                sync_once(runtime, phone, "unavailable");
                let_presence_window_end(runtime);
                sync_once(runtime, desktop, "online");
            }

            THEN("she stays online and bob's server was told once")
            {
                REQUIRE(alice_presence_state(runtime) == "online");
                REQUIRE(queued_presence_edus(runtime).size() == 1U);
            }
        }

        WHEN("her desktop stops syncing for longer than a device holds the account and her phone syncs unavailable")
        {
            advance_presence_clock(runtime, merovingian::homeserver::AccountPresenceTracker::device_fresh_ms);
            sync_once(runtime, phone, "unavailable");

            THEN("she is unavailable and bob's server is told")
            {
                REQUIRE(alice_presence_state(runtime) == "unavailable");
                REQUIRE(queued_presence_edus(runtime).size() == 2U);
            }
        }

        WHEN("her desktop syncs with set_presence=offline and then her phone syncs unavailable")
        {
            sync_once(runtime, desktop, "offline");
            let_presence_window_end(runtime);
            sync_once(runtime, phone, "unavailable");

            THEN("the desktop no longer holds her online, so she is unavailable")
            {
                REQUIRE(alice_presence_state(runtime) == "unavailable");
            }
        }
    }
}

// ADR-0872: the first change of an account's presence opens a window of AccountPresenceTracker::change_window_ms in
// which no other change is kept: a sync's is dropped, a PUT is answered 429 M_LIMIT_EXCEEDED, which the spec gives this
// endpoint. The first change asked for is the one kept, never the last.
//
// Spec: Matrix Client-Server API v1.19, PUT /_matrix/client/v3/presence/{userId}/status, responses 200 and 429.
SCENARIO("Only the first presence change in a window is kept", "[integration][presence][rate_limit]")
{
    GIVEN("alice shares a room with bob on another server and has just synced online")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const token = register_alice(runtime);
        share_room_with_remote_bob(runtime);
        sync_once(runtime, token, "online");
        REQUIRE(queued_presence_edus(runtime).size() == 1U);
        auto const& store = runtime.homeserver.database.persistent_store;
        auto const watermark = store.next_sync_stream_id;

        WHEN("she syncs unavailable at once")
        {
            sync_once(runtime, token, "unavailable");

            THEN("the change is dropped: nothing is stored, woken or sent")
            {
                REQUIRE(alice_presence_state(runtime) == "online");
                REQUIRE(store.next_sync_stream_id == watermark);
                REQUIRE(queued_presence_edus(runtime).size() == 1U);
            }
        }

        WHEN("she syncs unavailable once the window has ended")
        {
            let_presence_window_end(runtime);
            sync_once(runtime, token, "unavailable");

            THEN("the change is kept and bob's server is told")
            {
                REQUIRE(alice_presence_state(runtime) == "unavailable");
                REQUIRE(queued_presence_edus(runtime).size() == 2U);
            }
        }

        WHEN("she sets her presence at once")
        {
            auto const put = put_alice_presence(runtime, token, R"({"presence":"unavailable","status_msg":"away"})");

            THEN("it is refused with 429 M_LIMIT_EXCEEDED and when to retry, and nothing is stored or sent")
            {
                REQUIRE(put.status == 429U);
                auto const body = parse_object(put.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_LIMIT_EXCEEDED");
                auto const* retry_after_ms = int_member(body, "retry_after_ms");
                REQUIRE(retry_after_ms != nullptr);
                REQUIRE(*retry_after_ms > 0);
                REQUIRE(*retry_after_ms <= merovingian::homeserver::AccountPresenceTracker::change_window_ms);
                REQUIRE(alice_presence_state(runtime) == "online");
                REQUIRE(store.next_sync_stream_id == watermark);
                REQUIRE(queued_presence_edus(runtime).size() == 1U);
            }
        }

        WHEN("she sets her presence once the window has ended")
        {
            let_presence_window_end(runtime);
            auto const put = put_alice_presence(runtime, token, R"({"presence":"unavailable"})");

            THEN("it is stored and sent")
            {
                REQUIRE(put.status == 200U);
                REQUIRE(alice_presence_state(runtime) == "unavailable");
                REQUIRE(queued_presence_edus(runtime).size() == 2U);
            }
        }
    }
}

// ADR-0872: a sync that leaves the stored presence as it is changes nothing, so it opens no window. Without this, a
// client polling /sync (an omitted set_presence asks for online) could never change its presence: every poll would
// open a window, and PUT /presence would answer 429.
SCENARIO("A sync that leaves the presence as it is opens no change window", "[integration][presence][rate_limit]")
{
    GIVEN("alice shares a room with bob on another server and her change to online has had its window end")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const token = register_alice(runtime);
        share_room_with_remote_bob(runtime);
        sync_once(runtime, token, "online");
        let_presence_window_end(runtime);
        REQUIRE(queued_presence_edus(runtime).size() == 1U);

        WHEN("she syncs online again, which changes nothing, and at once sets her presence unavailable")
        {
            sync_once(runtime, token, "online");
            auto const put = put_alice_presence(runtime, token, R"({"presence":"unavailable"})");

            THEN("the change is kept and sent")
            {
                REQUIRE(put.status == 200U);
                REQUIRE(alice_presence_state(runtime) == "unavailable");
                REQUIRE(queued_presence_edus(runtime).size() == 2U);
            }
        }

        WHEN("she is set unavailable, the window ends, she syncs unavailable, and at once sets her presence online")
        {
            // Offline forgets the device's online ask, so the unavailable sync below is judged on the stored state
            // alone.
            sync_once(runtime, token, "offline");
            REQUIRE(put_alice_presence(runtime, token, R"({"presence":"unavailable"})").status == 200U);
            let_presence_window_end(runtime);
            sync_once(runtime, token, "unavailable");
            auto const put = put_alice_presence(runtime, token, R"({"presence":"online"})");

            THEN("the unavailable sync changed nothing, so the change is kept and sent")
            {
                REQUIRE(put.status == 200U);
                REQUIRE(alice_presence_state(runtime) == "online");
                REQUIRE(queued_presence_edus(runtime).size() == 3U);
            }
        }
    }
}

// ADR-0872: a change dropped in a window is dropped, never kept for later. A long-polling sync whose change was
// dropped is run again after a wake-up or its timeout (`rerun_waiting_sync`); that rerun is the same request and does
// not apply its `set_presence` again, even once the window has ended.
SCENARIO("A parked sync run again does not apply its set_presence a second time", "[integration][presence][long_poll]")
{
    GIVEN("alice shares a room with bob on another server, set herself online, and holds a next_batch")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const token = register_alice(runtime);
        share_room_with_remote_bob(runtime);
        REQUIRE(put_alice_presence(runtime, token, R"({"presence":"online"})").status == 200U);
        auto const initial = call(runtime, "GET", "/_matrix/client/v3/sync?timeout=0&set_presence=offline", token);
        REQUIRE(initial.status == 200U);
        auto const initial_body = parse_object(initial.body);
        auto const* since = string_member(initial_body, "next_batch");
        REQUIRE(since != nullptr);
        REQUIRE(queued_presence_edus(runtime).size() == 1U);

        WHEN("she long-polls asking for unavailable inside the window, and the poll is run again once it has ended")
        {
            auto const long_poll = merovingian::homeserver::LocalHttpRequest{
                "GET", "/_matrix/client/v3/sync?timeout=30000&set_presence=unavailable&since=" + *since, token, {}};
            auto const first = merovingian::homeserver::handle_client_server_request(runtime, long_poll);
            REQUIRE(first.status == merovingian::homeserver::DispatchResult::Status::needs_wait);
            let_presence_window_end(runtime);
            auto const rerun = merovingian::homeserver::handle_client_server_request(
                runtime, long_poll,
                merovingian::homeserver::ClientServerDispatchOptions{
                    .can_wait = false, .rate_limit_admitted = true, .sync_rerun = true});

            THEN("the dropped change stays dropped: she is still online and bob's server is told nothing more")
            {
                REQUIRE(rerun.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(alice_presence_state(runtime) == "online");
                REQUIRE(queued_presence_edus(runtime).size() == 1U);
            }
        }
    }
}

namespace
{

constexpr auto sliding_sync_target = std::string_view{"/_matrix/client/unstable/org.matrix.msc4186/sync"};

// The `pos` of a sliding sync that answers at once and leaves alice's presence alone.
[[nodiscard]] auto sliding_sync_pos(ClientServerRuntime& runtime, std::string const& token) -> std::string
{
    auto const synced = call(runtime, "POST", std::string{sliding_sync_target}, token, R"({"set_presence":"offline"})");
    REQUIRE(synced.status == 200U);
    auto const body = parse_object(synced.body);
    auto const* pos = string_member(body, "pos");
    REQUIRE(pos != nullptr);
    return *pos;
}

} // namespace

SCENARIO("A parked sliding sync run again does not apply its set_presence a second time",
         "[integration][presence][sliding-sync][long_poll]")
{
    GIVEN("alice shares a room with bob on another server, set herself online, and holds a sliding sync pos")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const token = register_alice(runtime);
        share_room_with_remote_bob(runtime);
        REQUIRE(put_alice_presence(runtime, token, R"({"presence":"online"})").status == 200U);
        auto const pos = sliding_sync_pos(runtime, token);
        REQUIRE(queued_presence_edus(runtime).size() == 1U);

        WHEN("she long-polls asking for unavailable inside the window, and the poll is run again once it has ended")
        {
            auto const long_poll = merovingian::homeserver::LocalHttpRequest{
                "POST", std::string{sliding_sync_target} + "?timeout=30000&pos=" + pos, token,
                R"({"set_presence":"unavailable"})"};
            auto const first = merovingian::homeserver::handle_client_server_request(runtime, long_poll);
            REQUIRE(first.status == merovingian::homeserver::DispatchResult::Status::needs_wait);
            let_presence_window_end(runtime);
            auto const rerun = merovingian::homeserver::handle_client_server_request(
                runtime, long_poll,
                merovingian::homeserver::ClientServerDispatchOptions{
                    .can_wait = false, .rate_limit_admitted = true, .sync_rerun = true});

            THEN("the dropped change stays dropped: she is still online and bob's server is told nothing more")
            {
                REQUIRE(rerun.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(alice_presence_state(runtime) == "online");
                REQUIRE(queued_presence_edus(runtime).size() == 1U);
            }
        }
    }
}

// MSC4186: "Servers MUST reject a `pos` that was not issued to the requesting user and device", and a pos from another
// stream epoch is unknown too (ADR-0592). A refused request does nothing else, so its set_presence opens no ADR-0872
// window that would make a later PUT /presence 429.
SCENARIO("A sliding sync refused for an unknown pos changes no presence", "[integration][presence][sliding-sync]")
{
    GIVEN("a registered user with no presence row")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_alice(runtime);

        WHEN("she sliding-syncs with a pos this server never issued, asking for unavailable")
        {
            auto const refused = call(runtime, "POST", std::string{sliding_sync_target} + "?pos=not-issued", token,
                                      R"({"set_presence":"unavailable"})");

            THEN("it is 400 M_UNKNOWN_POS, nothing is stored, and her presence may be set at once")
            {
                REQUIRE(refused.status == 400U);
                auto const body = parse_object(refused.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNKNOWN_POS");
                REQUIRE(alice_presence_state(runtime) == "none");
                REQUIRE(put_alice_presence(runtime, token, R"({"presence":"online"})").status == 200U);
            }
        }

        WHEN("she sliding-syncs with a pos this server issued before a restore moved the stream epoch on")
        {
            auto const pos = sliding_sync_pos(runtime, token);
            runtime.homeserver.database.persistent_store.stream_token_epoch += 1U;
            auto const refused = call(runtime, "POST", std::string{sliding_sync_target} + "?pos=" + pos, token,
                                      R"({"set_presence":"unavailable"})");

            THEN("it is 400 M_UNKNOWN_POS, nothing is stored, and her presence may be set at once")
            {
                REQUIRE(refused.status == 400U);
                auto const body = parse_object(refused.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNKNOWN_POS");
                REQUIRE(alice_presence_state(runtime) == "none");
                REQUIRE(put_alice_presence(runtime, token, R"({"presence":"online"})").status == 200U);
            }
        }
    }
}

// ADR-0871: a device is one device whichever sync API it uses, so the hold one transport takes is released by the
// other's set_presence=offline.
SCENARIO("A device's hold taken through sliding sync is released by its classic sync",
         "[integration][presence][sliding-sync][devices]")
{
    GIVEN("alice's desktop sliding-synced online and she has a phone too")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const desktop = register_alice(runtime);
        auto const phone = log_alice_in_on(runtime, "PHONE");
        REQUIRE(call(runtime, "POST", std::string{sliding_sync_target}, desktop, "{}").status == 200U);
        REQUIRE(alice_presence_state(runtime) == "online");
        let_presence_window_end(runtime);

        WHEN("the phone syncs asking for unavailable while the desktop holds the account")
        {
            sync_once(runtime, phone, "unavailable");

            THEN("she stays online")
            {
                REQUIRE(alice_presence_state(runtime) == "online");
            }
        }

        WHEN("the desktop's classic sync says offline, and then the phone asks for unavailable")
        {
            sync_once(runtime, desktop, "offline");
            sync_once(runtime, phone, "unavailable");

            THEN("the desktop no longer holds the account, so she becomes unavailable")
            {
                REQUIRE(alice_presence_state(runtime) == "unavailable");
            }
        }
    }
}

// ADR-0872: at its cap, with every account in its window, the presence tracker refuses a change of an account it does
// not hold (fails closed), so a flood of accounts cannot lift the limit for itself. The refusal says so and waits for
// the soonest window to end.
SCENARIO("A presence change is refused while the presence tracker is full", "[integration][presence][rate_limit]")
{
    GIVEN("alice shares a room with bob on another server, and the tracker is full of accounts that just changed")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const token = register_alice(runtime);
        share_room_with_remote_bob(runtime);
        using merovingian::homeserver::AccountPresenceTracker;
        auto& tracker = runtime.homeserver.presence_tracker;
        auto const now_ms = merovingian::homeserver::presence_limit_clock_ms(runtime.homeserver);
        for (auto index = std::size_t{0U}; index < AccountPresenceTracker::max_accounts; ++index)
        {
            // Started a window ahead, so no window can end while the scenario runs on the live clock.
            tracker.note_change("@user" + std::to_string(index) + ":other.example",
                                now_ms + AccountPresenceTracker::change_window_ms);
        }
        auto const& store = runtime.homeserver.database.persistent_store;
        auto const watermark = store.next_sync_stream_id;

        WHEN("she sets her presence")
        {
            auto const put = put_alice_presence(runtime, token, R"({"presence":"online"})");

            THEN("it is 429 naming the full tracker, told to wait for the soonest window, and nothing is kept")
            {
                REQUIRE(put.status == 429U);
                auto const body = parse_object(put.body);
                auto const* error = string_member(body, "error");
                REQUIRE(error != nullptr);
                REQUIRE(*error == "too many accounts are changing presence");
                auto const* retry_after_ms = int_member(body, "retry_after_ms");
                REQUIRE(retry_after_ms != nullptr);
                REQUIRE(*retry_after_ms > 0);
                REQUIRE(*retry_after_ms <= AccountPresenceTracker::change_window_ms);
                REQUIRE(alice_presence_state(runtime) == "none");
                REQUIRE(store.next_sync_stream_id == watermark);
                REQUIRE(queued_presence_edus(runtime).empty());
                REQUIRE(tracker.full_refusals() == 1U);
            }
        }

        WHEN("she syncs, which asks for online")
        {
            sync_once(runtime, token, "online");

            THEN("the change is dropped: nothing is stored or sent, and the tracker does not grow")
            {
                REQUIRE(alice_presence_state(runtime) == "none");
                REQUIRE(queued_presence_edus(runtime).empty());
                REQUIRE(tracker.account_count() == AccountPresenceTracker::max_accounts);
                REQUIRE(tracker.full_refusals() == 1U);
            }
        }
    }
}

// ADR-0873: a /sync never sends the caller their own presence, so a long-poll whose only news is the caller's own
// presence row would be answered with nothing, and its client would sync again at once. It keeps waiting instead, as
// sliding sync does for what its response does not send (ADR-0869).
SCENARIO("A long-polling /sync whose only news is the caller's own presence keeps waiting",
         "[integration][presence][sync][long_poll]")
{
    GIVEN("alice has synced with set_presence=offline and holds its next_batch")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(presence_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_alice(runtime);
        auto const initial = call(runtime, "GET", "/_matrix/client/v3/sync?timeout=0&set_presence=offline", token);
        REQUIRE(initial.status == 200U);
        auto const initial_body = parse_object(initial.body);
        auto const* since = string_member(initial_body, "next_batch");
        REQUIRE(since != nullptr);
        auto const long_poll = merovingian::homeserver::LocalHttpRequest{
            "GET", "/_matrix/client/v3/sync?timeout=30000&since=" + *since, token, {}};
        auto const& store = runtime.homeserver.database.persistent_store;

        WHEN("she long-polls from it without set_presence, which marks her online")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(runtime, long_poll);

            THEN("she is online and the sync waits past her own presence row")
            {
                REQUIRE(alice_presence_state(runtime) == "online");
                REQUIRE(result.status == merovingian::homeserver::DispatchResult::Status::needs_wait);
                REQUIRE(result.wait.since_sync_stream_id == store.next_sync_stream_id);
            }
        }

        WHEN("she long-polls from it with full_state=true and nothing new to send")
        {
            std::ignore = merovingian::homeserver::handle_client_server_request(runtime, long_poll);
            auto const full_state = merovingian::homeserver::LocalHttpRequest{
                "GET", "/_matrix/client/v3/sync?timeout=30000&full_state=true&since=" + *since, token, {}};
            auto const result = merovingian::homeserver::handle_client_server_request(runtime, full_state);

            THEN("the timeout is ignored and it is answered at once, as the spec requires")
            {
                REQUIRE(result.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(result.response.status == 200U);
            }
        }

        WHEN("something else is stored for her after her own presence, and the sync runs again")
        {
            std::ignore = merovingian::homeserver::handle_client_server_request(runtime, long_poll);
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/org.example.a",
                         token, R"({"a":1})")
                        .status == 200U);
            auto const result = merovingian::homeserver::handle_client_server_request(runtime, long_poll);

            THEN("it is answered")
            {
                REQUIRE(result.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(result.response.status == 200U);
            }
        }
    }
}
