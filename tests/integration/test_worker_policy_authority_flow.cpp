// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Main, not a federation worker, is authoritative for the admin's federation policy rules (F-21) and for a
// room's m.room.server_acl (F-24). A worker's store is a snapshot (PostgreSQL workers hold no policy rules at
// all; only the shard that owns a room is told when it changes), and a worker is assumed compromisable, so
// everything it relays to main (pdu_ingest, membership_ingest, invite_ingest) is judged again against main's own
// store. A relay that crosses the worker's decision is the "stale worker" case the tests below model: the
// relayed event is perfectly valid and signed, only main's current rule or ACL says no.
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md, "Server Access Control Lists (ACLs)": the send_join,
// send_leave, send_knock and invite endpoints MUST be protected by the room's ACL, and for /send "ACLs MUST be
// applied to all PDUs on a per-PDU basis. If the sending server is denied access to the room identified by
// `room_id`, the PDU MUST be ignored with an appropriate error included in the response for the respective event
// ID."
// Tags: [worker_policy_authority].

#include "../FederationSigningTestSupport.hpp"
#include "../support/RemoteRoomFixture.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/InboundIngestion.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/PduIngestionStatus.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/WorkerPool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian;
using namespace merovingian::tests::remote_room;
using merovingian::federation::InboundPduEnvelope;
using merovingian::federation::PduIngestionStatus;

// A server that relays the remote server's events: the transport origin of the relay, not the event's sender.
constexpr auto relaying_server = "relay.example.org";

enum class RelayPath
{
    pdu,
    membership,
    invite
};

constexpr auto relay_paths = std::array{RelayPath::pdu, RelayPath::membership, RelayPath::invite};

[[nodiscard]] auto relay_path_name(RelayPath path) -> std::string_view
{
    return path == RelayPath::pdu          ? "pdu_ingest"
           : path == RelayPath::membership ? "membership_ingest"
                                           : "invite_ingest";
}

[[nodiscard]] auto string_array(std::vector<std::string> const& values) -> canonicaljson::Value
{
    auto array = canonicaljson::Array{};
    for (auto const& value : values)
    {
        array.push_back(canonicaljson::Value{value});
    }
    return canonicaljson::Value{std::move(array)};
}

// The frame a worker sends, built the way WorkerEventLoop.cpp's append_envelope_fields does. `origin` is the
// transport origin the worker names; the event is signed by the remote server whatever it is.
[[nodiscard]] auto relay_frame(RelayPath path, InboundPduEnvelope const& env, std::string_view origin) -> std::string
{
    auto obj = canonicaljson::Object{};
    if (path == RelayPath::invite)
    {
        obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"invite_ingest"}}));
        obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{env.room_id}));
        obj.push_back(canonicaljson::make_member("event_id", canonicaljson::Value{env.event_id}));
        obj.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{room_version}}));
        obj.push_back(canonicaljson::make_member("invite_event_json", canonicaljson::Value{env.json}));
        obj.push_back(canonicaljson::make_member("origin", canonicaljson::Value{std::string{origin}}));
        obj.push_back(
            canonicaljson::make_member("invite_room_state_json", canonicaljson::Value{canonicaljson::Array{}}));
    }
    else
    {
        obj.push_back(canonicaljson::make_member(
            "type", canonicaljson::Value{std::string{path == RelayPath::pdu ? "pdu_ingest" : "membership_ingest"}}));
        if (path == RelayPath::membership)
        {
            obj.push_back(canonicaljson::make_member("endpoint", canonicaljson::Value{std::string{"send_leave"}}));
        }
        obj.push_back(canonicaljson::make_member("event_id", canonicaljson::Value{env.event_id}));
        obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{env.room_id}));
        obj.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{room_version}}));
        obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{env.sender}));
        obj.push_back(canonicaljson::make_member("event_type", canonicaljson::Value{env.event_type}));
        obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{env.origin_server_ts}));
        obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{static_cast<std::int64_t>(env.depth)}));
        obj.push_back(canonicaljson::make_member("json", canonicaljson::Value{env.json}));
        obj.push_back(canonicaljson::make_member("origin", canonicaljson::Value{std::string{origin}}));
        if (env.state_key.has_value())
        {
            obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{*env.state_key}));
        }
        obj.push_back(canonicaljson::make_member("auth_event_ids", string_array(env.auth_event_ids)));
        obj.push_back(canonicaljson::make_member("prev_event_ids", string_array(env.prev_event_ids)));
        obj.push_back(canonicaljson::make_member("signatures", canonicaljson::Value{canonicaljson::Array{}}));
    }
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

struct RelayedEvent final
{
    InboundPduEnvelope envelope;
    std::string room_id;
};

// A valid, correctly signed event of the remote member for `path`, in a room seeded for it.
[[nodiscard]] auto make_relayed_event(homeserver::HomeserverRuntime& runtime, RelayPath path, std::string room_id,
                                      std::int64_t sequence) -> RelayedEvent
{
    seed_room_with_genesis_state_group(runtime, room_id);
    auto const prev = std::vector<std::string>{room_id + ":member"};
    auto const auth = std::vector<std::string>{room_id + ":create", room_id + ":pl", room_id + ":member:bob"};
    auto json = std::string{};
    if (path == RelayPath::pdu)
    {
        json = make_remote_message_json(room_id, prev, auth, 4, sequence);
    }
    else
    {
        auto content = canonicaljson::Object{};
        content.push_back(canonicaljson::make_member(
            "membership", canonicaljson::Value{std::string{path == RelayPath::invite ? "invite" : "leave"}}));
        auto const state_key =
            path == RelayPath::invite ? std::string{"@alice:"} + local_server : std::string{remote_member};
        json = make_remote_event_json(room_id, "m.room.member", state_key, remote_member, std::move(content), prev,
                                      auth, 4, sequence);
    }
    auto envelope = federation::parse_inbound_pdu_envelope(json, room_version);
    REQUIRE(envelope.has_value());
    envelope->origin = remote_server;
    return {*envelope, std::move(room_id)};
}

// Whether the relay was taken in: accepted for a PDU, `accepted` for the other two.
[[nodiscard]] auto relay_once(homeserver::HomeserverRuntime& runtime, RelayPath path, RelayedEvent const& event,
                              std::string_view origin) -> bool
{
    auto const frame = relay_frame(path, event.envelope, origin);
    if (path == RelayPath::pdu)
    {
        return homeserver::handle_pdu_ingest_request(runtime, frame).status == PduIngestionStatus::accepted;
    }
    auto const response = path == RelayPath::membership ? homeserver::handle_membership_ingest_request(runtime, frame)
                                                        : homeserver::handle_invite_ingest_request(runtime, frame);
    return response.find(R"("accepted":true)") != std::string::npos;
}

// Whether main refused the relay for the operator's policy on the event's author. The membership and invite handlers
// also require the origin to be the author's server, so "not taken in" alone says nothing about this policy there.
[[nodiscard]] auto relay_refused_for_author_policy(homeserver::HomeserverRuntime& runtime, RelayPath path,
                                                   RelayedEvent const& event, std::string_view origin) -> bool
{
    auto constexpr refusal = std::string_view{"server is denied by operator policy"};
    auto const frame = relay_frame(path, event.envelope, origin);
    if (path == RelayPath::pdu)
    {
        auto const result = homeserver::handle_pdu_ingest_request(runtime, frame);
        return result.status == PduIngestionStatus::rejected_acl && result.reason == refusal;
    }
    auto const response = path == RelayPath::membership ? homeserver::handle_membership_ingest_request(runtime, frame)
                                                        : homeserver::handle_invite_ingest_request(runtime, frame);
    return response.find(refusal) != std::string::npos;
}

// Everything persistent a relay could change, so "nothing stored" is checked as state, not as one event's absence.
struct StoreShape final
{
    std::size_t events{};
    std::size_t memberships{};
    std::size_t invites{};
    std::size_t state{};
    std::uint64_t next_stream_ordering{};

    [[nodiscard]] auto operator==(StoreShape const&) const -> bool = default;
};

[[nodiscard]] auto store_shape(homeserver::HomeserverRuntime const& runtime) -> StoreShape
{
    auto const& store = runtime.database.persistent_store;
    return {store.events.size(), store.memberships.size(), store.invites.size(), store.state.size(),
            runtime.database.next_stream_ordering};
}

[[nodiscard]] auto event_stored(homeserver::HomeserverRuntime const& runtime, std::string_view event_id) -> bool
{
    return std::ranges::any_of(runtime.database.persistent_store.events, [&](database::PersistentEvent const& event) {
        return event.event_id == event_id;
    });
}

// A room's current m.room.server_acl denying `denied_server`, in main's store.
auto install_server_acl(homeserver::HomeserverRuntime& runtime, std::string const& room_id,
                        std::string const& denied_server) -> void
{
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("allow", string_array({"*"})));
    content.push_back(canonicaljson::make_member("deny", string_array({denied_server})));
    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.server_acl"}}));
    obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{}}));
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{local_admin}}));
    obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    auto& store = runtime.database.persistent_store;
    auto const event_id = room_id + ":acl";
    store.events.push_back({event_id, room_id, local_admin, serialized.output, 5U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.server_acl", "", event_id});
}

auto set_federation_policy_rule(homeserver::HomeserverRuntime& runtime, std::string const& server,
                                std::string const& action) -> void
{
    runtime.database.persistent_store.policy_rules.push_back({"rule-" + server, "federation", server, action, ""});
}

struct StartedMain final
{
    std::filesystem::path path;
    homeserver::RuntimeStartResult started;
};

[[nodiscard]] auto start_main(std::string_view prefix) -> StartedMain
{
    auto path = unique_sqlite_path(prefix);
    std::filesystem::remove(path);
    auto started = homeserver::start_runtime(config_with_sqlite(path));
    REQUIRE(started.started);
    return {std::move(path), std::move(started)};
}

auto prepare(homeserver::HomeserverRuntime& runtime) -> void
{
    homeserver::wire_federation_callbacks(runtime);
    runtime.database.users.push_back({std::string{"@alice:"} + local_server, "", false, false, false});
    runtime.federation.cached_pdu_key_lookup = {};
    runtime.federation.remote_key_resolver = genuine_key_resolver();
}

// A fresh main runtime with a room and a valid signed event for `path`. Each check below starts from one, so a
// refusal is never the leftover of an earlier relay. The runtime is built in place and never moved once its
// federation callbacks are wired (they capture its address).
class RelayCase final
{
public:
    RelayCase(RelayPath path, std::string_view prefix, std::int64_t sequence)
        : main_runtime_{start_main(prefix)}
        , event_{seeded_event(main_runtime_.started.runtime, path, prefix, sequence)}
    {
    }

    RelayCase(RelayCase const&) = delete;
    auto operator=(RelayCase const&) -> RelayCase& = delete;
    RelayCase(RelayCase&&) = delete;
    auto operator=(RelayCase&&) -> RelayCase& = delete;

    ~RelayCase()
    {
        std::filesystem::remove(main_runtime_.path);
    }

    [[nodiscard]] auto runtime() -> homeserver::HomeserverRuntime&
    {
        return main_runtime_.started.runtime;
    }
    [[nodiscard]] auto event() const -> RelayedEvent const&
    {
        return event_;
    }

private:
    [[nodiscard]] static auto seeded_event(homeserver::HomeserverRuntime& runtime, RelayPath path,
                                           std::string_view prefix, std::int64_t sequence) -> RelayedEvent
    {
        prepare(runtime);
        return make_relayed_event(
            runtime, path, "!" + std::string{prefix} + std::to_string(sequence) + ":local.example.org", sequence);
    }

    StartedMain main_runtime_;
    RelayedEvent event_;
};

} // namespace

// F-24: the worker that relayed the event had a snapshot without the room's current ACL.
// (The checks loop inside THEN: a Catch2 section inside a loop runs for its first pass only.)
SCENARIO("main refuses a relayed event that the room's own server ACL denies, whatever the worker decided",
         "[integration][federation-worker][worker_policy_authority][f24]")
{
    GIVEN("a room whose current m.room.server_acl, in main's store, denies the remote server")
    {
        WHEN("the worker relays an event that server signed, naming that server as the transport origin")
        {
            THEN("main does not take it in and stores nothing, on each relay path")
            {
                auto sequence = std::int64_t{10};
                for (auto const path : relay_paths)
                {
                    CAPTURE(relay_path_name(path));
                    auto relay_case = RelayCase{path, "acl-origin", sequence++};
                    auto& runtime = relay_case.runtime();
                    install_server_acl(runtime, relay_case.event().room_id, remote_server);
                    auto const before = store_shape(runtime);

                    CHECK_FALSE(relay_once(runtime, path, relay_case.event(), remote_server));
                    CHECK(store_shape(runtime) == before);
                    CHECK_FALSE(event_stored(runtime, relay_case.event().envelope.event_id));
                }
            }
        }

        WHEN("the worker relays that server's event through an allowed peer, as another transport origin")
        {
            THEN("main still refuses a PDU or membership event for the server its sender belongs to")
            {
                auto sequence = std::int64_t{20};
                for (auto const path : {RelayPath::pdu, RelayPath::membership})
                {
                    CAPTURE(relay_path_name(path));
                    auto relay_case = RelayCase{path, "acl-sender", sequence++};
                    auto& runtime = relay_case.runtime();
                    install_server_acl(runtime, relay_case.event().room_id, remote_server);
                    auto const before = store_shape(runtime);

                    CHECK_FALSE(relay_once(runtime, path, relay_case.event(), relaying_server));
                    CHECK(store_shape(runtime) == before);
                    CHECK_FALSE(event_stored(runtime, relay_case.event().envelope.event_id));
                }
            }
        }

        WHEN("the room's ACL names some other server")
        {
            THEN("the same relays are taken in, so the refusals above are the ACL's and nothing else's")
            {
                auto sequence = std::int64_t{30};
                for (auto const path : relay_paths)
                {
                    CAPTURE(relay_path_name(path));
                    auto relay_case = RelayCase{path, "acl-control", sequence++};
                    auto& runtime = relay_case.runtime();
                    install_server_acl(runtime, relay_case.event().room_id, "someone-else.example.org");

                    CHECK(relay_once(runtime, path, relay_case.event(), remote_server));
                }
            }
        }
    }
}

// F-21: a rule added while the request was in flight, or never seen by the worker, still holds in main.
SCENARIO("main refuses a relayed event from an origin an admin's federation policy rule denies",
         "[integration][federation-worker][worker_policy_authority][f21]")
{
    GIVEN("a federation-scope policy rule in main's store that the relaying worker never saw")
    {
        WHEN("the rule denies the origin and the worker relays a valid signed event from it")
        {
            THEN("main does not take it in and stores nothing, on each relay path")
            {
                auto sequence = std::int64_t{40};
                for (auto const path : relay_paths)
                {
                    for (std::string_view const action_name : {"deny", "quarantine"})
                    {
                        CAPTURE(relay_path_name(path), action_name);
                        auto relay_case = RelayCase{path, "rule-origin", sequence++};
                        auto& runtime = relay_case.runtime();
                        set_federation_policy_rule(runtime, remote_server, std::string{action_name});
                        auto const before = store_shape(runtime);

                        CHECK_FALSE(relay_once(runtime, path, relay_case.event(), remote_server));
                        CHECK(store_shape(runtime) == before);
                        CHECK_FALSE(event_stored(runtime, relay_case.event().envelope.event_id));
                    }
                }
            }
        }

        WHEN("the rule names a different origin, or is an explicit allow")
        {
            THEN("the same relays are taken in, so the refusals above are the rule's and nothing else's")
            {
                auto sequence = std::int64_t{60};
                for (auto const path : relay_paths)
                {
                    for (auto const& [server, action] : {
                             std::pair<std::string, std::string>{"someone-else.example.org", "deny" },
                             std::pair<std::string, std::string>{remote_server,              "allow"}
                    })
                    {
                        CAPTURE(relay_path_name(path), server, action);
                        auto relay_case = RelayCase{path, "rule-control", sequence++};
                        auto& runtime = relay_case.runtime();
                        set_federation_policy_rule(runtime, server, action);

                        CHECK(relay_once(runtime, path, relay_case.event(), remote_server));
                    }
                }
            }
        }
    }
}

// F-72 (ADR-0390): the server that wrote the event is held to the operator's policy, whoever carries it.
// (The checks loop inside THEN: a Catch2 section inside a loop runs for its first pass only.)
SCENARIO("main refuses a relayed event whose sender's server the operator's policy excludes",
         "[integration][federation-worker][worker_policy_authority][operator-policy]")
{
    auto constexpr allowed_relay = std::string_view{"allowed-relay.example.org"};

    GIVEN("an allowed origin relaying a valid signed event written by another server")
    {
        WHEN("an admin rule denies or quarantines the sender's server")
        {
            THEN("main does not take it in and stores nothing, on each relay path")
            {
                auto sequence = std::int64_t{80};
                for (auto const path : relay_paths)
                {
                    for (std::string_view const action_name : {"deny", "quarantine"})
                    {
                        CAPTURE(relay_path_name(path), action_name);
                        auto relay_case = RelayCase{path, "rule-sender", sequence++};
                        auto& runtime = relay_case.runtime();
                        set_federation_policy_rule(runtime, remote_server, std::string{action_name});
                        auto const before = store_shape(runtime);

                        CHECK(relay_refused_for_author_policy(runtime, path, relay_case.event(), allowed_relay));
                        CHECK(store_shape(runtime) == before);
                        CHECK_FALSE(event_stored(runtime, relay_case.event().envelope.event_id));
                    }
                }
            }
        }

        WHEN("the sender's server is in denied_servers")
        {
            THEN("main does not take it in, looks up no key for that server, and stores nothing")
            {
                auto sequence = std::int64_t{100};
                for (auto const path : relay_paths)
                {
                    CAPTURE(relay_path_name(path));
                    auto relay_case = RelayCase{path, "config-sender", sequence++};
                    auto& runtime = relay_case.runtime();
                    runtime.federation.config.denied_servers.emplace_back(remote_server);
                    auto key_lookups = std::make_shared<std::atomic<int>>(0);
                    runtime.federation.remote_key_resolver =
                        [key_lookups](std::string_view,
                                      std::string_view) -> std::optional<federation::FederationRemoteRuntime> {
                        ++*key_lookups;
                        return std::nullopt;
                    };
                    auto const before = store_shape(runtime);

                    CHECK(relay_refused_for_author_policy(runtime, path, relay_case.event(), allowed_relay));
                    CHECK(key_lookups->load() == 0);
                    CHECK(store_shape(runtime) == before);
                }
            }
        }

        WHEN("the rule names a different server")
        {
            THEN("none of the relays is refused for this policy, and the PDU is taken in")
            {
                auto sequence = std::int64_t{120};
                for (auto const path : relay_paths)
                {
                    CAPTURE(relay_path_name(path));
                    auto relay_case = RelayCase{path, "rule-sender-control", sequence++};
                    auto& runtime = relay_case.runtime();
                    set_federation_policy_rule(runtime, "someone-else.example.org", "deny");

                    CHECK_FALSE(relay_refused_for_author_policy(runtime, path, relay_case.event(), allowed_relay));
                }
                auto relay_case = RelayCase{RelayPath::pdu, "rule-sender-accepted", sequence++};
                auto& runtime = relay_case.runtime();
                set_federation_policy_rule(runtime, "someone-else.example.org", "deny");

                CHECK(relay_once(runtime, RelayPath::pdu, relay_case.event(), allowed_relay));
            }
        }
    }
}

// F-24: what /send reports for the PDU, so the sender is told.
SCENARIO("a PDU main refuses for the room ACL is reported to the worker as a refusal, not as handled",
         "[integration][federation-worker][worker_policy_authority][f24]")
{
    GIVEN("a room whose ACL in main's store denies the remote server")
    {
        auto main_runtime = start_main("policy-authority-status");
        auto& runtime = main_runtime.started.runtime;
        prepare(runtime);
        auto const event = make_relayed_event(runtime, RelayPath::pdu, "!acl-status:local.example.org", 90);
        install_server_acl(runtime, event.room_id, remote_server);

        WHEN("the worker relays a PDU of that server")
        {
            auto const result = homeserver::handle_pdu_ingest_request(
                runtime, relay_frame(RelayPath::pdu, event.envelope, remote_server));

            THEN("the answer says the PDU was refused for the ACL, which /send reports as an error for its event ID")
            {
                CHECK(result.status == PduIngestionStatus::rejected_acl);
                CHECK(result.reason.find("ACL") != std::string::npos);
            }
        }
        std::filesystem::remove(main_runtime.path);
    }
}

// F-14 (security audit run 4): the invite relay judged only the origin the worker named. A blank origin skipped the
// origin ACL and the invite handler's sender-equals-origin guard, and no ACL was applied to the verified inviter's
// server.
SCENARIO("main applies the room ACL to the verified inviter of a relayed invite, and refuses a blank origin",
         "[integration][federation-worker][worker_policy_authority][f14]")
{
    GIVEN("a room whose current m.room.server_acl, in main's store, denies the remote server")
    {
        WHEN("the worker relays that server's signed invite with a blank origin")
        {
            THEN("main refuses it and stores nothing, as it does for the same frame sent as a PDU")
            {
                auto relay_case = RelayCase{RelayPath::invite, "invite-blank", 100};
                auto& runtime = relay_case.runtime();
                install_server_acl(runtime, relay_case.event().room_id, remote_server);
                auto const before = store_shape(runtime);

                CHECK_FALSE(relay_once(runtime, RelayPath::invite, relay_case.event(), ""));
                CHECK(store_shape(runtime) == before);
                CHECK_FALSE(event_stored(runtime, relay_case.event().envelope.event_id));
            }
        }

        WHEN("the worker relays it through an allowed peer, as another transport origin")
        {
            THEN("main refuses it for the ACL on the inviter's server")
            {
                auto relay_case = RelayCase{RelayPath::invite, "invite-peer", 101};
                auto& runtime = relay_case.runtime();
                install_server_acl(runtime, relay_case.event().room_id, remote_server);
                auto const before = store_shape(runtime);

                auto const frame = relay_frame(RelayPath::invite, relay_case.event().envelope, relaying_server);
                auto const response = homeserver::handle_invite_ingest_request(runtime, frame);
                CHECK(response.find("server is denied by room ACL") != std::string::npos);
                CHECK(store_shape(runtime) == before);
            }
        }
    }

    GIVEN("a room with no ACL against the remote server")
    {
        WHEN("the worker relays the invite with a blank origin")
        {
            THEN("main refuses it all the same, because the sender-equals-origin guard needs an origin")
            {
                auto relay_case = RelayCase{RelayPath::invite, "invite-blank-open", 102};
                auto& runtime = relay_case.runtime();
                auto const before = store_shape(runtime);

                CHECK_FALSE(relay_once(runtime, RelayPath::invite, relay_case.event(), ""));
                CHECK(store_shape(runtime) == before);
            }
        }

        WHEN("the worker relays it with the inviter's own server as origin")
        {
            THEN("main takes it in, so the refusals above are the new checks' and nothing else's")
            {
                auto relay_case = RelayCase{RelayPath::invite, "invite-control", 103};
                CHECK(relay_once(relay_case.runtime(), RelayPath::invite, relay_case.event(), remote_server));
            }
        }
    }
}

// F-12 (ADR-0591): main applies the acceptor's admission to a relayed send_join, send_leave or send_knock itself,
// whatever the worker decided: a room in which no user of this server is joined, invited or knocking is not one it
// answers for, so nothing is stored. The one exception (ADR-0747) is a leave whose sender, a remote user, still holds
// a join, invite or knock row there: that row bounds what is stored, so a sender with no row is refused as before.
SCENARIO("main refuses a relayed membership event for a room with no local member and stores nothing",
         "[integration][federation-worker][worker_policy_authority][f12][adr0747]")
{
    GIVEN("a room whose only local member has left, in main's store")
    {
        WHEN("the worker relays a valid, signed leave of a remote user who holds no membership to end there")
        {
            THEN("main refuses it at the admission gate and the store is unchanged")
            {
                auto relay_case = RelayCase{RelayPath::membership, "no-interest", 110};
                auto& runtime = relay_case.runtime();
                for (auto& membership : runtime.database.persistent_store.memberships)
                {
                    if (membership.user_id == local_admin || membership.user_id == remote_member)
                    {
                        membership.membership = "leave";
                    }
                }
                auto const before = store_shape(runtime);

                auto const frame = relay_frame(RelayPath::membership, relay_case.event().envelope, remote_server);
                auto const response = homeserver::handle_membership_ingest_request(runtime, frame);
                CHECK(response.find(R"("accepted":true)") == std::string::npos);
                CHECK(response.find("this server has no local member in that room") != std::string::npos);
                CHECK(store_shape(runtime) == before);
                CHECK_FALSE(event_stored(runtime, relay_case.event().envelope.event_id));
            }
        }

        WHEN("the worker relays the leave of the remote member, who is still joined there")
        {
            THEN("main takes it in once, and the member's row becomes leave, so it admits no second leave")
            {
                auto relay_case = RelayCase{RelayPath::membership, "remote-leave", 112};
                auto& runtime = relay_case.runtime();
                for (auto& membership : runtime.database.persistent_store.memberships)
                {
                    if (membership.user_id == local_admin)
                    {
                        membership.membership = "leave";
                    }
                }

                CHECK(relay_once(runtime, RelayPath::membership, relay_case.event(), remote_server));
                CHECK(event_stored(runtime, relay_case.event().envelope.event_id));
                auto const* const row = database::find_membership_row(runtime.database.persistent_store,
                                                                      relay_case.event().room_id, remote_member);
                REQUIRE(row != nullptr);
                CHECK(row->membership == "leave");
            }
        }

        WHEN("the local member is still joined")
        {
            THEN("the same relay is taken in, so the refusal is the admission's and nothing else's")
            {
                auto relay_case = RelayCase{RelayPath::membership, "interest-control", 111};
                CHECK(relay_once(relay_case.runtime(), RelayPath::membership, relay_case.event(), remote_server));
            }
        }
    }
}
