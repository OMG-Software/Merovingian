// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              FEDERATION EVENT-GRAPH QUERY CONFORMANCE TESTS              |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19, Sec. Retrieving state for a room |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md                |
// |        #get_matrixfederationv1stateroomid                               |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST or SHOULD from the Matrix    |
// |  specification. If a test fails:                                        |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                    |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass. |
// +-------------------------------------------------------------------------+

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/event_query.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace
{

// Builds a minimal stored event. Only the fields the event-graph query path
// reads (id, room, json, auth links) are populated; depth/ordering are left at
// their defaults because state and auth-chain responses do not depend on them.
[[nodiscard]] auto make_event(std::string event_id, std::string room_id, std::string type,
                              std::vector<std::string> auth_event_ids, std::vector<std::string> prev_event_ids = {})
    -> merovingian::database::PersistentEvent
{
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = std::move(event_id);
    event.room_id = std::move(room_id);
    event.sender_user_id = "@creator:example.org";
    event.json = "{\"type\":\"" + std::move(type) + "\",\"sender\":\"@creator:example.org\"}";
    event.auth_event_ids = std::move(auth_event_ids);
    event.prev_event_ids = std::move(prev_event_ids);
    return event;
}

// Extracts the string array stored under `key` in a canonical-JSON object body.
// Returns an empty vector when the body is unparseable or the key is absent so
// callers can distinguish "present but empty" from "missing" via the body text.
[[nodiscard]] auto string_array_member(std::string_view body, std::string_view key) -> std::vector<std::string>
{
    auto parsed = merovingian::canonicaljson::parse_lossless(body);
    if (parsed.error != merovingian::canonicaljson::ParseError::none)
    {
        return {};
    }
    auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    if (object == nullptr)
    {
        return {};
    }
    auto values = std::vector<std::string>{};
    for (auto const& member : *object)
    {
        if (member.key != key || member.value == nullptr)
        {
            continue;
        }
        auto const* array = std::get_if<merovingian::canonicaljson::Array>(&member.value->storage());
        if (array == nullptr)
        {
            return {};
        }
        for (auto const& element : *array)
        {
            if (auto const* text = std::get_if<std::string>(&element.storage()); text != nullptr)
            {
                values.push_back(*text);
            }
        }
    }
    return values;
}

[[nodiscard]] auto contains(std::vector<std::string> const& haystack, std::string_view needle) -> bool
{
    return std::ranges::find(haystack, needle) != haystack.end();
}

// Builds a stored state event whose JSON carries a `state_key`, so the
// event-graph query path recognises it as state and can place it by (type,
// state_key). `depth` drives the "most recent value wins" tie-break during
// state-at-event reconstruction.
[[nodiscard]] auto make_state_event(std::string event_id, std::string room_id, std::string type, std::string state_key,
                                    std::uint64_t depth, std::vector<std::string> auth_event_ids,
                                    std::vector<std::string> prev_event_ids) -> merovingian::database::PersistentEvent
{
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = std::move(event_id);
    event.room_id = std::move(room_id);
    event.sender_user_id = "@creator:example.org";
    // A membership event carries a `join` so the requesting server (example.org,
    // the creator's server) counts as being in the room (FED-2).
    auto const content =
        type == "m.room.member" ? std::string{",\"content\":{\"membership\":\"join\"}"} : std::string{};
    event.json = "{\"type\":\"" + std::move(type) + "\",\"state_key\":\"" + std::move(state_key) +
                 "\",\"sender\":\"@creator:example.org\"" + content + "}";
    event.depth = depth;
    event.auth_event_ids = std::move(auth_event_ids);
    event.prev_event_ids = std::move(prev_event_ids);
    return event;
}

// Records one state group, with no m.room.history_visibility (so `shared`), for every event stored in
// `room`. /event, /backfill and /get_missing_events send an event in full only when the state recorded
// for it shows the requesting server may see it (ADR-0064 state groups); these fixtures write events
// straight into the store, so they record that state here.
auto record_shared_state_group(merovingian::database::PersistentStore& store, std::string const& room) -> void
{
    auto const group =
        merovingian::database::create_or_reuse_state_group(store, room, "sg:shared:" + room, std::nullopt, {});
    REQUIRE(group.has_value());
    for (auto const& event : store.events)
    {
        if (event.room_id == room)
        {
            REQUIRE(merovingian::database::set_event_state_group(store, event.event_id, *group));
        }
    }
}

// The requesting server. It is example.org because the rooms below have a joined
// user, @creator:example.org, on that server: the FED-2 in-room check passes.
constexpr auto requesting_server = std::string_view{"example.org"};

// Returns the body of a successful room read, failing the calling test otherwise.
[[nodiscard]] auto ok_body(merovingian::federation::RoomReadResult const& result) -> std::string
{
    REQUIRE(result.status == merovingian::federation::RoomReadStatus::ok);
    return result.body;
}

} // namespace

// --- Auth chain reconstruction for /state_ids --------------------------------
// Spec: Matrix Server-Server API v1.19, GET /_matrix/federation/v1/state_ids/{roomId}
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1state_idsroomid
//
// The response MUST carry `auth_chain_ids`: the IDs of every event in the auth
// chains of the returned state events. A receiving server relies on this set to
// authorize the state it is fetching, so an empty array when auth events exist
// is a spec violation, not an acceptable stub.
SCENARIO("state_ids response reconstructs the transitive auth chain", "[federation][conformance][event-graph]")
{
    GIVEN("a room whose member event is authorized by power-levels and create events")
    {
        auto const room = std::string{"!graph:example.org"};
        auto store = merovingian::database::PersistentStore{};
        // Auth DAG: create <- power_levels <- member. The member event names
        // both create and power_levels as auth events; power_levels names create.
        // The message event follows the member event, giving /state_ids a real
        // event to resolve the state at.
        store.events.push_back(make_state_event("$create", room, "m.room.create", "", 1U, {}, {}));
        store.events.push_back(make_state_event("$pl", room, "m.room.power_levels", "", 2U, {"$create"}, {"$create"}));
        store.events.push_back(make_state_event("$member", room, "m.room.member", "@creator:example.org", 3U,
                                                {"$create", "$pl"}, {"$pl"}));
        store.events.push_back(
            make_event("$message", room, "m.room.message", {"$create", "$pl", "$member"}, {"$member"}));
        store.state.push_back({room, "m.room.create", "", "$create"});
        store.state.push_back({room, "m.room.power_levels", "", "$pl"});
        store.state.push_back({room, "m.room.member", "@creator:example.org", "$member"});

        WHEN("the state_ids response is built")
        {
            auto const body =
                ok_body(merovingian::federation::build_state_ids_response(store, room, "$message", requesting_server));
            auto const pdu_ids = string_array_member(body, "pdu_ids");
            auto const auth_chain_ids = string_array_member(body, "auth_chain_ids");

            THEN("pdu_ids lists the current state and auth_chain_ids lists the transitive auth events")
            {
                // Spec MUST: pdu_ids enumerates the current room state event IDs.
                // Do NOT remove/change - a receiving server replaces room state from exactly this set.
                REQUIRE(contains(pdu_ids, "$create"));
                REQUIRE(contains(pdu_ids, "$pl"));
                REQUIRE(contains(pdu_ids, "$member"));
                // Spec MUST: auth_chain_ids MUST NOT be empty when the state events have auth events.
                // Do NOT remove/change - an empty chain here defeats the receiver's authorization checks.
                REQUIRE_FALSE(auth_chain_ids.empty());
                // Spec MUST: the auth chain MUST include every transitively-referenced auth event.
                // Do NOT remove/change - omitting create or power_levels breaks auth verification.
                REQUIRE(contains(auth_chain_ids, "$create"));
                REQUIRE(contains(auth_chain_ids, "$pl"));
            }
        }
    }
}

// --- Backfill event graph walk ------------------------------------------------
// Spec: Matrix Server-Server API v1.19, GET /_matrix/federation/v1/backfill/{roomId}
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1backfillroomid
//
// The 200 response contains "the PDUs that preceded the given event(s),
// including the given event(s), up to the given limit." Backfill therefore
// starts at each `v` event and walks backwards through `prev_events`.
SCENARIO("backfill PDU collection includes requested events and predecessors",
         "[federation][conformance][event-graph][backfill]")
{
    GIVEN("a room with a predecessor chain")
    {
        auto const room = std::string{"!graph:example.org"};
        auto store = merovingian::database::PersistentStore{};
        store.events.push_back(make_event("$create", room, "m.room.create", {}));
        store.events.push_back(make_event("$join", room, "m.room.member", {"$create"}, {"$create"}));
        store.events.push_back(make_event("$message", room, "m.room.message", {"$join"}, {"$join"}));
        record_shared_state_group(store, room);

        WHEN("backfill starts at the message event")
        {
            auto const pdus =
                merovingian::federation::build_backfill_pdus(store, room, {"$message"}, 10U, requesting_server);

            THEN("the returned PDUs include the requested event and its predecessors")
            {
                // Spec MUST: the requested `v` event is included.
                REQUIRE(pdus.size() == 3U);
                REQUIRE(std::ranges::any_of(pdus, [](std::string const& pdu) {
                    return pdu.find("m.room.message") != std::string::npos;
                }));
                // Spec MUST: predecessor PDUs are included up to the limit.
                REQUIRE(std::ranges::any_of(pdus, [](std::string const& pdu) {
                    return pdu.find("m.room.member") != std::string::npos;
                }));
                REQUIRE(std::ranges::any_of(pdus, [](std::string const& pdu) {
                    return pdu.find("m.room.create") != std::string::npos;
                }));
            }
        }
    }
}

// --- Auth chain reconstruction for /state ------------------------------------
// Spec: Matrix Server-Server API v1.19, GET /_matrix/federation/v1/state/{roomId}
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1stateroomid
//
// The full-event `/state` response MUST carry `auth_chain`: the complete events
// (not just IDs) for every event in the auth chains of the returned state.
SCENARIO("state response embeds the auth chain events", "[federation][conformance][event-graph]")
{
    GIVEN("a room with a create, power-levels, and member state event")
    {
        auto const room = std::string{"!graph-full:example.org"};
        auto store = merovingian::database::PersistentStore{};
        store.events.push_back(make_state_event("$create", room, "m.room.create", "", 1U, {}, {}));
        store.events.push_back(make_state_event("$pl", room, "m.room.power_levels", "", 2U, {"$create"}, {"$create"}));
        store.events.push_back(make_state_event("$member", room, "m.room.member", "@creator:example.org", 3U,
                                                {"$create", "$pl"}, {"$pl"}));
        store.events.push_back(
            make_event("$message", room, "m.room.message", {"$create", "$pl", "$member"}, {"$member"}));
        store.state.push_back({room, "m.room.create", "", "$create"});
        store.state.push_back({room, "m.room.power_levels", "", "$pl"});
        store.state.push_back({room, "m.room.member", "@creator:example.org", "$member"});

        WHEN("the state response is built")
        {
            auto const body =
                ok_body(merovingian::federation::build_state_response(store, room, "$message", requesting_server));

            THEN("the response is well-formed and carries a non-empty auth_chain array")
            {
                auto parsed = merovingian::canonicaljson::parse_lossless(body);
                // Spec MUST: the response body MUST be a well-formed canonical JSON object.
                // Do NOT remove/change - a malformed body cannot be consumed by a peer.
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(object != nullptr);
                auto const auth_chain_present =
                    std::ranges::any_of(*object, [](merovingian::canonicaljson::ObjectMember const& member) {
                        if (member.key != "auth_chain" || member.value == nullptr)
                        {
                            return false;
                        }
                        auto const* array = std::get_if<merovingian::canonicaljson::Array>(&member.value->storage());
                        return array != nullptr && !array->empty();
                    });
                // Spec MUST: auth_chain MUST contain the full auth events for the returned state.
                // Do NOT remove/change - peers verify state authorization against these embedded events.
                REQUIRE(auth_chain_present);
            }
        }
    }
}

// --- State-at-event reconstruction -------------------------------------------
// Spec: Matrix Server-Server API v1.19, GET /_matrix/federation/v1/state_ids/{roomId}
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1state_idsroomid
//
// The response is "the fully resolved state for the room, prior to considering
// any state changes induced by the requested event." So when a (type, state_key)
// has been set more than once, the response MUST carry the value that was
// current *before* the requested event — not the room's latest value, and not
// the requested event itself.
SCENARIO("state_ids reconstructs the room state as of the requested event",
         "[federation][conformance][event-graph][state-at-event]")
{
    GIVEN("a room whose topic is set twice along a linear event chain")
    {
        auto const room = std::string{"!history:example.org"};
        auto store = merovingian::database::PersistentStore{};
        // create <- join <- topic_v1 <- topic_v2, ascending depth.
        store.events.push_back(make_state_event("$create", room, "m.room.create", "", 1U, {}, {}));
        store.events.push_back(
            make_state_event("$join", room, "m.room.member", "@creator:example.org", 2U, {"$create"}, {"$create"}));
        store.events.push_back(make_state_event("$topic_v1", room, "m.room.topic", "", 3U, {"$create"}, {"$join"}));
        store.events.push_back(make_state_event("$topic_v2", room, "m.room.topic", "", 4U, {"$create"}, {"$topic_v1"}));
        // Current room state points at the newest topic.
        store.state.push_back({room, "m.room.create", "", "$create"});
        store.state.push_back({room, "m.room.member", "@creator:example.org", "$join"});
        store.state.push_back({room, "m.room.topic", "", "$topic_v2"});

        WHEN("state_ids is requested as of the second topic event")
        {
            auto const body =
                ok_body(merovingian::federation::build_state_ids_response(store, room, "$topic_v2", requesting_server));
            auto const pdu_ids = string_array_member(body, "pdu_ids");

            THEN("the state carries the topic value prior to that event, not the event itself")
            {
                // Spec MUST: state is resolved "prior to considering any state changes
                // induced by the requested event" - so $topic_v2 MUST NOT appear.
                REQUIRE_FALSE(contains(pdu_ids, "$topic_v2"));
                // Spec MUST: the resolved topic is the value current before $topic_v2.
                REQUIRE(contains(pdu_ids, "$topic_v1"));
                // Spec MUST: unrelated state (create, membership) is carried as of the event.
                REQUIRE(contains(pdu_ids, "$create"));
                REQUIRE(contains(pdu_ids, "$join"));
            }
        }

        WHEN("state_ids is requested as of the first topic event")
        {
            auto const body =
                ok_body(merovingian::federation::build_state_ids_response(store, room, "$topic_v1", requesting_server));
            auto const pdu_ids = string_array_member(body, "pdu_ids");

            THEN("no topic is present because none had been set before that event")
            {
                // Spec MUST: state prior to $topic_v1 contains neither topic event.
                REQUIRE_FALSE(contains(pdu_ids, "$topic_v1"));
                REQUIRE_FALSE(contains(pdu_ids, "$topic_v2"));
                // Spec MUST: the create and membership state are still present.
                REQUIRE(contains(pdu_ids, "$create"));
                REQUIRE(contains(pdu_ids, "$join"));
            }
        }
    }
}

// --- Room membership gate for federation reads (FED-2) ------------------------
// Spec: Matrix Server-Server API v1.19, GET /_matrix/federation/v1/state_ids/{roomId}
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1state_idsroomid
//
// The 403 response is "The requesting host is not in the room, or is excluded from
// the room via `m.room.server_acl`." The other event-graph endpoints list no 403;
// this server applies the same refusal to them as a security requirement, so that a
// server outside a room cannot pull its state, members or history.
SCENARIO("event-graph reads refuse a server that is not in the room",
         "[federation][conformance][event-graph][fed2][security]")
{
    GIVEN("a room whose only joined user is on example.org")
    {
        auto const room = std::string{"!private:example.org"};
        auto store = merovingian::database::PersistentStore{};
        store.events.push_back(make_state_event("$create", room, "m.room.create", "", 1U, {}, {}));
        store.events.push_back(
            make_state_event("$member", room, "m.room.member", "@creator:example.org", 2U, {"$create"}, {"$create"}));
        store.events.push_back(make_event("$message", room, "m.room.message", {"$create", "$member"}, {"$member"}));
        store.state.push_back({room, "m.room.create", "", "$create"});
        store.state.push_back({room, "m.room.member", "@creator:example.org", "$member"});

        WHEN("a server that has no user in the room reads state_ids, state and an event")
        {
            using merovingian::federation::RoomReadStatus;
            auto const state_ids =
                merovingian::federation::build_state_ids_response(store, room, "$message", "outsider.example.net");
            auto const state =
                merovingian::federation::build_state_response(store, room, "$message", "outsider.example.net");
            auto const event =
                merovingian::federation::build_event_response(store, "$message", "example.org", "outsider.example.net");

            THEN("each is refused with no room data")
            {
                // Spec: state_ids 403 "The requesting host is not in the room".
                REQUIRE(state_ids.status == RoomReadStatus::forbidden);
                REQUIRE(state_ids.body.empty());
                REQUIRE(state.status == RoomReadStatus::forbidden);
                REQUIRE(state.body.empty());
                REQUIRE(event.status == RoomReadStatus::forbidden);
                REQUIRE(event.body.empty());
            }
        }

        WHEN("state_ids names an event this server never stored")
        {
            auto const result = merovingian::federation::build_state_ids_response(store, room, "$nope", "example.org");

            THEN("the answer is not found instead of the room's current state")
            {
                REQUIRE(result.status == merovingian::federation::RoomReadStatus::not_found);
                REQUIRE(result.body.empty());
            }
        }
    }
}

// --- event_auth ----------------------------------------------------------------
// Spec: Matrix Server-Server API v1.19, GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1event_authroomideventid
//
// "Retrieves the complete auth chain for a given event." The 200 response's `auth_chain` is "The
// PDUs forming the auth chain of the given event": every event reachable through `auth_events`,
// transitively, as full PDUs. Like every room-scoped read the answer is for a server that has a
// joined user in the room; an event that is not in the room is not found.
SCENARIO("event_auth returns the complete auth chain of the event as full PDUs",
         "[federation][conformance][event-graph][event_auth][fed-endpoints]")
{
    GIVEN("a room whose message is authorised by member, power_levels and create, each with their own auth events")
    {
        auto const room = std::string{"!auth:example.org"};
        auto const other_room = std::string{"!elsewhere:example.org"};
        auto store = merovingian::database::PersistentStore{};
        store.events.push_back(make_state_event("$create", room, "m.room.create", "", 1U, {}, {}));
        store.events.push_back(make_state_event("$pl", room, "m.room.power_levels", "", 2U, {"$create"}, {"$create"}));
        store.events.push_back(make_state_event("$member", room, "m.room.member", "@creator:example.org", 3U,
                                                {"$create", "$pl"}, {"$pl"}));
        store.events.push_back(
            make_state_event("$jr", room, "m.room.join_rules", "", 4U, {"$create", "$pl", "$member"}, {"$member"}));
        store.events.push_back(make_event("$message", room, "m.room.message", {"$create", "$pl", "$member"}, {"$jr"}));
        store.events.push_back(make_event("$stranger", other_room, "m.room.message", {}, {}));
        store.state.push_back({room, "m.room.create", "", "$create"});
        store.state.push_back({room, "m.room.member", "@creator:example.org", "$member"});

        WHEN("the auth chain of the message is requested by a server in the room")
        {
            auto const body =
                ok_body(merovingian::federation::build_event_auth_response(store, room, "$message", requesting_server));
            auto const parsed = merovingian::canonicaljson::parse_lossless(body);
            REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
            auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
            REQUIRE(object != nullptr);

            THEN("auth_chain holds the create, power_levels and member PDUs, each once, and not the event itself")
            {
                // Spec: `auth_chain` is "Required"; the key is the only member of the answer.
                REQUIRE(object->size() == 1U);
                REQUIRE((*object)[0].key == "auth_chain");
                auto const* chain = std::get_if<merovingian::canonicaljson::Array>(&(*object)[0].value->storage());
                REQUIRE(chain != nullptr);
                // Spec: "the complete auth chain": all three, transitively, each as a full PDU object.
                REQUIRE(chain->size() == 3U);
                for (auto const& pdu : *chain)
                {
                    REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&pdu.storage()) != nullptr);
                }
                REQUIRE(body.find("m.room.create") != std::string::npos);
                REQUIRE(body.find("m.room.power_levels") != std::string::npos);
                REQUIRE(body.find("m.room.member") != std::string::npos);
                REQUIRE(body.find("m.room.message") == std::string::npos);
            }
        }

        WHEN("the chain of an event whose auth event is itself a deep chain is requested")
        {
            auto const body =
                ok_body(merovingian::federation::build_event_auth_response(store, room, "$jr", requesting_server));

            THEN("the transitive closure is returned, not just the direct auth events")
            {
                // The PDUs are objects, so look for them through their type markers.
                REQUIRE(body.find("m.room.create") != std::string::npos);
                REQUIRE(body.find("m.room.power_levels") != std::string::npos);
                REQUIRE(body.find("m.room.member") != std::string::npos);
            }
        }

        WHEN("a server with no joined user in the room asks")
        {
            auto const result =
                merovingian::federation::build_event_auth_response(store, room, "$message", "stranger.example.net");

            THEN("it is refused, as for every room-scoped read")
            {
                REQUIRE(result.status == merovingian::federation::RoomReadStatus::forbidden);
            }
        }

        WHEN("the event is unknown, or belongs to another room")
        {
            auto const unknown =
                merovingian::federation::build_event_auth_response(store, room, "$nothing", requesting_server);
            auto const elsewhere =
                merovingian::federation::build_event_auth_response(store, room, "$stranger", requesting_server);

            THEN("both are not found: the room's chain is never answered for a foreign event")
            {
                REQUIRE(unknown.status == merovingian::federation::RoomReadStatus::not_found);
                REQUIRE(elsewhere.status == merovingian::federation::RoomReadStatus::not_found);
            }
        }
    }
}

// --- get_missing_events walk --------------------------------------------------
// Spec: Matrix Server-Server API v1.19, POST /_matrix/federation/v1/get_missing_events/{roomId}
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#post_matrixfederationv1get_missing_eventsroomid
//
// "Retrieves previous events that the sender is missing. This is done by doing a
// breadth-first walk of the `prev_events` for the `latest_events`, ignoring any
// events in `earliest_events` and stopping at the `limit`." The 200 response is
// "The previous events for `latest_events`, excluding any `earliest_events`, up to
// the provided `limit`." `limit` defaults to 10.
SCENARIO("get_missing_events walks prev_events from latest_events, excluding earliest_events, up to limit",
         "[federation][conformance][event-graph][get_missing_events][fed2]")
{
    GIVEN("a room with a chain e0 <- e1 <- ... <- e29 and a server that is in the room")
    {
        auto const room = std::string{"!chain:example.org"};
        auto store = merovingian::database::PersistentStore{};
        store.events.push_back(make_state_event("$member", room, "m.room.member", "@creator:example.org", 1U, {}, {}));
        store.state.push_back({room, "m.room.member", "@creator:example.org", "$member"});
        for (auto i = 0; i < 30; ++i)
        {
            auto const id = "$e" + std::to_string(i);
            auto event = make_event(id, room, "m.room.message", {},
                                    i == 0 ? std::vector<std::string>{"$member"}
                                           : std::vector<std::string>{"$e" + std::to_string(i - 1)});
            // Carry the ID in the JSON so a response can be checked event by event.
            event.json = "{\"type\":\"m.room.message\",\"event_id\":\"" + id + "\"}";
            event.depth = static_cast<std::uint64_t>(i) + 10U;
            store.events.push_back(std::move(event));
        }
        record_shared_state_group(store, room);

        auto const events_in = [](merovingian::federation::RoomReadResult const& result) {
            REQUIRE(result.status == merovingian::federation::RoomReadStatus::ok);
            auto parsed = merovingian::canonicaljson::parse_lossless(result.body);
            REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
            auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
            REQUIRE(object != nullptr);
            REQUIRE(object->size() == 1U);
            REQUIRE((*object)[0].key == "events");
            auto const* events = std::get_if<merovingian::canonicaljson::Array>(&(*object)[0].value->storage());
            REQUIRE(events != nullptr);
            return events->size();
        };

        WHEN("the request asks for limit 1000 with the walk starting at e29")
        {
            auto const query_policy = merovingian::federation::FederationQueryPolicy{
                .max_missing_events_pdus = 20U,
            };
            auto const result = merovingian::federation::build_get_missing_events_response(
                store, room, R"({"latest_events":["$e29"],"earliest_events":[],"limit":1000})", "example.org",
                query_policy);

            THEN("at most 20 previous events come back and e29 itself is not among them")
            {
                // Spec: "stopping at the limit"; this test supplies a 20-event server policy.
                REQUIRE(events_in(result) == 20U);
                // Spec: "The previous events for latest_events" - not latest_events.
                REQUIRE(result.body.find("\"$e29\"") == std::string::npos);
                REQUIRE(result.body.find("\"$e28\"") != std::string::npos);
            }
        }

        WHEN("the request lists e25 as an earliest event")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(
                store, room, R"({"latest_events":["$e29"],"earliest_events":["$e25"],"limit":10})", "example.org");

            THEN("only the events after e25 come back: neither e25 nor anything behind it")
            {
                // Spec: "ignoring any events in earliest_events".
                REQUIRE(events_in(result) == 3U);
                REQUIRE(result.body.find("\"$e26\"") != std::string::npos);
                REQUIRE(result.body.find("\"$e25\"") == std::string::npos);
                REQUIRE(result.body.find("\"$e24\"") == std::string::npos);
            }
        }

        WHEN("the request lists e25 as an earliest event and asks for the three events after it")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(
                store, room, R"({"latest_events":["$e29"],"earliest_events":["$e25"],"limit":10})", "example.org");

            THEN("they come back oldest first, so a receiver can store each parent before its child")
            {
                // Spec: a breadth-first walk of `prev_events`; the receiver stores events in order,
                // so the answer lists e26, e27, e28 (parents before children).
                auto const e26 = result.body.find("\"$e26\"");
                auto const e27 = result.body.find("\"$e27\"");
                auto const e28 = result.body.find("\"$e28\"");
                REQUIRE(e26 != std::string::npos);
                REQUIRE(e26 < e27);
                REQUIRE(e27 < e28);
            }
        }

        WHEN("the request omits the limit")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(
                store, room, R"({"latest_events":["$e29"],"earliest_events":[]})", "example.org");

            THEN("the spec default of 10 applies")
            {
                REQUIRE(events_in(result) == 10U);
            }
        }
    }
}

// --- The create event of a room whose ID implies it (ADR-0286) ------------------
// Spec: Matrix Server-Server API v1.19, GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1event_authroomideventid
// Spec: Room Version 12, "Auth rules" and "Auth chain"
// URL:  ../../docs/matrix-v1.19-spec/rooms/v12.md
//
// v12.md: "The `m.room.create` event MUST NOT be selected for `auth_events` on events. The `room_id`
// (being the `m.room.create` event's ID) implies this instead." The same document defines an event's
// auth chain as what is reachable through its `auth_events` links, so read literally it leaves the
// create event out. The owner chose the other reading: the create event is an implied auth event of
// every event of such a room, and a peer needs it to apply the auth rules, so the auth chains this
// server SERVES hold it, once. Earlier room versions list the create event in `auth_events` and are
// unchanged. State resolution's own auth-chain computation is not part of this.
namespace
{

// A room of `version` holding a create, a creator's join, a power_levels and a message. From v12
// the create event is in no `auth_events`; before it, every event names it.
struct VersionedRoom final
{
    std::string room{};
    std::string create_id{};
};

[[nodiscard]] auto make_versioned_room(merovingian::database::PersistentStore& store, std::string const& version)
    -> VersionedRoom
{
    auto const implied = version == "12";
    auto const room = implied ? std::string{"!v12hash"} : std::string{"!v11room:example.org"};
    auto const create_id = implied ? std::string{"$v12hash"} : std::string{"$create"};
    auto const create_auth = std::vector<std::string>{};
    auto create = make_state_event(create_id, room, "m.room.create", "", 1U, create_auth, {});
    create.json = "{\"type\":\"m.room.create\",\"state_key\":\"\",\"sender\":\"@creator:example.org\","
                  "\"content\":{\"room_version\":\"" +
                  version + "\"}}";
    store.events.push_back(std::move(create));
    auto const with_create = [&](std::vector<std::string> ids) {
        if (!implied)
        {
            ids.insert(ids.begin(), create_id);
        }
        return ids;
    };
    store.events.push_back(
        make_state_event("$member", room, "m.room.member", "@creator:example.org", 2U, with_create({}), {create_id}));
    store.events.push_back(
        make_state_event("$pl", room, "m.room.power_levels", "", 3U, with_create({"$member"}), {"$member"}));
    store.events.push_back(make_event("$message", room, "m.room.message", with_create({"$pl", "$member"}), {"$pl"}));
    store.state.push_back({room, "m.room.create", "", create_id});
    store.state.push_back({room, "m.room.member", "@creator:example.org", "$member"});
    store.state.push_back({room, "m.room.power_levels", "", "$pl"});
    return {room, create_id};
}

// The `type` of every PDU in the answer's `array_key` array, in order.
[[nodiscard]] auto pdu_types_in(std::string_view body, std::string_view array_key) -> std::vector<std::string>
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(body);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(object != nullptr);
    auto types = std::vector<std::string>{};
    for (auto const& member : *object)
    {
        if (member.key != array_key)
        {
            continue;
        }
        auto const* array = std::get_if<merovingian::canonicaljson::Array>(&member.value->storage());
        REQUIRE(array != nullptr);
        for (auto const& pdu : *array)
        {
            auto const* event = std::get_if<merovingian::canonicaljson::Object>(&pdu.storage());
            REQUIRE(event != nullptr);
            for (auto const& field : *event)
            {
                if (field.key == "type")
                {
                    types.push_back(std::get<std::string>(field.value->storage()));
                }
            }
        }
    }
    return types;
}

[[nodiscard]] auto count_of(std::vector<std::string> const& values, std::string_view wanted) -> std::ptrdiff_t
{
    return std::ranges::count(values, wanted);
}

} // namespace

// Spec: Matrix Server-Server API v1.19; Room Version 12
// Endpoint / Section: GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}; rooms/v12 "Auth chain"
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1event_authroomideventid
//
// v12: "The m.room.create event MUST NOT be selected for auth_events on events. The room_id ...
// implies this instead." The chains this server serves include that implied event once (ADR-0286).
SCENARIO("event_auth includes the create event of a room whose ID implies it, once",
         "[federation][conformance][event-graph][event_auth][create-implied]")
{
    GIVEN("a room version 12 room, whose events do not list the create event in auth_events")
    {
        auto store = merovingian::database::PersistentStore{};
        auto const fixture = make_versioned_room(store, "12");

        WHEN("the auth chain of the message is requested")
        {
            auto const body = ok_body(
                merovingian::federation::build_event_auth_response(store, fixture.room, "$message", requesting_server));
            auto const types = pdu_types_in(body, "auth_chain");

            THEN("the create event is in the chain exactly once, with the power_levels and member events")
            {
                // The owner's reading of v12.md "The `room_id` ... implies this instead": served chains
                // hold the implied create event so a peer can apply the auth rules.
                REQUIRE(count_of(types, "m.room.create") == 1);
                REQUIRE(count_of(types, "m.room.power_levels") == 1);
                REQUIRE(count_of(types, "m.room.member") == 1);
                REQUIRE(types.size() == 3U);
            }
        }

        WHEN("the auth chain of the create event itself is requested")
        {
            auto const body = ok_body(merovingian::federation::build_event_auth_response(
                store, fixture.room, fixture.create_id, requesting_server));

            THEN("it is empty: an event is not in its own auth chain")
            {
                REQUIRE(pdu_types_in(body, "auth_chain").empty());
            }
        }

        WHEN("an event that (wrongly) lists the create event is asked for")
        {
            store.events.push_back(
                make_event("$odd", fixture.room, "m.room.message", {fixture.create_id, "$pl"}, {"$pl"}));
            auto const body = ok_body(
                merovingian::federation::build_event_auth_response(store, fixture.room, "$odd", requesting_server));

            THEN("the create event is still in the chain only once")
            {
                REQUIRE(count_of(pdu_types_in(body, "auth_chain"), "m.room.create") == 1);
            }
        }
    }

    GIVEN("a room version 12 room this server holds no create event for")
    {
        auto store = merovingian::database::PersistentStore{};
        auto const fixture = make_versioned_room(store, "12");
        store.state.erase(std::remove_if(store.state.begin(), store.state.end(),
                                         [](merovingian::database::PersistentStateEvent const& row) {
                                             return row.event_type == "m.room.create";
                                         }),
                          store.state.end());

        WHEN("the auth chain of the message is requested")
        {
            auto const body = ok_body(
                merovingian::federation::build_event_auth_response(store, fixture.room, "$message", requesting_server));

            THEN("nothing is invented: the chain is what is held")
            {
                REQUIRE(count_of(pdu_types_in(body, "auth_chain"), "m.room.create") == 0);
            }
        }
    }

    GIVEN("a room version 11 room, whose events list the create event in auth_events")
    {
        auto store = merovingian::database::PersistentStore{};
        auto const fixture = make_versioned_room(store, "11");

        WHEN("the auth chain of the message is requested")
        {
            auto const body = ok_body(
                merovingian::federation::build_event_auth_response(store, fixture.room, "$message", requesting_server));
            auto const types = pdu_types_in(body, "auth_chain");

            THEN("the answer is unchanged: the create event once, reached through auth_events")
            {
                REQUIRE(count_of(types, "m.room.create") == 1);
                REQUIRE(types.size() == 3U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1event_authroomideventid
//
// "Retrieves the complete auth chain": a chain this server will not send whole is refused, never cut
// (ADR-0284). The implied create event is part of the chain, so it counts toward that bound.
SCENARIO("the implied create event counts toward the event_auth bound",
         "[federation][conformance][event-graph][event_auth][create-implied]")
{
    auto const build_long_chain = [](merovingian::database::PersistentStore& store, std::string const& version) {
        auto const fixture = make_versioned_room(store, version);
        // The chain of "$tip" is exactly the bound, without the implied create event: the links, each
        // naming the one before, then "$member" (and, before v12, the create event "$member" names).
        auto previous = std::string{"$member"};
        auto const links = merovingian::federation::max_event_auth_chain_events - (version == "12" ? 1U : 2U);
        for (auto i = std::size_t{0U}; i < links; ++i)
        {
            auto id = "$link" + std::to_string(i);
            store.events.push_back(make_event(id, fixture.room, "m.room.message", {previous}, {"$pl"}));
            previous = std::move(id);
        }
        store.events.push_back(make_event("$tip", fixture.room, "m.room.message", {previous}, {"$pl"}));
        return fixture;
    };

    GIVEN("a room version 12 room where an event's chain, without the create event, is exactly the bound")
    {
        auto store = merovingian::database::PersistentStore{};
        auto const fixture = build_long_chain(store, "12");

        WHEN("its auth chain is requested")
        {
            auto const result =
                merovingian::federation::build_event_auth_response(store, fixture.room, "$tip", requesting_server);

            THEN("it is refused as too large, because the create event would make it one more")
            {
                REQUIRE(result.status == merovingian::federation::RoomReadStatus::too_large);
            }
        }
    }

    GIVEN("a room version 11 room with a chain of exactly the bound")
    {
        auto store = merovingian::database::PersistentStore{};
        auto const fixture = build_long_chain(store, "11");

        WHEN("its auth chain is requested")
        {
            auto const result =
                merovingian::federation::build_event_auth_response(store, fixture.room, "$tip", requesting_server);

            THEN("it is answered whole")
            {
                REQUIRE(result.status == merovingian::federation::RoomReadStatus::ok);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, GET /_matrix/federation/v1/state/{roomId}
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1stateroomid
//
// `auth_chain`: "The full set of authorisation events that make up the state of the room, and their
// authorisation events, recursively." In a room whose ID implies its create event, that event is one
// of them (ADR-0286). /state_ids lists the same set by ID.
SCENARIO("state and state_ids auth chains include the implied create event, once",
         "[federation][conformance][event-graph][state][create-implied]")
{
    GIVEN("a room version 12 room")
    {
        auto store = merovingian::database::PersistentStore{};
        auto const fixture = make_versioned_room(store, "12");

        WHEN("the state at the message is requested")
        {
            auto const body = ok_body(
                merovingian::federation::build_state_response(store, fixture.room, "$message", requesting_server));

            THEN("auth_chain holds the create event exactly once")
            {
                REQUIRE(count_of(pdu_types_in(body, "auth_chain"), "m.room.create") == 1);
            }
        }

        WHEN("the state IDs at the message are requested")
        {
            auto const body = ok_body(
                merovingian::federation::build_state_ids_response(store, fixture.room, "$message", requesting_server));
            auto const ids = string_array_member(body, "auth_chain_ids");

            THEN("auth_chain_ids names the create event exactly once")
            {
                REQUIRE(std::ranges::count(ids, fixture.create_id) == 1);
            }
        }
    }

    GIVEN("a room version 11 room")
    {
        auto store = merovingian::database::PersistentStore{};
        auto const fixture = make_versioned_room(store, "11");

        WHEN("the state at the message is requested")
        {
            auto const body = ok_body(
                merovingian::federation::build_state_response(store, fixture.room, "$message", requesting_server));

            THEN("the create event is in auth_chain once, as before")
            {
                REQUIRE(count_of(pdu_types_in(body, "auth_chain"), "m.room.create") == 1);
            }
        }
    }
}
