// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              FEDERATION EVENT-GRAPH QUERY CONFORMANCE TESTS              |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.18, Sec. Retrieving state for a room |
// |  URL:  ../../docs/matrix-v1.18-spec/server-server-api.md                |
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
                              std::vector<std::string> auth_event_ids) -> merovingian::database::PersistentEvent
{
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = std::move(event_id);
    event.room_id = std::move(room_id);
    event.sender_user_id = "@creator:example.org";
    event.json = "{\"type\":\"" + std::move(type) + "\",\"sender\":\"@creator:example.org\"}";
    event.auth_event_ids = std::move(auth_event_ids);
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

} // namespace

// --- Auth chain reconstruction for /state_ids --------------------------------
// Spec: Matrix Server-Server API v1.18, GET /_matrix/federation/v1/state_ids/{roomId}
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#get_matrixfederationv1state_idsroomid
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
        store.events.push_back(make_event("$create", room, "m.room.create", {}));
        store.events.push_back(make_event("$pl", room, "m.room.power_levels", {"$create"}));
        store.events.push_back(make_event("$member", room, "m.room.member", {"$create", "$pl"}));
        store.state.push_back({room, "m.room.create", "", "$create"});
        store.state.push_back({room, "m.room.power_levels", "", "$pl"});
        store.state.push_back({room, "m.room.member", "@creator:example.org", "$member"});

        WHEN("the state_ids response is built")
        {
            auto const body = merovingian::federation::build_state_ids_response(store, room);
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

// --- Auth chain reconstruction for /state ------------------------------------
// Spec: Matrix Server-Server API v1.18, GET /_matrix/federation/v1/state/{roomId}
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#get_matrixfederationv1stateroomid
//
// The full-event `/state` response MUST carry `auth_chain`: the complete events
// (not just IDs) for every event in the auth chains of the returned state.
SCENARIO("state response embeds the auth chain events", "[federation][conformance][event-graph]")
{
    GIVEN("a room with a create, power-levels, and member state event")
    {
        auto const room = std::string{"!graph-full:example.org"};
        auto store = merovingian::database::PersistentStore{};
        store.events.push_back(make_event("$create", room, "m.room.create", {}));
        store.events.push_back(make_event("$pl", room, "m.room.power_levels", {"$create"}));
        store.events.push_back(make_event("$member", room, "m.room.member", {"$create", "$pl"}));
        store.state.push_back({room, "m.room.create", "", "$create"});
        store.state.push_back({room, "m.room.power_levels", "", "$pl"});
        store.state.push_back({room, "m.room.member", "@creator:example.org", "$member"});

        WHEN("the state response is built")
        {
            auto const body = merovingian::federation::build_state_response(store, room);

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
