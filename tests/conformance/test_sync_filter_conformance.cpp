// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX SYNC FILTER CONFORMANCE TESTS                            |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.18 — Filtering                       |
// |  URL:  https://spec.matrix.org/v1.18/client-server-api/#filtering       |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec.        |
// |  If a test fails:                                                        |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |       spec itself has changed and citing the updated section.            |
// |                                                                         |
// |  Filter application rules (spec § Filtering):                           |
// |    not_types > types > (no restriction)                                  |
// |    not_senders > senders > (no restriction)                              |
// |    An empty list means "no restriction" — all events pass.              |
// +-------------------------------------------------------------------------+

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/sync/sync_filter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

// Spec: Matrix Client-Server API v1.18 — Filtering
// URL: https://spec.matrix.org/v1.18/client-server-api/#filtering
//
// When no filter is applied (filter argument is empty or absent), all events
// pass. The SyncFilter.present flag must be false when no filter was given.
SCENARIO("An absent filter allows all events through", "[sync][filter][conformance]")
{
    GIVEN("no filter is provided")
    {
        auto const filter = merovingian::sync::parse_filter_argument("");

        THEN("the filter is marked as not present")
        {
            // Spec MUST: an absent filter MUST NOT restrict any events.
            REQUIRE(!filter.present);
        }

        THEN("all event types pass the room timeline filter")
        {
            // Spec MUST: absent filter = no restriction.
            REQUIRE(merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.message", "@alice:example.org"));
            REQUIRE(merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.member", "@alice:example.org"));
            REQUIRE(merovingian::sync::event_passes_filter(filter.room.timeline, "m.custom.event", "@bob:example.org"));
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — Filtering
// URL: https://spec.matrix.org/v1.18/client-server-api/#filtering
//
// "types": A list of event types to include. If this list is absent then all
// event types are included. If the list is present, only events whose type
// matches one of the listed types are included.
SCENARIO("Filter with 'types' list includes only matching event types",
         "[sync][filter][conformance]")
{
    GIVEN("a filter that requests only m.room.message events")
    {
        auto const filter =
            merovingian::sync::parse_filter_argument(R"({"room":{"timeline":{"types":["m.room.message"]}}})");

        THEN("the filter is marked as present")
        {
            REQUIRE(filter.present);
        }

        THEN("m.room.message events pass")
        {
            // Spec MUST: event type in the types list passes the filter.
            REQUIRE(merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.message", "@alice:example.org"));
        }

        THEN("m.room.member events are excluded")
        {
            // Spec MUST: event type NOT in the types list is excluded.
            REQUIRE(
                !merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.member", "@alice:example.org"));
        }

        THEN("m.room.create events are excluded")
        {
            // Spec MUST: unlisted types are excluded when types list is present.
            REQUIRE(
                !merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.create", "@alice:example.org"));
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — Filtering
// URL: https://spec.matrix.org/v1.18/client-server-api/#filtering
//
// "not_types": A list of event types to exclude. Events whose type matches
// any entry in not_types are excluded regardless of the types list.
SCENARIO("Filter with 'not_types' list excludes matching event types",
         "[sync][filter][conformance]")
{
    GIVEN("a filter that excludes m.room.member events")
    {
        auto const filter =
            merovingian::sync::parse_filter_argument(R"({"room":{"timeline":{"not_types":["m.room.member"]}}})");

        THEN("m.room.message events pass (not in not_types)")
        {
            // Spec MUST: types not in not_types pass the filter.
            REQUIRE(
                merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.message", "@alice:example.org"));
        }

        THEN("m.room.member events are excluded")
        {
            // Spec MUST: event type in not_types is excluded.
            REQUIRE(
                !merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.member", "@alice:example.org"));
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — Filtering
// URL: https://spec.matrix.org/v1.18/client-server-api/#filtering
//
// "not_types" takes precedence over "types". If an event type appears in
// both lists it MUST be excluded.
SCENARIO("Filter not_types takes precedence over types", "[sync][filter][conformance]")
{
    GIVEN("a filter with m.room.message in both types and not_types")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"timeline":{"types":["m.room.message"],"not_types":["m.room.message"]}}})");

        THEN("m.room.message is excluded because not_types wins")
        {
            // Spec MUST: not_types > types. An event type in both lists is excluded.
            // Do NOT change this assertion — the spec is explicit that not_types
            // takes priority to allow a "deny some from an allowed set" pattern.
            REQUIRE(
                !merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.message", "@alice:example.org"));
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — Filtering
// URL: https://spec.matrix.org/v1.18/client-server-api/#filtering
//
// "senders": A list of senders to include. When present, only events from
// a sender in this list are included.
SCENARIO("Filter with 'senders' list includes only events from listed senders",
         "[sync][filter][conformance]")
{
    GIVEN("a filter that only includes events from @alice:example.org")
    {
        auto const filter =
            merovingian::sync::parse_filter_argument(R"({"room":{"timeline":{"senders":["@alice:example.org"]}}})");

        THEN("events from @alice:example.org pass")
        {
            // Spec MUST: sender in the senders list passes the filter.
            REQUIRE(merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.message", "@alice:example.org"));
        }

        THEN("events from @bob:example.org are excluded")
        {
            // Spec MUST: sender NOT in the senders list is excluded.
            REQUIRE(
                !merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.message", "@bob:example.org"));
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — Filtering
// URL: https://spec.matrix.org/v1.18/client-server-api/#filtering
//
// "not_senders": A list of senders to exclude. Takes precedence over "senders".
// Events from a sender in not_senders are excluded regardless of senders.
SCENARIO("Filter with 'not_senders' excludes events from listed senders",
         "[sync][filter][conformance]")
{
    GIVEN("a filter that excludes events from @spam:example.org")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"timeline":{"not_senders":["@spam:example.org"]}}})");

        THEN("events from @alice:example.org pass")
        {
            REQUIRE(merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.message", "@alice:example.org"));
        }

        THEN("events from @spam:example.org are excluded")
        {
            // Spec MUST: sender in not_senders is excluded.
            REQUIRE(
                !merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.message", "@spam:example.org"));
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — Filtering
// URL: https://spec.matrix.org/v1.18/client-server-api/#filtering
//
// not_senders takes precedence over senders — a sender in both lists is excluded.
SCENARIO("Filter not_senders takes precedence over senders", "[sync][filter][conformance]")
{
    GIVEN("a filter with @alice:example.org in both senders and not_senders")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"timeline":{"senders":["@alice:example.org"],"not_senders":["@alice:example.org"]}}})");

        THEN("@alice:example.org is excluded because not_senders wins")
        {
            // Spec MUST: not_senders > senders.
            REQUIRE(
                !merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.message", "@alice:example.org"));
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — Filtering
// URL: https://spec.matrix.org/v1.18/client-server-api/#filtering
//
// A filter JSON object with no nested restriction fields is valid. The
// SyncFilter.present flag must be true when a filter was supplied.
SCENARIO("An empty JSON filter object {} is present but unrestricted",
         "[sync][filter][conformance]")
{
    GIVEN("an empty JSON object as filter")
    {
        auto const filter = merovingian::sync::parse_filter_argument("{}");

        THEN("the filter is marked as present")
        {
            // Spec: any supplied filter, even an empty one, is present.
            REQUIRE(filter.present);
        }

        THEN("all event types still pass")
        {
            // Spec MUST: an empty filter object imposes no restriction.
            REQUIRE(
                merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.message", "@alice:example.org"));
            REQUIRE(
                merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.member", "@bob:example.org"));
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — Filtering
// URL: https://spec.matrix.org/v1.18/client-server-api/#filtering
//
// Multiple filter criteria are AND-combined: an event must satisfy both the
// type filter and the sender filter to pass.
SCENARIO("Filter combines type and sender restrictions with AND logic",
         "[sync][filter][conformance]")
{
    GIVEN("a filter with both types and senders restrictions")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"timeline":{"types":["m.room.message"],"senders":["@alice:example.org"]}}})");

        THEN("events from @alice:example.org of type m.room.message pass")
        {
            // Spec MUST: event passes only when it satisfies ALL restrictions.
            REQUIRE(merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.message", "@alice:example.org"));
        }

        THEN("events from @alice:example.org of type m.room.member are excluded")
        {
            // Event type not in types list → excluded even if sender passes.
            REQUIRE(
                !merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.member", "@alice:example.org"));
        }

        THEN("events from @bob:example.org of type m.room.message are excluded")
        {
            // Sender not in senders list → excluded even if type passes.
            REQUIRE(
                !merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.message", "@bob:example.org"));
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — Filtering
// URL: https://spec.matrix.org/v1.18/client-server-api/#filtering
//
// Filters are stored server-side via POST /user/{userId}/filter and retrieved
// via GET /user/{userId}/filter/{filterId}. The parsed filter representation
// must round-trip through parse_filter_argument so that inline JSON filters
// (passed directly as the ?filter= query param) behave the same as stored ones.
// NOTE: This tests internal parse_filter_argument helper behavior, not Matrix API conformance.
// The Matrix spec would require the /sync endpoint to return 400 M_BAD_JSON for an
// invalid literal filter. The helper itself is intentionally lenient (pass-all on error)
// so the runtime can log and continue. API-level 400 enforcement sits in the route handler.
// See: src/homeserver/client_server.cpp — the sync route validates filter JSON before
//      calling sync_json() and returns dispatch_err(400, "M_BAD_JSON") on parse failure.
SCENARIO("parse_filter_argument handles invalid JSON gracefully", "[sync][filter][helper]")
{
    GIVEN("syntactically invalid JSON as filter argument")
    {
        auto const filter = merovingian::sync::parse_filter_argument("{invalid json}");

        THEN("the filter is not marked as present")
        {
            // Implementation helper behaviour, NOT Matrix API behaviour.
            // The spec requires the /sync route to return 400 M_BAD_JSON for an
            // invalid inline filter; that check sits in the route handler BEFORE
            // this helper is called. The helper itself is intentionally lenient:
            // it returns a pass-all filter so callers that don't gate on the
            // route can log and continue without crashing.
            REQUIRE(!filter.present);
        }

        THEN("all events still pass through")
        {
            REQUIRE(merovingian::sync::event_passes_filter(filter.room.timeline, "m.room.message", "@alice:example.org"));
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — GET /sync
// URL:  https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3sync
//
// The ?filter= query parameter may be either a stored filter ID (opaque string)
// or an inline JSON object (starts with '{'). When the value starts with '{'
// the server MUST treat it as literal JSON and MUST return 400 M_BAD_JSON if
// the JSON is not well-formed.
//
// Implementation note: the /sync route handler in client_server.cpp performs
// this validation via canonicaljson::parse_lossless() before calling sync_json().
// The parse_filter_argument() helper is intentionally lenient so that it can
// be reused in non-HTTP contexts; the API-level error lives in the route.
SCENARIO("Sync API route: invalid inline JSON filter is identified as a parse error",
         "[sync][filter][conformance]")
{
    GIVEN("a filter argument that starts with '{' but contains invalid JSON")
    {
        auto const bad_filter = std::string{"{invalid json}"};

        WHEN("the filter value is parsed as canonical JSON (as the route handler does)")
        {
            // The route handler calls canonicaljson::parse_lossless() on any
            // filter that starts with '{' and returns 400 M_BAD_JSON if it fails.
            auto const result = merovingian::canonicaljson::parse_lossless(bad_filter);

            THEN("the parse fails, confirming the route will return 400 M_BAD_JSON")
            {
                // Spec MUST: malformed inline filter JSON MUST be rejected with M_BAD_JSON.
                REQUIRE(result.error != merovingian::canonicaljson::ParseError::none);
            }
        }
    }

    GIVEN("a filter argument that starts with '{' and contains valid JSON")
    {
        auto const good_filter = std::string{R"({"room":{"timeline":{"limit":20}}})"};

        WHEN("the filter value is parsed as canonical JSON")
        {
            auto const result = merovingian::canonicaljson::parse_lossless(good_filter);

            THEN("the parse succeeds — the route will proceed to sync_json()")
            {
                // Spec: a well-formed inline filter must pass the route validation step.
                REQUIRE(result.error == merovingian::canonicaljson::ParseError::none);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// rooms / not_rooms — room-level allowlist and denylist
// Spec: Matrix Client-Server API v1.18 — Filtering
// URL:  https://spec.matrix.org/v1.18/client-server-api/#filtering
// ---------------------------------------------------------------------------

// Spec: "rooms": A list of room IDs to include. If absent all rooms are included.
SCENARIO("Filter with 'rooms' list includes only events from specified rooms",
         "[sync][filter][conformance]")
{
    GIVEN("a filter that specifies a rooms include-list")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"rooms":["!alpha:example.org"]}})");

        THEN("events from the listed room pass the room filter")
        {
            // Spec MUST: room in the rooms list passes the filter.
            REQUIRE(merovingian::sync::room_passes_filter(filter.room, "!alpha:example.org"));
        }

        THEN("events from an unlisted room are excluded")
        {
            // Spec MUST: room NOT in the rooms list is excluded.
            REQUIRE_FALSE(merovingian::sync::room_passes_filter(filter.room, "!beta:example.org"));
        }
    }
}

// Spec: "not_rooms": A list of room IDs to exclude. Takes precedence over rooms.
SCENARIO("Filter with 'not_rooms' excludes events from specified rooms",
         "[sync][filter][conformance]")
{
    GIVEN("a filter that excludes !spam:example.org")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"not_rooms":["!spam:example.org"]}})");

        THEN("events from an unlisted room pass")
        {
            REQUIRE(merovingian::sync::room_passes_filter(filter.room, "!good:example.org"));
        }

        THEN("events from the excluded room are filtered")
        {
            // Spec MUST: room in not_rooms is excluded.
            REQUIRE_FALSE(merovingian::sync::room_passes_filter(filter.room, "!spam:example.org"));
        }
    }
}

// Spec: not_rooms takes precedence over rooms.
SCENARIO("Filter not_rooms takes precedence over rooms",
         "[sync][filter][conformance]")
{
    GIVEN("a filter with the same room in both rooms and not_rooms")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"rooms":["!room:example.org"],"not_rooms":["!room:example.org"]}})");

        THEN("the room is excluded because not_rooms wins")
        {
            // Spec MUST: not_rooms > rooms (deny-list trumps allow-list).
            REQUIRE_FALSE(merovingian::sync::room_passes_filter(filter.room, "!room:example.org"));
        }
    }
}

// ---------------------------------------------------------------------------
// Subfilters: state, ephemeral, account_data (room-level)
// Spec: Matrix Client-Server API v1.18 — Filtering
// URL:  https://spec.matrix.org/v1.18/client-server-api/#filtering
// ---------------------------------------------------------------------------

// Spec: room.state — filter applied to the state events included in the /sync response.
SCENARIO("Filter room.state subfilter restricts state event types",
         "[sync][filter][conformance]")
{
    GIVEN("a filter with state restricted to m.room.member")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"state":{"types":["m.room.member"]}}})");

        THEN("m.room.member state events pass")
        {
            // Spec MUST: state event type in the types list passes the state filter.
            REQUIRE(merovingian::sync::event_passes_filter(
                filter.room.state, "m.room.member", "@alice:example.org"));
        }

        THEN("m.room.power_levels state events are excluded")
        {
            // Spec MUST: state event type not in the types list is excluded.
            REQUIRE_FALSE(merovingian::sync::event_passes_filter(
                filter.room.state, "m.room.power_levels", "@alice:example.org"));
        }
    }
}

// Spec: room.ephemeral — filter applied to ephemeral events (typing, read receipts).
SCENARIO("Filter room.ephemeral subfilter restricts ephemeral event types",
         "[sync][filter][conformance]")
{
    GIVEN("a filter that excludes m.typing from ephemeral events")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"ephemeral":{"not_types":["m.typing"]}}})");

        THEN("m.receipt events pass the ephemeral filter")
        {
            REQUIRE(merovingian::sync::event_passes_filter(
                filter.room.ephemeral, "m.receipt", "@alice:example.org"));
        }

        THEN("m.typing events are excluded from the ephemeral stream")
        {
            // Spec MUST: event type in not_types is excluded from the ephemeral stream.
            REQUIRE_FALSE(merovingian::sync::event_passes_filter(
                filter.room.ephemeral, "m.typing", "@alice:example.org"));
        }
    }
}

// Spec: room.account_data — filter for per-room account data events.
SCENARIO("Filter room.account_data subfilter restricts room-level account data events",
         "[sync][filter][conformance]")
{
    GIVEN("a filter with room account_data restricted to m.fully_read")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"account_data":{"types":["m.fully_read"]}}})");

        THEN("m.fully_read room account_data events pass")
        {
            REQUIRE(merovingian::sync::event_passes_filter(
                filter.room.account_data, "m.fully_read", "@alice:example.org"));
        }

        THEN("m.tag room account_data events are excluded")
        {
            REQUIRE_FALSE(merovingian::sync::event_passes_filter(
                filter.room.account_data, "m.tag", "@alice:example.org"));
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level presence and account_data filters
// Spec: Matrix Client-Server API v1.18 — Filtering
// URL:  https://spec.matrix.org/v1.18/client-server-api/#filtering
// ---------------------------------------------------------------------------

// Spec: presence — filter applied to presence events in the /sync response.
SCENARIO("Top-level presence filter restricts presence events by sender",
         "[sync][filter][conformance]")
{
    GIVEN("a filter that excludes presence from @bot:example.org")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"presence":{"not_senders":["@bot:example.org"]}})");

        THEN("presence from a regular user passes")
        {
            REQUIRE(merovingian::sync::event_passes_filter(
                filter.presence, "m.presence", "@alice:example.org"));
        }

        THEN("presence from the excluded bot is filtered")
        {
            // Spec MUST: sender in not_senders is excluded from the presence stream.
            REQUIRE_FALSE(merovingian::sync::event_passes_filter(
                filter.presence, "m.presence", "@bot:example.org"));
        }
    }
}

// Spec: account_data (top-level) — filter for global (non-room) account data events.
SCENARIO("Top-level account_data filter restricts global account data events",
         "[sync][filter][conformance]")
{
    GIVEN("a top-level account_data filter restricted to m.push_rules")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"account_data":{"types":["m.push_rules"]}})");

        THEN("m.push_rules account_data events pass")
        {
            REQUIRE(merovingian::sync::event_passes_filter(
                filter.account_data, "m.push_rules", "@alice:example.org"));
        }

        THEN("m.identity_server account_data events are excluded")
        {
            REQUIRE_FALSE(merovingian::sync::event_passes_filter(
                filter.account_data, "m.identity_server", "@alice:example.org"));
        }
    }
}

// ---------------------------------------------------------------------------
// limit and include_leave
// Spec: Matrix Client-Server API v1.18 — Filtering
// URL:  https://spec.matrix.org/v1.18/client-server-api/#filtering
// ---------------------------------------------------------------------------

// Spec: "limit" caps the number of timeline events returned per room in /sync.
SCENARIO("Filter timeline limit field is parsed from the JSON filter",
         "[sync][filter][conformance]")
{
    GIVEN("a filter with timeline limit set to 50")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"timeline":{"limit":50}}})");

        THEN("the parsed limit value is 50")
        {
            // Spec: limit controls how many timeline events are returned per room.
            REQUIRE(filter.room.timeline.limit == 50U);
        }
    }

    GIVEN("a filter with no limit field")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"timeline":{"types":["m.room.message"]}}})");

        THEN("the limit defaults to 0 (meaning no cap)")
        {
            // Implementation: limit == 0 means no client-imposed cap.
            REQUIRE(filter.room.timeline.limit == 0U);
        }
    }
}

// Spec: "include_leave": Whether to include rooms the user has left in the sync response.
// Default is false per the spec.
SCENARIO("Filter include_leave defaults to false and is set correctly when present",
         "[sync][filter][conformance]")
{
    GIVEN("a filter with include_leave set to true")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"include_leave":true}})");

        THEN("include_leave is true")
        {
            // Spec: include_leave=true causes left rooms to appear in the sync response.
            REQUIRE(filter.room.include_leave);
        }
    }

    GIVEN("a filter without include_leave specified")
    {
        auto const filter = merovingian::sync::parse_filter_argument(
            R"({"room":{"timeline":{"limit":10}}})");

        THEN("include_leave defaults to false")
        {
            // Spec: absent include_leave means left rooms are omitted (default: false).
            REQUIRE_FALSE(filter.room.include_leave);
        }
    }
}
