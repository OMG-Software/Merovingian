// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/sync/sliding_sync_parser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace
{
[[nodiscard]] auto required_state(std::size_t count) -> std::string
{
    auto out = std::string{"["};
    for (auto i = std::size_t{0U}; i < count; ++i)
    {
        if (i != 0U)
        {
            out += ',';
        }
        out += "[\"m.room.member\",\"@u" + std::to_string(i) + ":example.org\"]";
    }
    out += ']';
    return out;
}

[[nodiscard]] auto subscriptions(std::size_t count, std::size_t required_state_count = 2U) -> std::string
{
    auto out = std::string{"{\"room_subscriptions\":{"};
    for (auto i = std::size_t{0U}; i < count; ++i)
    {
        if (i != 0U)
        {
            out += ',';
        }
        out += "\"!r" + std::to_string(i) +
               ":example.org\":{\"required_state\":" + required_state(required_state_count) +
               ",\"timeline_limit\":120}";
    }
    out += "}}";
    return out;
}

} // namespace

SCENARIO("sliding sync parser clamps both timeline surfaces to the supplied policy", "[sync][limits]")
{
    GIVEN("a policy whose timeline ceiling is below a list and subscription request")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.timeline_limit = 2U;
        auto const body =
            R"({"lists":{"a":{"ranges":[[0,1]],"timeline_limit":5}},"room_subscriptions":{"!r:example.org":{"timeline_limit":4}}})";

        WHEN("the request is parsed under that policy")
        {
            auto const parsed = merovingian::sync::parse_sliding_sync_request(body, limits);

            THEN("both requested timeline sizes are capped by the configured ceiling")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->lists.at("a").timeline_limit == 2U);
                REQUIRE(parsed->room_subscriptions.at("!r:example.org").timeline_limit == 2U);
            }
        }
    }
}

SCENARIO("sliding sync parser honors policy values above the compiled compatibility defaults", "[sync][limits]")
{
    GIVEN("a configured timeline ceiling of 150 and a request for 120 events")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.timeline_limit = 150U;
        auto const body = R"({"room_subscriptions":{"!r:example.org":{"timeline_limit":120}}})";

        WHEN("the request is parsed under that policy")
        {
            auto const parsed = merovingian::sync::parse_sliding_sync_request(body, limits);

            THEN("the configured higher ceiling is honored")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->room_subscriptions.at("!r:example.org").timeline_limit == 120U);
            }
        }
    }
}

SCENARIO("sliding sync count limits can be raised above their compatibility defaults", "[sync][limits]")
{
    GIVEN("configured subscription and required-state ceilings above 256")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.room_subscriptions = 300U;
        limits.required_state_entries = 300U;

        WHEN("a request uses 257 subscriptions and 257 required-state pairs")
        {
            auto const many_subscriptions =
                merovingian::sync::parse_sliding_sync_request(subscriptions(257U, 0U), limits);
            auto const many_state_pairs = merovingian::sync::parse_sliding_sync_request(
                std::string{"{\"room_subscriptions\":{\"!r:example.org\":{\"required_state\":"} + required_state(257U) +
                    "}}}",
                limits);

            THEN("the configured higher count ceilings admit both requests")
            {
                REQUIRE(many_subscriptions.has_value());
                REQUIRE_FALSE(
                    merovingian::sync::sliding_sync_request_limit_violation(*many_subscriptions, limits).has_value());
                REQUIRE(many_state_pairs.has_value());
                REQUIRE_FALSE(
                    merovingian::sync::sliding_sync_request_limit_violation(*many_state_pairs, limits).has_value());
            }
        }
    }
}

SCENARIO("sliding sync admission uses configured subscription and state pair ceilings", "[sync][limits]")
{
    GIVEN("a policy that permits two subscriptions with two required-state pairs each")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.room_subscriptions = 2U;
        limits.required_state_entries = 2U;
        auto const parsed = merovingian::sync::parse_sliding_sync_request(subscriptions(3U), limits);
        REQUIRE(parsed.has_value());

        WHEN("the parsed request exceeds the subscription policy")
        {
            auto const violation = merovingian::sync::sliding_sync_request_limit_violation(*parsed, limits);

            THEN("the policy checker reports the subscription bound")
            {
                REQUIRE(violation.has_value());
                REQUIRE(*violation == "too many room_subscriptions");
            }
        }
    }
}

SCENARIO("sliding sync required-state checks use configured policy and retain default compatibility", "[sync][limits]")
{
    GIVEN("one subscription with three required-state pairs and a configured cap of two")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.room_subscriptions = 4U;
        limits.required_state_entries = 2U;
        auto body = std::string{"{\"room_subscriptions\":{\"!r:example.org\":{\"required_state\":"} +
                    required_state(3U) + "}}}";
        auto const parsed = merovingian::sync::parse_sliding_sync_request(body, limits);
        REQUIRE(parsed.has_value());

        WHEN("the configured required-state policy is applied")
        {
            auto const violation = merovingian::sync::sliding_sync_request_limit_violation(*parsed, limits);

            THEN("the request is rejected by the supplied cap while default calls retain the old ceiling")
            {
                REQUIRE(violation.has_value());
                REQUIRE(*violation == "too many required_state entries in a room subscription");
                auto const default_violation = merovingian::sync::sliding_sync_request_limit_violation(*parsed);
                REQUIRE_FALSE(default_violation.has_value());
            }
        }
    }
}

SCENARIO("sliding sync position parsing remains independent of resource policy", "[sync][limits]")
{
    GIVEN("a valid encoded position and a restrictive empty-work policy")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.timeline_limit = 0U;
        limits.room_subscriptions = 0U;
        limits.required_state_entries = 0U;

        WHEN("request limits and the position are interpreted separately")
        {
            auto const parsed = merovingian::sync::parse_sliding_sync_request(R"({"pos":"1|2|3"})", limits);
            auto const pos = merovingian::sync::parse_sliding_sync_pos("/sync?pos=1_2_3");

            THEN("the request limits do not alter position decoding")
            {
                REQUIRE(parsed.has_value());
                REQUIRE_FALSE(merovingian::sync::sliding_sync_request_limit_violation(*parsed, limits).has_value());
                REQUIRE(pos.has_value());
                REQUIRE(pos->event_ordering == 1U);
            }
        }
    }
}

SCENARIO("sliding sync admission caps the number of lists, sort keys and bump event types",
         "[sliding-sync][limits][security][sp01]")
{
    // The numbers asserted here are the shipped defaults; the other givens override them with small caps to keep
    // requests tiny.
    GIVEN("the default sliding sync policy")
    {
        auto const limits = merovingian::sync::SlidingSyncLimits{};

        WHEN("the list-shape caps are read")
        {
            THEN("they are 32 lists, 3 sort keys per list and 64 bump event types per list")
            {
                REQUIRE(limits.lists == 32U);
                REQUIRE(limits.sort_keys == 3U);
                REQUIRE(limits.bump_event_types == 64U);
            }
        }
    }

    // Boundary pair for each cap: exactly at the cap is admitted, one more is rejected, so an off-by-one in either
    // direction is caught.
    GIVEN("a request with exactly as many lists as the policy allows")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.lists = 4U;
        auto request = merovingian::sync::SlidingSyncRequest{};
        for (auto i = std::size_t{0U}; i < limits.lists; ++i)
        {
            request.lists.emplace("list" + std::to_string(i), merovingian::sync::SlidingSyncList{});
        }

        WHEN("the request is checked against the policy")
        {
            auto const at_cap = merovingian::sync::sliding_sync_request_limit_violation(request, limits);

            THEN("it is admitted")
            {
                REQUIRE_FALSE(at_cap.has_value());
            }
        }

        WHEN("one more list is added and the request is checked")
        {
            request.lists.emplace("one-too-many", merovingian::sync::SlidingSyncList{});
            auto const over_cap = merovingian::sync::sliding_sync_request_limit_violation(request, limits);

            THEN("the list count is reported as the violation")
            {
                REQUIRE(over_cap.has_value());
                REQUIRE(*over_cap == "too many lists");
            }
        }
    }

    GIVEN("a list with exactly as many sort keys as the policy allows")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.sort_keys = 3U;
        auto list = merovingian::sync::SlidingSyncList{};
        list.sort = {"by_recency", "by_name", "by_notification_count"};
        auto request = merovingian::sync::SlidingSyncRequest{};

        WHEN("the request is checked against the policy")
        {
            request.lists.emplace("a", list);
            auto const at_cap = merovingian::sync::sliding_sync_request_limit_violation(request, limits);

            THEN("it is admitted")
            {
                REQUIRE_FALSE(at_cap.has_value());
            }
        }

        // The extra key repeats an existing one: the cap counts entries, not distinct keys.
        WHEN("the list repeats a sort key so that it has one more than the policy allows")
        {
            list.sort.emplace_back("by_recency");
            request.lists.emplace("a", list);
            auto const over_cap = merovingian::sync::sliding_sync_request_limit_violation(request, limits);

            THEN("the sort key count is reported as the violation")
            {
                REQUIRE(over_cap.has_value());
                REQUIRE(*over_cap == "too many sort keys in a list");
            }
        }
    }

    // Bump event types are counted per list, so the cap is set on a single list rather than across the request.
    GIVEN("a list with exactly as many bump event types as the policy allows")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.bump_event_types = 5U;
        auto list = merovingian::sync::SlidingSyncList{};
        for (auto i = std::size_t{0U}; i < limits.bump_event_types; ++i)
        {
            list.bump_event_types.push_back("m.test.type" + std::to_string(i));
        }
        auto request = merovingian::sync::SlidingSyncRequest{};

        WHEN("the request is checked against the policy")
        {
            request.lists.emplace("a", list);
            auto const at_cap = merovingian::sync::sliding_sync_request_limit_violation(request, limits);

            THEN("it is admitted")
            {
                REQUIRE_FALSE(at_cap.has_value());
            }
        }

        WHEN("one more bump event type is added and the request is checked")
        {
            list.bump_event_types.emplace_back("m.test.one-too-many");
            request.lists.emplace("a", list);
            auto const over_cap = merovingian::sync::sliding_sync_request_limit_violation(request, limits);

            THEN("the bump event type count is reported as the violation")
            {
                REQUIRE(over_cap.has_value());
                REQUIRE(*over_cap == "too many bump_event_types in a list");
            }
        }
    }

    // The cases below use the real defaults, with no custom limits, to prove the production values are what actually
    // gets enforced.
    GIVEN("a request that exceeds the default list, sort key and bump event type caps")
    {
        auto const limits = merovingian::sync::SlidingSyncLimits{};

        WHEN("33 lists are sent")
        {
            auto request = merovingian::sync::SlidingSyncRequest{};
            for (auto i = std::size_t{0U}; i < 33U; ++i)
            {
                request.lists.emplace("list" + std::to_string(i), merovingian::sync::SlidingSyncList{});
            }

            // The overload without a limits argument must apply the same defaults, not an unlimited policy.
            THEN("both the explicit defaults and the default-argument overload reject it")
            {
                auto const explicit_default = merovingian::sync::sliding_sync_request_limit_violation(request, limits);
                auto const implicit_default = merovingian::sync::sliding_sync_request_limit_violation(request);
                REQUIRE(explicit_default.has_value());
                REQUIRE(*explicit_default == "too many lists");
                REQUIRE(implicit_default.has_value());
                REQUIRE(*implicit_default == "too many lists");
            }
        }

        WHEN("a list with 4 sort keys is sent")
        {
            auto list = merovingian::sync::SlidingSyncList{};
            list.sort = {"by_recency", "by_name", "by_recency", "by_name"};
            auto request = merovingian::sync::SlidingSyncRequest{};
            request.lists.emplace("a", list);

            THEN("the default policy rejects it")
            {
                auto const violation = merovingian::sync::sliding_sync_request_limit_violation(request);
                REQUIRE(violation.has_value());
                REQUIRE(*violation == "too many sort keys in a list");
            }
        }

        WHEN("a list with 65 bump event types is sent")
        {
            auto list = merovingian::sync::SlidingSyncList{};
            for (auto i = std::size_t{0U}; i < 65U; ++i)
            {
                list.bump_event_types.push_back("m.test.type" + std::to_string(i));
            }
            auto request = merovingian::sync::SlidingSyncRequest{};
            request.lists.emplace("a", list);

            THEN("the default policy rejects it")
            {
                auto const violation = merovingian::sync::sliding_sync_request_limit_violation(request);
                REQUIRE(violation.has_value());
                REQUIRE(*violation == "too many bump_event_types in a list");
            }
        }
    }
}

// Security audit run-1 (sp01.sliding-sync-extension-rooms-unbounded): every room named in the
// receipts or typing extension's `rooms` array costs a membership lookup (and, for receipts, the
// room's receipts) while the runtime lock is held. Each array is bounded like
// room_subscriptions, the request's other list of client-named rooms, and a repeated room ID
// counts once.
SCENARIO("sliding sync bounds and de-duplicates the receipts and typing extension rooms arrays",
         "[sliding-sync][limits][security][sp01]")
{
    auto const request_naming = [](std::size_t receipts, std::size_t typing) {
        auto request = merovingian::sync::SlidingSyncRequest{};
        auto extensions = merovingian::sync::SlidingSyncExtensionRequests{};
        auto receipt_req = merovingian::sync::ExtReceiptsRequest{};
        receipt_req.enabled = true;
        for (auto i = std::size_t{0U}; i < receipts; ++i)
        {
            receipt_req.rooms.push_back("!r" + std::to_string(i) + ":example.org");
        }
        auto typing_req = merovingian::sync::ExtTypingRequest{};
        typing_req.enabled = true;
        for (auto i = std::size_t{0U}; i < typing; ++i)
        {
            typing_req.rooms.push_back("!t" + std::to_string(i) + ":example.org");
        }
        extensions.receipts = std::move(receipt_req);
        extensions.typing = std::move(typing_req);
        request.extensions = std::move(extensions);
        return request;
    };

    GIVEN("a policy allowing 4 client-named rooms")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.room_subscriptions = 4U;

        WHEN("each extension names exactly 4 rooms")
        {
            auto const violation =
                merovingian::sync::sliding_sync_request_limit_violation(request_naming(4U, 4U), limits);

            THEN("the request is admitted")
            {
                REQUIRE_FALSE(violation.has_value());
            }
        }

        WHEN("the receipts extension names 5 rooms")
        {
            auto const violation =
                merovingian::sync::sliding_sync_request_limit_violation(request_naming(5U, 0U), limits);

            THEN("the receipts rooms array is reported as the violation")
            {
                REQUIRE(violation.has_value());
                REQUIRE(*violation == "too many rooms in the receipts extension");
            }
        }

        WHEN("the typing extension names 5 rooms")
        {
            auto const violation =
                merovingian::sync::sliding_sync_request_limit_violation(request_naming(0U, 5U), limits);

            THEN("the typing rooms array is reported as the violation")
            {
                REQUIRE(violation.has_value());
                REQUIRE(*violation == "too many rooms in the typing extension");
            }
        }
    }

    GIVEN("a request body naming the same room many times in each extension")
    {
        auto rooms = std::string{};
        for (auto i = 0; i < 50; ++i)
        {
            rooms += std::string{i == 0 ? "" : ","} + "\"!same:example.org\",\"!other:example.org\"";
        }
        auto const body = R"({"extensions":{"receipts":{"enabled":true,"rooms":[)" + rooms +
                          R"(]},"typing":{"enabled":true,"rooms":[)" + rooms + R"(]}}})";

        WHEN("it is parsed")
        {
            auto const parsed = merovingian::sync::parse_sliding_sync_request(body);

            THEN("each room is kept once, in first-seen order, so the request is within any cap of 2")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->extensions.has_value());
                auto const expected = std::vector<std::string>{"!same:example.org", "!other:example.org"};
                REQUIRE(parsed->extensions->receipts->rooms == expected);
                REQUIRE(parsed->extensions->typing->rooms == expected);
                auto limits = merovingian::sync::SlidingSyncLimits{};
                limits.room_subscriptions = 2U;
                REQUIRE_FALSE(merovingian::sync::sliding_sync_request_limit_violation(*parsed, limits).has_value());
            }
        }
    }
}
