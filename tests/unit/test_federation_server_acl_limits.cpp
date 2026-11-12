// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/ServerAcl.hpp"
#include "merovingian/federation/ServerAclDecision.hpp"
#include "merovingian/federation/ServerAclEvent.hpp"
#include "merovingian/federation/ServerAclGlob.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

using namespace merovingian::federation;

namespace
{

// The table matcher the server used before ADR-0640: the reference every answer must still equal.
[[nodiscard]] auto reference_glob(std::string_view pattern, std::string_view text) -> bool
{
    auto previous = std::vector<char>(text.size() + 1U, 0);
    auto current = std::vector<char>(text.size() + 1U, 0);
    previous[0U] = 1;
    for (auto p = std::size_t{1U}; p <= pattern.size(); ++p)
    {
        auto const c = pattern[p - 1U];
        std::ranges::fill(current, 0);
        if (c == '*')
        {
            current[0U] = previous[0U];
            for (auto t = std::size_t{1U}; t <= text.size(); ++t)
            {
                current[t] = static_cast<char>(previous[t] != 0 || current[t - 1U] != 0);
            }
        }
        else
        {
            for (auto t = std::size_t{1U}; t <= text.size(); ++t)
            {
                auto const same = c == '?' || std::tolower(static_cast<unsigned char>(c)) ==
                                                  std::tolower(static_cast<unsigned char>(text[t - 1U]));
                current[t] = same ? previous[t - 1U] : char{0};
            }
        }
        previous.swap(current);
    }
    return previous[text.size()] != 0;
}

[[nodiscard]] auto all_strings(std::string_view alphabet, std::size_t max_length) -> std::vector<std::string>
{
    auto result = std::vector<std::string>{""};
    auto start = std::size_t{0U};
    for (auto length = std::size_t{1U}; length <= max_length; ++length)
    {
        auto const end = result.size();
        for (auto index = start; index < end; ++index)
        {
            for (auto const letter : alphabet)
            {
                result.push_back(result[index] + letter);
            }
        }
        start = end;
    }
    return result;
}

[[nodiscard]] auto acl_with(std::vector<std::string> allow, std::vector<std::string> deny) -> ServerAclEvent
{
    auto acl = ServerAclEvent{};
    acl.allow = std::move(allow);
    acl.deny = std::move(deny);
    return acl;
}

[[nodiscard]] auto content_json(std::vector<std::string> const& allow, std::vector<std::string> const& deny)
    -> std::string
{
    auto const list = [](std::vector<std::string> const& patterns) {
        auto out = std::string{"["};
        for (auto const& pattern : patterns)
        {
            out += (out.size() > 1U ? ",\"" : "\"") + pattern + "\"";
        }
        return out + "]";
    };
    return R"({"allow":)" + list(allow) + R"(,"deny":)" + list(deny) + "}";
}

[[nodiscard]] auto parsed_acl(std::string const& content) -> ServerAclEvent
{
    auto const parsed = merovingian::canonicaljson::parse_json(content);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return parse_server_acl(parsed.value);
}

} // namespace

SCENARIO("The linear server ACL glob answers exactly as the table matcher did",
         "[federation][security][acl][acl_limits]")
{
    GIVEN("every pattern up to four characters and every text up to five over a small alphabet")
    {
        auto const patterns = all_strings("aB?*", 4U);
        auto const texts = all_strings("ab", 5U);

        WHEN("each pair is matched")
        {
            auto mismatches = std::size_t{0U};
            auto exhausted = std::size_t{0U};
            for (auto const& pattern : patterns)
            {
                for (auto const& text : texts)
                {
                    auto steps = std::size_t{100000U};
                    auto const answer = server_acl_glob_match(pattern, text, steps);
                    if (!answer.has_value())
                    {
                        ++exhausted;
                    }
                    else if (*answer != reference_glob(pattern, text))
                    {
                        ++mismatches;
                    }
                }
            }

            THEN("no answer differs and none runs out of steps")
            {
                REQUIRE(mismatches == 0U);
                REQUIRE(exhausted == 0U);
            }
        }
    }
}

SCENARIO("A server ACL glob spends work in proportion to pattern and text", "[federation][security][acl][acl_limits]")
{
    GIVEN("a 255-character server name and a pattern shape that was worst for the table matcher")
    {
        auto const host = std::string(255U, 'a');
        auto alternating = std::string{};
        for (auto index = 0U; index < 100U; ++index)
        {
            alternating += "b*";
        }
        constexpr auto allowance = std::size_t{1000000U};

        WHEN("a pattern of alternating b and star is matched")
        {
            auto steps = allowance;
            auto const answer = server_acl_glob_match(alternating, host, steps);
            auto const spent = allowance - steps;

            THEN("it is refused for at most a few steps per character")
            {
                REQUIRE(answer == std::optional<bool>{false});
                REQUIRE(spent <= 2U * (alternating.size() + host.size()));
            }
        }

        WHEN("a star, a literal that never occurs and a final literal are matched")
        {
            auto steps = allowance;
            auto const answer = server_acl_glob_match("*b*a", host, steps);
            auto const spent = allowance - steps;

            THEN("the work is at most twice the text")
            {
                REQUIRE(answer == std::optional<bool>{false});
                REQUIRE(spent <= 2U * host.size() + 4U);
            }
        }

        WHEN("the step allowance is smaller than the work")
        {
            auto steps = std::size_t{10U};
            auto const answer = server_acl_glob_match("*b", host, steps);

            THEN("the answer is not a verdict")
            {
                REQUIRE_FALSE(answer.has_value());
                REQUIRE(steps == 0U);
            }
        }
    }
}

SCENARIO("A server ACL past its caps refuses every server and one under them is unchanged",
         "[federation][security][acl][acl_limits]")
{
    GIVEN("ACL contents at and just past the pattern count and pattern length caps")
    {
        auto at_count = std::vector<std::string>(server_acl_max_patterns - 1U, "x.example");
        at_count.emplace_back("*");
        auto past_count = at_count;
        past_count.emplace_back("y.example");
        auto const at_length = std::string(server_acl_max_pattern_length - 2U, 'a') + ".*";
        auto const past_length = at_length + "b";

        WHEN("the ACL holds exactly the cap of patterns")
        {
            auto const acl = parsed_acl(content_json(at_count, {}));

            THEN("it is evaluated: the star allows a server")
            {
                REQUIRE_FALSE(acl.exceeds_limits);
                REQUIRE(evaluate_server_acl("any.example", acl).decision == ServerAclDecision::allow);
            }
        }

        WHEN("the ACL holds one pattern more than the cap")
        {
            auto const acl = parsed_acl(content_json(past_count, {}));

            THEN("it refuses every server with the limits rule")
            {
                REQUIRE(acl.exceeds_limits);
                auto const evaluation = evaluate_server_acl("any.example", acl);
                REQUIRE(evaluation.decision == ServerAclDecision::deny);
                REQUIRE(evaluation.rule == "acl_limits");
            }
        }

        WHEN("a pattern is exactly as long as the cap")
        {
            auto const acl = parsed_acl(content_json({at_length}, {}));

            THEN("it is evaluated")
            {
                REQUIRE(at_length.size() == server_acl_max_pattern_length);
                REQUIRE_FALSE(acl.exceeds_limits);
            }
        }

        WHEN("a deny pattern is one character longer than the cap")
        {
            auto const acl = parsed_acl(content_json({"*"}, {past_length}));

            THEN("the ACL refuses every server rather than skipping the deny pattern")
            {
                REQUIRE(acl.exceeds_limits);
                REQUIRE(evaluate_server_acl("any.example", acl).rule == "acl_limits");
            }
        }
    }
}

SCENARIO("A server ACL check stops at its step budget and refuses", "[federation][security][acl][acl_limits]")
{
    GIVEN("thousands of patterns that each scan a 255-character server name")
    {
        auto const acl = acl_with({"*"}, std::vector<std::string>(server_acl_max_patterns, "*b"));

        WHEN("the long name is checked")
        {
            auto const evaluation = evaluate_server_acl(std::string(255U, 'a'), acl);

            THEN("the check is refused for its budget instead of running to the end")
            {
                REQUIRE(evaluation.decision == ServerAclDecision::deny);
                REQUIRE(evaluation.rule == "acl_budget");
            }
        }

        WHEN("an ordinary name is checked")
        {
            auto const evaluation = evaluate_server_acl("example.org", acl);

            THEN("the allow list still decides")
            {
                REQUIRE(evaluation.decision == ServerAclDecision::allow);
                REQUIRE(evaluation.rule == "allow");
            }
        }
    }
}

SCENARIO("A cached room server ACL follows the event it was parsed from", "[federation][security][acl][acl_limits]")
{
    GIVEN("a room whose ACL event has been checked once")
    {
        using namespace merovingian::database;
        auto store = PersistentStore{};
        auto const room_id = std::string{"!limits-room:example.org"};
        auto const event_id = std::string{"$limits-acl-event"};
        store.state.push_back(PersistentStateEvent{room_id, "m.room.server_acl", "", event_id});
        auto const make_json = [&](std::string const& content) {
            return R"({"type":"m.room.server_acl","state_key":"","sender":"@a:example.org","content":)" + content +
                   R"(,"event_id":")" + event_id + R"("})";
        };
        store.events.push_back(PersistentEvent{event_id, room_id, "@a:example.org",
                                               make_json(R"({"allow":["*"],"deny":["evil.org"]})"), 0U, 0U});
        REQUIRE(room_server_acl_allows(store, room_id, "good.org"));
        REQUIRE_FALSE(room_server_acl_allows(store, room_id, "evil.org"));

        WHEN("the same event ID now holds redacted content")
        {
            std::ignore = store.events.erase_if([&](PersistentEvent const& event) {
                return event.event_id == event_id;
            });
            store.events.push_back(PersistentEvent{event_id, room_id, "@a:example.org", make_json("{}"), 0U, 0U});

            THEN("the check follows the stored content, not the earlier parse")
            {
                REQUIRE_FALSE(room_server_acl_allows(store, room_id, "good.org"));
            }
        }
    }
}
