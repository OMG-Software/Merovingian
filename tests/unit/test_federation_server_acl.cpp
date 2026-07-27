// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/federation/server_acl.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace merovingian::federation;

namespace
{

[[nodiscard]] auto acl_from_json(std::string_view content_json) -> ServerAclEvent
{
    auto const parsed = merovingian::canonicaljson::parse_json(content_json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return parse_server_acl(parsed.value);
}

} // namespace

SCENARIO("Server ACL port stripping ignores ports while preserving host names", "[federation][security][acl]")
{
    GIVEN("server names with and without ports")
    {
        WHEN("ports are stripped")
        {
            THEN("the host is returned without the trailing port")
            {
                REQUIRE(strip_server_port("evil.com") == "evil.com");
                REQUIRE(strip_server_port("evil.com:8448") == "evil.com");
                REQUIRE(strip_server_port("evil.com:1234") == "evil.com");
                REQUIRE(strip_server_port("[2001:db8::1]:8448") == "[2001:db8::1]");
                REQUIRE(strip_server_port("[::1]") == "[::1]");
            }
            THEN("non-numeric ports and malformed inputs are left unchanged")
            {
                REQUIRE(strip_server_port("").empty());
                REQUIRE(strip_server_port(":8448") == ":8448");
                REQUIRE(strip_server_port("evil.com:abc") == "evil.com:abc");
                REQUIRE(strip_server_port("[2001:db8::1") == "[2001:db8::1");
            }
        }
    }
}

SCENARIO("Server ACL glob matching is case-insensitive and supports * and ?", "[federation][security][acl]")
{
    GIVEN("an ACL that denies *.evil.com and allows *.example.org")
    {
        auto const acl = acl_from_json(R"({"allow":["*.example.org"],"deny":["*.evil.com"]})");
        REQUIRE(acl.deny.size() == 1U);
        REQUIRE(acl.deny.front() == "*.evil.com");

        WHEN("checking server names against the ACL")
        {
            THEN("wildcard deny entries match subdomains exactly")
            {
                REQUIRE(evaluate_server_acl("sub.evil.com", acl).decision == ServerAclDecision::deny);
                REQUIRE(evaluate_server_acl("SUB.EVIL.COM", acl).decision == ServerAclDecision::deny);
                REQUIRE(evaluate_server_acl("deep.sub.evil.com", acl).decision == ServerAclDecision::deny);
            }
            THEN("deny entries do not match the parent domain or unrelated suffixes")
            {
                // Neither evil.com nor evilevil.com matches the *.evil.com deny
                // pattern (standard glob requires the literal dot before "evil").
                auto const parent = evaluate_server_acl("evil.com", acl);
                REQUIRE(parent.decision == ServerAclDecision::deny);

                auto const similar = evaluate_server_acl("evilevil.com", acl);
                REQUIRE(similar.decision == ServerAclDecision::deny);
            }
            THEN("wildcard allow entries permit matching servers")
            {
                REQUIRE(evaluate_server_acl("matrix.example.org", acl).decision == ServerAclDecision::allow);
                REQUIRE(evaluate_server_acl("MATRIX.EXAMPLE.ORG", acl).decision == ServerAclDecision::allow);
            }
            THEN("unmatched servers are denied when an allow list exists")
            {
                REQUIRE(evaluate_server_acl("other.org", acl).decision == ServerAclDecision::deny);
            }
        }
    }
}

SCENARIO("Server ACL single-character ? globs match exactly one character", "[federation][security][acl]")
{
    GIVEN("an ACL that allows ?evil.com and denies b?d.com")
    {
        auto const acl = acl_from_json(R"({"allow":["?evil.com"],"deny":["b?d.com"]})");

        WHEN("checking server names")
        {
            THEN("? matches a single character at its position")
            {
                REQUIRE(evaluate_server_acl("1evil.com", acl).decision == ServerAclDecision::allow);
                REQUIRE(evaluate_server_acl("12evil.com", acl).decision == ServerAclDecision::deny);
                REQUIRE(evaluate_server_acl("bad.com", acl).decision == ServerAclDecision::deny);
                REQUIRE(evaluate_server_acl("bd.com", acl).decision == ServerAclDecision::deny);
            }
        }
    }
}

SCENARIO("Server ACL with no allow list permits servers not explicitly denied", "[federation][security][acl]")
{
    GIVEN("an ACL that only denies evil.com")
    {
        auto const acl = acl_from_json(R"({"deny":["evil.com"]})");
        REQUIRE(acl.deny.size() == 1U);
        REQUIRE(acl.deny.front() == "evil.com");

        WHEN("checking a denied and an allowed server")
        {
            THEN("only the explicitly denied server is rejected")
            {
                auto const evil_result = evaluate_server_acl("evil.com", acl);
                REQUIRE(evil_result.decision == ServerAclDecision::deny);

                auto const good_result = evaluate_server_acl("good.com", acl);
                CAPTURE(good_result.decision);
                CAPTURE(good_result.rule);
                CAPTURE(good_result.reason);
                REQUIRE(good_result.decision == ServerAclDecision::allow);
            }
        }
    }
}

SCENARIO("Server ACL IP-literal denial works for IPv4 and bracketed IPv6", "[federation][security][acl]")
{
    GIVEN("an ACL that disallows IP literals")
    {
        auto const acl = acl_from_json(R"({"allow":["*"],"allow_ip_literals":false})");

        WHEN("checking IP literal server names")
        {
            THEN("IPv4 and bracketed IPv6 literals are denied")
            {
                REQUIRE(evaluate_server_acl("1.2.3.4", acl).decision == ServerAclDecision::deny);
                REQUIRE(evaluate_server_acl("1.2.3.4:8448", acl).decision == ServerAclDecision::deny);
                REQUIRE(evaluate_server_acl("[2001:db8::1]", acl).decision == ServerAclDecision::deny);
                REQUIRE(evaluate_server_acl("[2001:db8::1]:8448", acl).decision == ServerAclDecision::deny);
            }
            THEN("domain names are still allowed")
            {
                REQUIRE(evaluate_server_acl("example.org", acl).decision == ServerAclDecision::allow);
                REQUIRE(evaluate_server_acl("example.org:8448", acl).decision == ServerAclDecision::allow);
            }
        }
    }
}

SCENARIO("Server ACL deny rules are evaluated before allow rules", "[federation][security][acl]")
{
    GIVEN("an ACL that both allows and denies the same pattern")
    {
        auto const acl = acl_from_json(R"({"allow":["*"],"deny":["*.evil.com"]})");

        WHEN("checking a server that matches both lists")
        {
            THEN("deny takes precedence")
            {
                REQUIRE(evaluate_server_acl("sub.evil.com", acl).decision == ServerAclDecision::deny);
            }
        }
    }
}

SCENARIO("Server ACL allow_ip_literals defaults to true when missing", "[federation][security][acl]")
{
    GIVEN("an ACL with no allow_ip_literals field")
    {
        auto const acl = acl_from_json(R"({"allow":["*"]})");

        WHEN("checking an IP literal")
        {
            THEN("IP literals are allowed by default")
            {
                REQUIRE(evaluate_server_acl("1.2.3.4", acl).decision == ServerAclDecision::allow);
                REQUIRE(evaluate_server_acl("[::1]", acl).decision == ServerAclDecision::allow);
            }
        }
    }
}

SCENARIO("Server ACL IP-literal detection recognises IPv4 and bracketed IPv6", "[federation][security][acl]")
{
    GIVEN("a mix of literal and domain server names")
    {
        WHEN("testing whether a server name is an IP literal")
        {
            THEN("IPv4 and bracketed IPv6 are detected")
            {
                REQUIRE(server_name_is_ip_literal("1.2.3.4"));
                REQUIRE(server_name_is_ip_literal("1.2.3.4:8448"));
                REQUIRE(server_name_is_ip_literal("[::1]"));
                REQUIRE(server_name_is_ip_literal("[2001:db8::1]:8448"));
            }
            THEN("domain names are not IP literals")
            {
                REQUIRE_FALSE(server_name_is_ip_literal("example.org"));
                REQUIRE_FALSE(server_name_is_ip_literal("example.org:8448"));
                REQUIRE_FALSE(server_name_is_ip_literal(""));
            }
        }
    }
}

SCENARIO("Server ACL is loaded from persistent store state", "[federation][security][acl]")
{
    GIVEN("a persistent store containing an m.room.server_acl state event")
    {
        using namespace merovingian::database;
        auto store = PersistentStore{};
        auto const room_id = std::string{"!room:example.org"};
        auto const event_id = std::string{"$acl-event-id"};
        store.state.push_back(PersistentStateEvent{room_id, "m.room.server_acl", "", event_id});
        store.events.push_back(PersistentEvent{
            event_id,
            room_id,
            "@alice:example.org",
            R"({"type":"m.room.server_acl","state_key":"","sender":"@alice:example.org","content":{"allow":["*.example.org"],"deny":["evil.org"]},"event_id":"$acl-event-id"})",
            0U,
            0U,
        });

        WHEN("loading the ACL for that room")
        {
            auto const acl = load_room_server_acl(store, room_id);

            THEN("the parsed content is returned")
            {
                REQUIRE(acl.has_value());
                REQUIRE(acl->allow.size() == 1U);
                REQUIRE(acl->allow.front() == "*.example.org");
                REQUIRE(acl->deny.size() == 1U);
                REQUIRE(acl->deny.front() == "evil.org");
            }
        }

        WHEN("checking server names against the stored ACL")
        {
            THEN("allowed and denied servers are evaluated correctly")
            {
                REQUIRE(room_server_acl_allows(store, room_id, "matrix.example.org"));
                REQUIRE_FALSE(room_server_acl_allows(store, room_id, "evil.org"));
            }
        }
    }
}

SCENARIO("Server ACL rooms with no ACL event allow all servers", "[federation][security][acl]")
{
    GIVEN("a persistent store with no m.room.server_acl state")
    {
        using namespace merovingian::database;
        auto store = PersistentStore{};
        auto const room_id = std::string{"!room:example.org"};

        WHEN("checking any server against the room")
        {
            THEN("the absence of an ACL event allows everything")
            {
                REQUIRE_FALSE(load_room_server_acl(store, room_id).has_value());
                REQUIRE(room_server_acl_allows(store, room_id, "evil.org"));
                REQUIRE(room_server_acl_allows(store, room_id, "matrix.example.org"));
            }
        }
    }
}

SCENARIO("Server ACL parser falls back to spec defaults for malformed content", "[federation][security][acl]")
{
    GIVEN("content that is not a JSON object")
    {
        auto const parsed = merovingian::canonicaljson::parse_json("42");
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("parsing it as a server ACL")
        {
            auto const acl = parse_server_acl(parsed.value);

            THEN("defaults are returned so enforcement remains safe")
            {
                REQUIRE(acl.allow.empty());
                REQUIRE(acl.deny.empty());
                REQUIRE(acl.allow_ip_literals);
                // With empty allow and deny lists every server is permitted.
                REQUIRE(evaluate_server_acl("example.org", acl).decision == ServerAclDecision::allow);
            }
        }
    }
}
