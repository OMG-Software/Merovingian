// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |          APPLICATION SERVICE REGISTRATION — PARSING & NAMESPACES        |
// |                                                                         |
// |  Spec: Matrix Application Service API v1.19, "Registration"            |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// |                                                                         |
// |  Pure, network-free coverage of registration-file parsing, namespace   |
// |  matching, exclusivity, and cross-registration uniqueness validation.  |
// +-------------------------------------------------------------------------+

#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/appservice/registration.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using merovingian::appservice::any_exclusive_namespace_matches;
using merovingian::appservice::any_namespace_matches;
using merovingian::appservice::appservice_owns_user;
using merovingian::appservice::AppserviceRegistration;
using merovingian::appservice::AppserviceRegistry;
using merovingian::appservice::EventInterestFacts;
using merovingian::appservice::load_registration_file;
using merovingian::appservice::load_registrations;
using merovingian::appservice::Namespace;
using merovingian::appservice::namespace_matches;
using merovingian::appservice::parse_registration_json;
using merovingian::appservice::registration_interested_in_room_event;
using merovingian::appservice::sender_user_id;
using merovingian::appservice::validate_registrations;

namespace
{

[[nodiscard]] auto irc_bridge_registration_json() -> std::string
{
    return R"({
        "id": "irc-bridge",
        "url": "http://127.0.0.1:1234",
        "as_token": "irc-as-token-secret",
        "hs_token": "irc-hs-token-secret",
        "sender_localpart": "_irc_bot",
        "namespaces": {
            "users": [{"exclusive": true, "regex": "@_irc_bridge_.*"}],
            "aliases": [{"exclusive": false, "regex": "#_irc_bridge_.*"}],
            "rooms": []
        },
        "protocols": ["irc"]
    })";
}

} // namespace

SCENARIO("parsing a well-formed registration file", "[appservice][registration]")
{
    GIVEN("a spec-shaped IRC bridge registration document")
    {
        auto const json = irc_bridge_registration_json();

        WHEN("it is parsed")
        {
            auto const result = parse_registration_json(json);

            THEN("every required field is populated")
            {
                REQUIRE(result.value.has_value());
                CHECK(result.value->id == "irc-bridge");
                REQUIRE(result.value->url.has_value());
                CHECK(*result.value->url == "http://127.0.0.1:1234");
                CHECK(result.value->sender_localpart == "_irc_bot");
                CHECK(result.value->namespaces.users.size() == 1U);
                CHECK(result.value->namespaces.users.front().exclusive);
                CHECK(result.value->namespaces.aliases.size() == 1U);
                CHECK_FALSE(result.value->namespaces.aliases.front().exclusive);
                CHECK(result.value->namespaces.rooms.empty());
                CHECK(result.value->protocols == std::vector<std::string>{"irc"});
                // rate_limited and receive_ephemeral default per spec.
                CHECK(result.value->rate_limited);
                CHECK_FALSE(result.value->receive_ephemeral);
            }
        }
    }

    GIVEN("a registration document with url explicitly null")
    {
        auto const json = std::string{R"({
            "id": "no-traffic-service",
            "url": null,
            "as_token": "tok-a",
            "hs_token": "tok-b",
            "sender_localpart": "bot",
            "namespaces": {}
        })"};

        WHEN("it is parsed")
        {
            auto const result = parse_registration_json(json);

            THEN("url is nullopt, not an error")
            {
                REQUIRE(result.value.has_value());
                CHECK_FALSE(result.value->url.has_value());
            }
        }
    }
}

SCENARIO("rejecting malformed or incomplete registration documents", "[appservice][registration]")
{
    GIVEN("a document missing as_token")
    {
        auto const json = std::string{R"({
            "id": "bad",
            "url": "http://example.org",
            "hs_token": "tok",
            "sender_localpart": "bot",
            "namespaces": {}
        })"};

        WHEN("it is parsed")
        {
            auto const result = parse_registration_json(json);

            THEN("parsing fails")
            {
                REQUIRE_FALSE(result.value.has_value());
            }
        }
    }

    GIVEN("a document missing the namespaces object")
    {
        auto const json = std::string{R"({
            "id": "bad",
            "url": "http://example.org",
            "as_token": "a",
            "hs_token": "b",
            "sender_localpart": "bot"
        })"};

        WHEN("it is parsed")
        {
            auto const result = parse_registration_json(json);

            THEN("parsing fails")
            {
                REQUIRE_FALSE(result.value.has_value());
            }
        }
    }

    GIVEN("a document that is not valid JSON")
    {
        auto const json = std::string{"not json at all"};

        WHEN("it is parsed")
        {
            auto const result = parse_registration_json(json);

            THEN("parsing fails")
            {
                REQUIRE_FALSE(result.value.has_value());
            }
        }
    }

    GIVEN("a namespace entry missing the required 'exclusive' boolean")
    {
        auto const json = std::string{R"({
            "id": "bad",
            "url": "http://example.org",
            "as_token": "a",
            "hs_token": "b",
            "sender_localpart": "bot",
            "namespaces": {"users": [{"regex": "@foo_.*"}]}
        })"};

        WHEN("it is parsed")
        {
            auto const result = parse_registration_json(json);

            THEN("parsing fails")
            {
                REQUIRE_FALSE(result.value.has_value());
            }
        }
    }
}

SCENARIO("loading a registration file from disk", "[appservice][registration]")
{
    GIVEN("a registration file written to a temp path")
    {
        auto const dir = std::filesystem::temp_directory_path();
        auto const path = dir / "merovingian-test-appservice-registration.json";
        {
            auto out = std::ofstream{path, std::ios::binary};
            out << irc_bridge_registration_json();
        }

        WHEN("load_registration_file reads it")
        {
            auto const result = load_registration_file(path.string());

            THEN("it parses successfully")
            {
                REQUIRE(result.value.has_value());
                CHECK(result.value->id == "irc-bridge");
            }
        }

        std::filesystem::remove(path);
    }

    GIVEN("a path that does not exist")
    {
        WHEN("load_registration_file is called")
        {
            auto const result = load_registration_file("/nonexistent/path/to/registration.json");

            THEN("it fails without throwing")
            {
                REQUIRE_FALSE(result.value.has_value());
            }
        }
    }
}

SCENARIO("namespace regex matching", "[appservice][registration]")
{
    GIVEN("an exclusive users namespace matching @_irc_bridge_.*")
    {
        auto namespaces = std::vector<Namespace>{
            {true, "@_irc_bridge_.*"}
        };

        WHEN("a user id inside the namespace is checked")
        {
            THEN("it matches, including as an exclusive match")
            {
                CHECK(any_namespace_matches(namespaces, "@_irc_bridge_alice:example.org"));
                CHECK(any_exclusive_namespace_matches(namespaces, "@_irc_bridge_alice:example.org"));
            }
        }

        WHEN("a user id outside the namespace is checked")
        {
            THEN("it does not match")
            {
                CHECK_FALSE(any_namespace_matches(namespaces, "@alice:example.org"));
            }
        }
    }

    GIVEN("a malformed regular expression")
    {
        WHEN("namespace_matches is called with it")
        {
            THEN("it fails closed to false rather than throwing")
            {
                CHECK_FALSE(namespace_matches("(unclosed", "anything"));
            }
        }
    }
}

SCENARIO("appservice_owns_user rejects foreign users before namespace matching",
         "[appservice][registration][security][auth-6]")
{
    GIVEN("a registration whose users namespace would match a foreign user id")
    {
        auto const json = std::string{R"({
            "id": "bridge",
            "url": "http://127.0.0.1:5555",
            "as_token": "as-token",
            "hs_token": "hs-token",
            "sender_localpart": "bot",
            "namespaces": {
                "users": [{"regex": "@_x_.*", "exclusive": false}]
            }
        })"};
        auto const parsed = parse_registration_json(json);
        REQUIRE(parsed.value.has_value());

        WHEN("checked against a matching user on a different homeserver")
        {
            THEN("appservice_owns_user is false")
            {
                CHECK_FALSE(appservice_owns_user(*parsed.value, "example.org", "@_x_a:other.org"));
            }
        }

        WHEN("checked against a matching user on the local homeserver")
        {
            THEN("appservice_owns_user is true")
            {
                CHECK(appservice_owns_user(*parsed.value, "example.org", "@_x_a:example.org"));
            }
        }
    }
}

SCENARIO("appservice_owns_user resolves the sender_localpart default", "[appservice][registration]")
{
    GIVEN("a registration whose sender_localpart is '_irc_bot' with no matching users namespace")
    {
        auto const parsed = parse_registration_json(irc_bridge_registration_json());
        REQUIRE(parsed.value.has_value());

        WHEN("checked against the sender's own user id")
        {
            THEN("appservice_owns_user is true")
            {
                CHECK(sender_user_id(*parsed.value, "example.org") == "@_irc_bot:example.org");
                CHECK(appservice_owns_user(*parsed.value, "example.org", "@_irc_bot:example.org"));
            }
        }

        WHEN("checked against a user id inside the users namespace")
        {
            THEN("appservice_owns_user is true")
            {
                CHECK(appservice_owns_user(*parsed.value, "example.org", "@_irc_bridge_bob:example.org"));
            }
        }

        WHEN("checked against an unrelated user id")
        {
            THEN("appservice_owns_user is false")
            {
                CHECK_FALSE(appservice_owns_user(*parsed.value, "example.org", "@carol:example.org"));
            }
        }
    }
}

SCENARIO("cross-registration sender_localpart is reserved from ordinary registration",
         "[appservice][registration][security][auth-3]")
{
    GIVEN("a registration whose sender_localpart is outside its own users namespace")
    {
        auto registrations = std::vector<AppserviceRegistration>{};
        auto const json = std::string{R"({
            "id": "bridge",
            "url": "http://127.0.0.1:5555",
            "as_token": "as-token",
            "hs_token": "hs-token",
            "sender_localpart": "bridgebot",
            "namespaces": {
                "users": [{"regex": "@_irc_.*", "exclusive": true}]
            }
        })"};
        auto parsed = parse_registration_json(json);
        REQUIRE(parsed.value.has_value());
        registrations.push_back(std::move(*parsed.value));

        WHEN("the registry is asked whether @bridgebot:example.org is a sender user id")
        {
            auto const registry = AppserviceRegistry{std::move(registrations)};

            THEN("it is recognised as a sender")
            {
                CHECK(registry.is_sender_user_id("@bridgebot:example.org", "example.org"));
            }

            THEN("an unrelated user is not")
            {
                CHECK_FALSE(registry.is_sender_user_id("@_irc_bob:example.org", "example.org"));
            }
        }
    }
}

SCENARIO("cross-registration uniqueness validation", "[appservice][registration]")
{
    GIVEN("two registrations sharing the same id")
    {
        auto registrations = std::vector<AppserviceRegistration>{};
        auto first = parse_registration_json(irc_bridge_registration_json());
        REQUIRE(first.value.has_value());
        registrations.push_back(std::move(*first.value));

        auto second_json = std::string{R"({
            "id": "irc-bridge",
            "url": "http://127.0.0.1:5555",
            "as_token": "different-token",
            "hs_token": "different-hs-token",
            "sender_localpart": "_other_bot",
            "namespaces": {}
        })"};
        auto second = parse_registration_json(second_json);
        REQUIRE(second.value.has_value());
        registrations.push_back(std::move(*second.value));

        WHEN("validate_registrations runs")
        {
            auto const findings = validate_registrations(registrations);

            THEN("a duplicate-id finding is reported")
            {
                REQUIRE_FALSE(findings.empty());
            }
        }
    }

    GIVEN("two registrations sharing the same as_token")
    {
        auto registrations = std::vector<AppserviceRegistration>{};
        auto first = parse_registration_json(irc_bridge_registration_json());
        REQUIRE(first.value.has_value());
        registrations.push_back(std::move(*first.value));

        auto second_json = std::string{R"({
            "id": "different-id",
            "url": "http://127.0.0.1:5555",
            "as_token": "irc-as-token-secret",
            "hs_token": "different-hs-token",
            "sender_localpart": "_other_bot",
            "namespaces": {}
        })"};
        auto second = parse_registration_json(second_json);
        REQUIRE(second.value.has_value());
        registrations.push_back(std::move(*second.value));

        WHEN("validate_registrations runs")
        {
            auto const findings = validate_registrations(registrations);

            THEN("a duplicate as_token finding is reported")
            {
                REQUIRE_FALSE(findings.empty());
            }
        }
    }

    GIVEN("two registrations with distinct ids and tokens")
    {
        auto registrations = std::vector<AppserviceRegistration>{};
        auto first = parse_registration_json(irc_bridge_registration_json());
        REQUIRE(first.value.has_value());
        registrations.push_back(std::move(*first.value));

        auto second_json = std::string{R"({
            "id": "different-id",
            "url": "http://127.0.0.1:5555",
            "as_token": "another-token-entirely",
            "hs_token": "different-hs-token",
            "sender_localpart": "_other_bot",
            "namespaces": {}
        })"};
        auto second = parse_registration_json(second_json);
        REQUIRE(second.value.has_value());
        registrations.push_back(std::move(*second.value));

        WHEN("validate_registrations runs")
        {
            auto const findings = validate_registrations(registrations);

            THEN("no findings are reported")
            {
                CHECK(findings.empty());
            }
        }
    }
}

SCENARIO("AppserviceRegistry lookup and exclusivity checks", "[appservice][registration]")
{
    GIVEN("a registry loaded from a single registration file")
    {
        auto const dir = std::filesystem::temp_directory_path();
        auto const path = dir / "merovingian-test-appservice-registry.json";
        {
            auto out = std::ofstream{path, std::ios::binary};
            out << irc_bridge_registration_json();
        }
        auto const loaded = load_registrations({path.string()});
        REQUIRE(loaded.findings.empty());
        REQUIRE(loaded.registry.size() == 1U);

        WHEN("find_by_as_token is called with the correct token")
        {
            auto const* found = loaded.registry.find_by_as_token("irc-as-token-secret");

            THEN("the registration is returned")
            {
                REQUIRE(found != nullptr);
                CHECK(found->id == "irc-bridge");
            }
        }

        WHEN("find_by_as_token is called with a wrong token")
        {
            auto const* found = loaded.registry.find_by_as_token("wrong-token");

            THEN("nothing is returned")
            {
                CHECK(found == nullptr);
            }
        }

        WHEN("find_by_as_token is called with an empty token")
        {
            auto const* found = loaded.registry.find_by_as_token("");

            THEN("nothing is returned")
            {
                CHECK(found == nullptr);
            }
        }

        WHEN("checking a user id inside the exclusive users namespace, excluding the owner")
        {
            THEN("it is reported as exclusively owned by another appservice")
            {
                CHECK(loaded.registry.user_namespace_exclusively_owned_by_other("@_irc_bridge_bob:example.org", ""));
                // The owning appservice itself is excluded from the check.
                CHECK_FALSE(loaded.registry.user_namespace_exclusively_owned_by_other("@_irc_bridge_bob:example.org",
                                                                                      "irc-bridge"));
            }
        }

        WHEN("checking an alias inside the NON-exclusive aliases namespace")
        {
            THEN("it is not reported as exclusively owned")
            {
                CHECK_FALSE(
                    loaded.registry.alias_namespace_exclusively_owned_by_other("#_irc_bridge_channel:example.org", ""));
            }
        }

        std::filesystem::remove(path);
    }

    GIVEN("a missing registration file among the configured paths")
    {
        WHEN("load_registrations runs")
        {
            auto const loaded = load_registrations({"/nonexistent/registration.json"});

            THEN("the failure is recorded and the registry stays empty, not a crash")
            {
                REQUIRE_FALSE(loaded.findings.empty());
                CHECK(loaded.registry.empty());
            }
        }
    }
}

SCENARIO("registration_interested_in_room_event matches per the spec's namespace/membership rules",
         "[appservice][registration]")
{
    GIVEN("the IRC bridge registration (exclusive users namespace, non-exclusive aliases namespace)")
    {
        auto const parsed = parse_registration_json(irc_bridge_registration_json());
        REQUIRE(parsed.value.has_value());
        auto const& registration = *parsed.value;
        auto const server_name = std::string_view{"example.org"};

        auto const interested = [&](EventInterestFacts const& facts) {
            return registration_interested_in_room_event(registration, server_name, facts);
        };

        WHEN("the room id itself is in the rooms namespace (empty here) but the sender is a namespaced user")
        {
            THEN("the appservice is interested via the sender")
            {
                CHECK(interested({.room_id = "!room:example.org", .sender = "@_irc_bridge_alice:example.org"}));
            }
        }

        WHEN("the room has a matching canonical alias")
        {
            auto const aliases = std::vector<std::string>{"#_irc_bridge_channel:example.org"};

            THEN("the appservice is interested via the alias namespace, regardless of sender/members")
            {
                CHECK(interested(
                    {.room_id = "!room:example.org", .room_aliases = aliases, .sender = "@carol:example.org"}));
            }
        }

        WHEN("only the second of several aliases matches the alias namespace")
        {
            auto const aliases = std::vector<std::string>{"#general:example.org", "#_irc_bridge_second:example.org"};

            THEN("the appservice is interested: every alias of the room counts, not the first")
            {
                CHECK(interested(
                    {.room_id = "!room:example.org", .room_aliases = aliases, .sender = "@carol:example.org"}));
            }
        }

        WHEN("a namespaced user is a joined member but neither the sender nor the alias match")
        {
            auto const members = std::vector<std::string>{"@carol:example.org", "@_irc_bridge_dave:example.org"};

            THEN("the appservice is interested via room_members")
            {
                CHECK(interested(
                    {.room_id = "!room:example.org", .sender = "@carol:example.org", .room_members = members}));
            }
        }

        WHEN("nothing about the event touches the appservice's namespaces at all")
        {
            auto const members = std::vector<std::string>{"@carol:example.org"};

            THEN("the appservice is not interested")
            {
                CHECK_FALSE(interested(
                    {.room_id = "!room:example.org", .sender = "@carol:example.org", .room_members = members}));
            }
        }

        WHEN("the sender is the appservice's own sender_localpart user")
        {
            THEN("the appservice is interested (sender_localpart is always implicitly covered)")
            {
                CHECK(interested({.room_id = "!room:example.org", .sender = "@_irc_bot:example.org"}));
            }
        }
    }
}

// R07. Spec: Application Service API v1.19, "Registration": the `users` namespace matches
// "a local user matching one of the namespaces is the target of the event, or is a joined member
// of the room where the event occurred"; and "Events affecting users on other homeservers are not
// sent to an application service, even if the user happens to match one of the users namespaces
// (unless, of course, the event affects a room that the application service is interested in for
// another reason ...)". An invite names its target in `state_key`; the invitee is not yet joined.
SCENARIO("an appservice is interested in a membership event whose state_key is one of its users",
         "[appservice][registration][r07]")
{
    GIVEN("the IRC bridge registration and a room none of whose members belong to the bridge")
    {
        auto const parsed = parse_registration_json(irc_bridge_registration_json());
        REQUIRE(parsed.value.has_value());
        auto const& registration = *parsed.value;
        auto const server_name = std::string_view{"example.org"};
        auto const members = std::vector<std::string>{"@carol:example.org"};
        auto const interested = [&](EventInterestFacts const& facts) {
            return registration_interested_in_room_event(registration, server_name, facts);
        };

        WHEN("a human invites a virtual user of the bridge (the invitee is not joined)")
        {
            THEN("the appservice is interested: the invitee is the target of the event")
            {
                CHECK(interested({.room_id = "!room:example.org",
                                  .sender = "@carol:example.org",
                                  .member_event_target = "@_irc_bridge_dave:example.org",
                                  .room_members = members}));
            }
        }

        WHEN("a human kicks or bans a virtual user, so the target is no longer joined either")
        {
            THEN("the appservice is still interested, through the state_key")
            {
                CHECK(interested({.room_id = "!room:example.org",
                                  .sender = "@carol:example.org",
                                  .member_event_target = "@_irc_bridge_erin:example.org"}));
            }
        }

        WHEN("the appservice's own sender_localpart user is the target of the membership event")
        {
            THEN("the appservice is interested")
            {
                CHECK(interested({.room_id = "!room:example.org",
                                  .sender = "@carol:example.org",
                                  .member_event_target = "@_irc_bot:example.org"}));
            }
        }

        WHEN("the target is an ordinary user outside every namespace")
        {
            THEN("the appservice is not interested")
            {
                CHECK_FALSE(interested({.room_id = "!room:example.org",
                                        .sender = "@carol:example.org",
                                        .member_event_target = "@frank:example.org",
                                        .room_members = members}));
            }
        }

        WHEN("the target matches a users namespace but lives on another homeserver")
        {
            THEN("the appservice is not interested: only local users count")
            {
                CHECK_FALSE(interested({.room_id = "!room:example.org",
                                        .sender = "@carol:example.org",
                                        .member_event_target = "@_irc_bridge_dave:remote.example",
                                        .room_members = members}));
            }
        }

        WHEN("the event is not a membership event (no member_event_target)")
        {
            THEN("a virtual user named nowhere in the event does not make the appservice interested")
            {
                CHECK_FALSE(interested({.room_id = "!room:example.org", .sender = "@carol:example.org"}));
            }
        }
    }
}

SCENARIO("a namespace regex claims whole identifiers, not substrings", "[appservice][registration][security]")
{
    GIVEN("an exclusive namespace using the spec's reserved-prefix example pattern")
    {
        // Matrix v1.19 Application Service API, "Registration": `regex` is
        // "A POSIX regular expression defining which values this namespace
        // includes" — a namespace is a claim over an identifier, so the
        // pattern must match the whole value. An unanchored search would let
        // `@_irc_.*` also claim any user id that merely CONTAINS it, letting
        // one appservice's exclusive namespace swallow unrelated users.
        auto const pattern = std::string_view{"@_irc_.*"};

        WHEN("the value is an identifier the pattern genuinely covers")
        {
            THEN("it matches")
            {
                REQUIRE(merovingian::appservice::namespace_matches(pattern, "@_irc_bob:example.org"));
            }
        }

        WHEN("the pattern appears only as a substring of an unrelated identifier")
        {
            THEN("it does not match")
            {
                REQUIRE_FALSE(merovingian::appservice::namespace_matches(pattern, "@evil@_irc_bob:example.org"));
            }
        }

        WHEN("the value shares only a prefix of the pattern")
        {
            THEN("it does not match")
            {
                REQUIRE_FALSE(merovingian::appservice::namespace_matches(pattern, "@_ir:example.org"));
            }
        }
    }
}

SCENARIO("parsing the spec's own YAML registration example", "[appservice][registration][yaml]")
{
    GIVEN("the registration document printed in the Application Service API spec")
    {
        // Matrix v1.19 Application Service API, "Registration" — reproduced
        // verbatim, including the trailing comment and the empty `rooms` list.
        // Real bridges ship exactly this shape (`registration.yaml`), so a
        // homeserver that cannot read block-style YAML cannot load any of them.
        auto const document =
            std::string{"id: \"IRC Bridge\"\n"
                        "url: \"http://127.0.0.1:1234\"\n"
                        "as_token: \"30c05ae90a248a4188e620216fa72e349803310ec83e2a77b34fe90be6081f46\"\n"
                        "hs_token: \"312df522183efd404ec1cd22d2ffa4bbc76a8c1ccf541dd692eef281356bb74e\"\n"
                        "sender_localpart: \"_irc_bot\" # Will result in @_irc_bot:example.org\n"
                        "namespaces:\n"
                        "  users:\n"
                        "    - exclusive: true\n"
                        "      regex: \"@_irc_bridge_.*\"\n"
                        "  aliases:\n"
                        "    - exclusive: false\n"
                        "      regex: \"#_irc_bridge_.*\"\n"
                        "  rooms: []\n"};

        WHEN("it is parsed")
        {
            auto const result = merovingian::appservice::parse_registration_yaml(document);
            INFO("parser error: " << result.error.message());

            THEN("it is accepted and every field is carried through")
            {
                REQUIRE(result.value.has_value());
                REQUIRE(result.value->id == "IRC Bridge");
                REQUIRE(result.value->url.has_value());
                REQUIRE(*result.value->url == "http://127.0.0.1:1234");
                REQUIRE(result.value->sender_localpart == "_irc_bot");
            }

            THEN("the namespaces keep their exclusivity flags and patterns")
            {
                REQUIRE(result.value.has_value());
                REQUIRE(result.value->namespaces.users.size() == 1U);
                REQUIRE(result.value->namespaces.users.front().exclusive);
                REQUIRE(result.value->namespaces.users.front().regex() == "@_irc_bridge_.*");
                REQUIRE(result.value->namespaces.aliases.size() == 1U);
                REQUIRE_FALSE(result.value->namespaces.aliases.front().exclusive);
                REQUIRE(result.value->namespaces.rooms.empty());
            }

            THEN("the parsed exclusive user namespace claims only its own identifiers")
            {
                REQUIRE(result.value.has_value());
                REQUIRE(merovingian::appservice::any_exclusive_namespace_matches(result.value->namespaces.users,
                                                                                 "@_irc_bridge_alice:example.org"));
                REQUIRE_FALSE(merovingian::appservice::any_exclusive_namespace_matches(result.value->namespaces.users,
                                                                                       "@alice:example.org"));
            }
        }
    }
}

SCENARIO("an inline namespace value is accepted only when it is an empty list", "[appservice][registration][yaml]")
{
    GIVEN("a registration whose namespaces use inline flow syntax")
    {
        auto const document_for = [](std::string_view rooms_value) {
            return std::string{"id: \"bridge\"\n"
                               "url: \"http://127.0.0.1:1234\"\n"
                               "as_token: \"a\"\n"
                               "hs_token: \"b\"\n"
                               "sender_localpart: \"_bot\"\n"
                               "namespaces:\n"
                               "  users:\n"
                               "    - exclusive: true\n"
                               "      regex: \"@_bridge_.*\"\n"
                               "  rooms: "} +
                   std::string{rooms_value} + "\n";
        };

        WHEN("the value is the empty flow sequence the spec example uses")
        {
            auto const result = merovingian::appservice::parse_registration_yaml(document_for("[]"));

            THEN("it parses and the namespace is empty")
            {
                REQUIRE(result.value.has_value());
                REQUIRE(result.value->namespaces.rooms.empty());
                REQUIRE(result.value->namespaces.users.size() == 1U);
            }
        }

        WHEN("the value is a non-empty flow sequence this bounded subset cannot parse")
        {
            auto const result = merovingian::appservice::parse_registration_yaml(
                document_for("[{exclusive: true, regex: \"!x:example.org\"}]"));

            THEN("it is rejected rather than silently dropping the entries")
            {
                REQUIRE_FALSE(result.value.has_value());
            }
        }
    }
}

namespace
{
[[nodiscard]] auto registration_doc(std::string_view id, std::string_view localpart, std::string_view token,
                                    std::string_view user_regex, bool exclusive) -> std::string
{
    return std::string{"id: \""} + std::string{id} +
           "\"\n"
           "url: \"http://127.0.0.1:1234\"\n"
           "as_token: \"" +
           std::string{token} +
           "\"\n"
           "hs_token: \"hs-" +
           std::string{token} +
           "\"\n"
           "sender_localpart: \"" +
           std::string{localpart} +
           "\"\n"
           "namespaces:\n"
           "  users:\n"
           "    - exclusive: " +
           (exclusive ? "true" : "false") +
           "\n"
           "      regex: \"" +
           std::string{user_regex} +
           "\"\n"
           "  rooms: []\n";
}

[[nodiscard]] auto parsed(std::string const& document) -> merovingian::appservice::AppserviceRegistration
{
    auto result = merovingian::appservice::parse_registration_yaml(document);
    REQUIRE(result.value.has_value());
    return std::move(*result.value);
}
} // namespace

SCENARIO("two appservices cannot both claim the same exclusive namespace", "[appservice][registration][security]")
{
    GIVEN("two registrations whose user namespaces use the identical pattern")
    {
        // Matrix v1.19 Application Service API, "Registration": an exclusive
        // namespace means no other user may occupy it. Two appservices both
        // claiming `@_bridge_.*` exclusively is unsatisfiable — whichever the
        // registry consults first silently wins, and the other's exclusivity
        // guarantee is quietly not honoured.
        WHEN("both declare it exclusive")
        {
            auto registrations = std::vector<merovingian::appservice::AppserviceRegistration>{};
            registrations.push_back(parsed(registration_doc("irc", "_irc_bot", "tok-a", "@_bridge_.*", true)));
            registrations.push_back(parsed(registration_doc("xmpp", "_xmpp_bot", "tok-b", "@_bridge_.*", true)));

            auto const findings = merovingian::appservice::validate_registrations(registrations);

            THEN("the conflict is reported")
            {
                REQUIRE_FALSE(findings.empty());
            }
        }

        WHEN("only one declares it exclusive")
        {
            auto registrations = std::vector<merovingian::appservice::AppserviceRegistration>{};
            registrations.push_back(parsed(registration_doc("irc", "_irc_bot", "tok-a", "@_bridge_.*", true)));
            registrations.push_back(parsed(registration_doc("xmpp", "_xmpp_bot", "tok-b", "@_bridge_.*", false)));

            THEN("it is still a conflict, because exclusivity excludes the other claim too")
            {
                auto const findings = merovingian::appservice::validate_registrations(registrations);
                REQUIRE_FALSE(findings.empty());
            }
        }
    }

    GIVEN("two registrations with disjoint namespaces")
    {
        auto registrations = std::vector<merovingian::appservice::AppserviceRegistration>{};
        registrations.push_back(parsed(registration_doc("irc", "_irc_bot", "tok-a", "@_irc_.*", true)));
        registrations.push_back(parsed(registration_doc("xmpp", "_xmpp_bot", "tok-b", "@_xmpp_.*", true)));

        WHEN("they are validated")
        {
            auto const findings = merovingian::appservice::validate_registrations(registrations);

            THEN("no conflict is reported")
            {
                REQUIRE(findings.empty());
            }
        }
    }
}

SCENARIO("an appservice's sender user may not fall inside another's exclusive namespace",
         "[appservice][registration][security]")
{
    // Matrix v1.19 Application Service API, "Registration": an exclusive
    // namespace means no other user in it may be created by anyone else. The
    // sender_localpart user is a real local user the appservice acts as, so it
    // is subject to another appservice's exclusive claim exactly like any other
    // user id — and unlike an ordinary user it is created at startup, so the
    // collision is guaranteed rather than incidental.
    auto const server_name = std::string_view{"example.org"};

    GIVEN("an appservice whose sender user is claimed by another's exclusive namespace")
    {
        auto registrations = std::vector<merovingian::appservice::AppserviceRegistration>{};
        registrations.push_back(parsed(registration_doc("irc", "_irc_bot", "tok-a", "@_shared_.*", true)));
        registrations.push_back(parsed(registration_doc("xmpp", "_shared_bot", "tok-b", "@_xmpp_.*", true)));

        WHEN("the set is validated")
        {
            auto const findings = merovingian::appservice::validate_registrations(registrations, server_name);

            THEN("the encroachment is reported")
            {
                REQUIRE_FALSE(findings.empty());
            }
        }
    }

    GIVEN("appservices whose sender users fall outside every other exclusive namespace")
    {
        auto registrations = std::vector<merovingian::appservice::AppserviceRegistration>{};
        registrations.push_back(parsed(registration_doc("irc", "_irc_bot", "tok-a", "@_irc_.*", true)));
        registrations.push_back(parsed(registration_doc("xmpp", "_xmpp_bot", "tok-b", "@_xmpp_.*", true)));

        WHEN("the set is validated")
        {
            auto const findings = merovingian::appservice::validate_registrations(registrations, server_name);

            THEN("nothing is reported")
            {
                // Each sender sits inside its OWN exclusive namespace
                // (@_irc_bot matches @_irc_.*), which is correct and must not
                // be reported — an appservice always owns its own sender.
                REQUIRE(findings.empty());
            }
        }
    }

    GIVEN("a sender claimed only by another appservice's NON-exclusive namespace")
    {
        auto registrations = std::vector<merovingian::appservice::AppserviceRegistration>{};
        registrations.push_back(parsed(registration_doc("irc", "_irc_bot", "tok-a", "@_shared_.*", false)));
        registrations.push_back(parsed(registration_doc("xmpp", "_shared_bot", "tok-b", "@_xmpp_.*", true)));

        WHEN("the set is validated")
        {
            auto const findings = merovingian::appservice::validate_registrations(registrations, server_name);

            THEN("nothing is reported — a non-exclusive claim excludes nobody")
            {
                REQUIRE(findings.empty());
            }
        }
    }
}

namespace
{

[[nodiscard]] auto runtime_enabled_config(std::string server_name = "example.org") -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = std::move(server_name);
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

} // namespace

// AUTH-3: the sender_localpart user must be created at runtime startup,
// before ordinary client registration can race for the same localpart.
SCENARIO("appservice sender_localpart users are created at runtime startup",
         "[appservice][registration][security][auth-3]")
{
    GIVEN("a registration file whose sender_localpart is outside its users namespace")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-auth3-sender.json";
        {
            auto out = std::ofstream{path, std::ios::binary};
            out << R"({
                "id": "auth3-bridge",
                "url": null,
                "as_token": "as-token-auth3",
                "hs_token": "hs-token-auth3",
                "sender_localpart": "_auth3_bot",
                "namespaces": {
                    "users": [{"exclusive": true, "regex": "@_auth3_.*"}],
                    "aliases": [],
                    "rooms": []
                },
                "protocols": []
            })";
        }

        auto config = runtime_enabled_config();
        config.appservice().registration_files = {path.string()};

        WHEN("the runtime starts")
        {
            auto started = merovingian::homeserver::start_runtime(config);
            REQUIRE(started.started);
            auto const& runtime = started.runtime;

            THEN("the sender_localpart user exists in the local user store")
            {
                auto const expected_sender = std::string{"@_auth3_bot:example.org"};
                auto const found = std::ranges::any_of(
                    runtime.database.users, [&expected_sender](merovingian::homeserver::LocalUser const& user) {
                        return user.user_id == expected_sender;
                    });
                REQUIRE(found);
            }
        }
    }
}

// The interest check runs per event, per registration and (for the users namespace) per room
// member, while the runtime lock is held, so a namespace pattern is compiled once, when the
// registration is loaded, never per match (security audit run-1,
// sp02.appservice-regex-compile-under-mutex). Matching keeps its spec semantics: a POSIX regex
// over the whole identifier (Application Service API "Registration").
SCENARIO("a namespace compiles its pattern once, when it is built", "[appservice][registration][security][sp02]")
{
    GIVEN("a namespace built from a valid POSIX pattern")
    {
        auto const ns = merovingian::appservice::Namespace{true, "@_irc_.*"};

        THEN("its compiled form exists and matches whole identifiers only")
        {
            REQUIRE(ns.compiled() != nullptr);
            auto const namespaces = std::vector<merovingian::appservice::Namespace>{ns};
            REQUIRE(merovingian::appservice::any_namespace_matches(namespaces, "@_irc_bob:example.org"));
            REQUIRE_FALSE(merovingian::appservice::any_namespace_matches(namespaces, "@evil@_irc_bob:example.org"));
            REQUIRE(merovingian::appservice::any_exclusive_namespace_matches(namespaces, "@_irc_bob:example.org"));
        }

        WHEN("the namespace is copied, as registrations are into the registry")
        {
            auto const copy = ns;

            THEN("the copy shares the one compiled pattern instead of compiling again")
            {
                REQUIRE(copy.compiled() == ns.compiled());
            }
        }
    }

    GIVEN("a namespace built from a pattern that does not compile")
    {
        auto const ns = merovingian::appservice::Namespace{true, "(unclosed"};

        THEN("it has no compiled form and matches nothing")
        {
            REQUIRE(ns.compiled() == nullptr);
            auto const namespaces = std::vector<merovingian::appservice::Namespace>{ns};
            REQUIRE_FALSE(merovingian::appservice::any_namespace_matches(namespaces, "(unclosed"));
            REQUIRE_FALSE(merovingian::appservice::any_namespace_matches(namespaces, "@anyone:example.org"));
        }
    }

    GIVEN("a registration parsed from its YAML file")
    {
        auto const parsed = merovingian::appservice::parse_registration_yaml(
            "id: \"IRC Bridge\"\n"
            "url: \"http://127.0.0.1:1234\"\n"
            "as_token: \"30c05ae90a248a4188e620216fa72e349803310ec83e2a77b34fe90be6081f46\"\n"
            "hs_token: \"312df522183efd404ec1cd22d2ffa4bbc76a8c1ccf541dd692eef281356bb74e\"\n"
            "sender_localpart: \"_irc_bot\"\n"
            "namespaces:\n"
            "  users:\n"
            "    - exclusive: true\n"
            "      regex: \"@_irc_bridge_.*\"\n"
            "  aliases: []\n"
            "  rooms: []\n");

        THEN("every namespace it loads is already compiled")
        {
            REQUIRE(parsed.value.has_value());
            REQUIRE_FALSE(parsed.value->namespaces.users.empty());
            REQUIRE(parsed.value->namespaces.users.front().compiled() != nullptr);
        }
    }
}

// Complement run 10 (H1): Complement copies each test's application service
// registration into the container as this exact YAML (internal/docker/builder.go,
// generateASRegistrationYaml), and the image now configures it. A registration
// the parser refused would leave Complement's appservice tests unable to start.
SCENARIO("A registration in the form Complement writes is loaded", "[appservice][registration][complement]")
{
    GIVEN("a registration file written exactly as Complement writes one")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-test-complement-appservice.yaml";
        {
            auto out = std::ofstream{path, std::ios::binary};
            out << "id: my_as_id\n"
                   "hs_token: hs_token_value\n"
                   "as_token: as_token_value\n"
                   "url: 'http://host.docker.internal:9000'\n"
                   "sender_localpart: the-bridge-user\n"
                   "rate_limited: false\n"
                   "de.sorunome.msc2409.push_ephemeral: false\n"
                   "push_ephemeral: false\n"
                   "org.matrix.msc3202: false\n"
                   "namespaces:\n"
                   "  users:\n"
                   "    - exclusive: false\n"
                   "      regex: .*\n"
                   "  rooms: []\n"
                   "  aliases: []\n";
        }

        WHEN("it is loaded")
        {
            auto const loaded = load_registrations({path.string()}, "hs1");
            std::filesystem::remove(path);

            THEN("it is accepted with its tokens, sender, URL and user namespace")
            {
                for (auto const& finding : loaded.findings)
                {
                    UNSCOPED_INFO("finding: " << finding.message);
                }
                REQUIRE(loaded.findings.empty());
                REQUIRE(loaded.registry.size() == 1U);
                auto const* found = loaded.registry.find_by_as_token("as_token_value");
                REQUIRE(found != nullptr);
                CHECK(found->id == "my_as_id");
                CHECK(found->sender_localpart == "the-bridge-user");
                CHECK(found->url == std::optional<std::string>{"http://host.docker.internal:9000"});
                REQUIRE(found->namespaces.users.size() == 1U);
                CHECK(found->namespaces.users.front().compiled() != nullptr);
            }
        }
    }
}

// ADR-0273 (narrows ADR-0035): only vendor-namespaced keys and MSC2409's unstable
// push_ephemeral are ignored. Any other unknown key, a typo of a real one included,
// still refuses the file.
SCENARIO("A registration with an unknown plain key is still refused", "[appservice][registration][complement]")
{
    GIVEN("an otherwise valid registration with a mistyped top-level key")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-test-unknown-key-appservice.yaml";
        {
            auto out = std::ofstream{path, std::ios::binary};
            out << "id: typo_bridge\n"
                   "hs_token: hs_token_value\n"
                   "as_token: as_token_value\n"
                   "as_tokn: another_value\n"
                   "url: null\n"
                   "sender_localpart: the-bridge-user\n"
                   "namespaces:\n"
                   "  users: []\n"
                   "  rooms: []\n"
                   "  aliases: []\n";
        }

        WHEN("it is loaded")
        {
            auto const loaded = load_registrations({path.string()}, "hs1");
            std::filesystem::remove(path);

            THEN("it is refused with a finding naming the key")
            {
                REQUIRE(loaded.registry.size() == 0U);
                REQUIRE_FALSE(loaded.findings.empty());
                CHECK(std::ranges::any_of(loaded.findings, [](auto const& finding) {
                    return finding.message.find("as_tokn") != std::string::npos;
                }));
            }
        }
    }
}
