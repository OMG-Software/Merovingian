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

#include "merovingian/appservice/registration.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>

using merovingian::appservice::any_exclusive_namespace_matches;
using merovingian::appservice::any_namespace_matches;
using merovingian::appservice::appservice_owns_user;
using merovingian::appservice::AppserviceRegistration;
using merovingian::appservice::AppserviceRegistry;
using merovingian::appservice::load_registration_file;
using merovingian::appservice::load_registrations;
using merovingian::appservice::Namespace;
using merovingian::appservice::namespace_matches;
using merovingian::appservice::parse_registration_json;
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
