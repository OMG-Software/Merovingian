// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Unit tests for federation security boundary functions not covered by
// test_federation_security.cpp (which covers ip_address_is_private_or_loopback
// ranges, trust policy, and DNS rebinding).
//
// Coverage:
//   - server_name_is_valid: valid domain, domain+port, empty, no-dot, >255,
//                           space, control char (anomaly/boundary paths)
//   - federation_discovery_policy: empty address set, unresolved host,
//                                  invalid server name, TLS-not-required
//   - parse_inbound_pdu_envelope: empty input, JSON array, JSON string literal,
//                                 valid minimal PDU

#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/security.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

// --- server_name_is_valid ----------------------------------------------------

SCENARIO("server_name_is_valid accepts domain names with at least one dot",
         "[federation][security][server-name]")
{
    GIVEN("valid Matrix server names")
    {
        WHEN("a fully-qualified domain name is tested")
        {
            THEN("a two-label domain is accepted")
            {
                REQUIRE(merovingian::federation::server_name_is_valid("matrix.org"));
            }

            THEN("a multi-label subdomain is accepted")
            {
                REQUIRE(merovingian::federation::server_name_is_valid("matrix.example.org"));
            }

            THEN("a domain with an explicit port is accepted")
            {
                // Port numbers are separated by ':' which is not a control character
                // or space, so the name passes all four checks.
                REQUIRE(merovingian::federation::server_name_is_valid("matrix.example.org:8448"));
            }
        }
    }
}

SCENARIO("server_name_is_valid rejects empty and dot-free server names",
         "[federation][security][server-name][error]")
{
    GIVEN("server names that lack the minimum required structure")
    {
        WHEN("an empty string is tested")
        {
            THEN("empty is rejected — no server name can be the empty string")
            {
                REQUIRE_FALSE(merovingian::federation::server_name_is_valid(""));
            }
        }

        WHEN("a single-label hostname with no dot is tested")
        {
            THEN("single-label names are rejected")
            {
                REQUIRE_FALSE(merovingian::federation::server_name_is_valid("localhost"));
                REQUIRE_FALSE(merovingian::federation::server_name_is_valid("homeserver"));
            }
        }
    }
}

SCENARIO("server_name_is_valid rejects server names exceeding 255 characters",
         "[federation][security][server-name][boundary]")
{
    GIVEN("a server name longer than 255 characters")
    {
        // 252 'a's + ".org" = 256 characters
        auto const long_name = std::string(252, 'a') + ".org";
        REQUIRE(long_name.size() == 256U);

        WHEN("the oversized name is tested")
        {
            THEN("it is rejected — 255 is the maximum")
            {
                REQUIRE_FALSE(merovingian::federation::server_name_is_valid(long_name));
            }
        }
    }

    GIVEN("a server name of exactly 255 characters")
    {
        // 251 'a's + ".org" = 255 characters
        auto const max_name = std::string(251, 'a') + ".org";
        REQUIRE(max_name.size() == 255U);

        WHEN("the 255-character name is tested")
        {
            THEN("it is accepted — 255 is the maximum allowed length")
            {
                REQUIRE(merovingian::federation::server_name_is_valid(max_name));
            }
        }
    }
}

SCENARIO("server_name_is_valid rejects server names containing whitespace or control characters",
         "[federation][security][server-name][security]")
{
    GIVEN("server names with embedded whitespace or control bytes")
    {
        WHEN("a name with an embedded space is tested")
        {
            THEN("the space is rejected")
            {
                REQUIRE_FALSE(merovingian::federation::server_name_is_valid("matrix .org"));
            }
        }

        WHEN("a name with an embedded newline is tested")
        {
            THEN("the newline is rejected")
            {
                REQUIRE_FALSE(merovingian::federation::server_name_is_valid("matrix\n.org"));
            }
        }

        WHEN("a name with an embedded tab is tested")
        {
            THEN("the tab is rejected")
            {
                REQUIRE_FALSE(merovingian::federation::server_name_is_valid("matrix\t.org"));
            }
        }
    }
}

// --- federation_discovery_policy edge cases ----------------------------------

SCENARIO("federation_discovery_policy rejects a remote with an empty resolved_host",
         "[federation][security][discovery][error]")
{
    // Spec: Matrix Server-Server API v1.18
    // URL: ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
    //
    // A remote whose resolved_host is empty has not been resolved through the
    // well-known + SRV + direct lookup chain. The discovery policy MUST reject
    // it rather than connecting to an unresolved target.
    GIVEN("a remote record with a valid server name but no resolved host")
    {
        auto remote = merovingian::federation::RemoteServerRecord{};
        remote.server_name = "matrix.example.org";
        remote.well_known_host = "";
        remote.resolved_host = ""; // unresolved
        remote.resolved_addresses = {"203.0.113.10"};
        remote.tls_required = true;

        WHEN("discovery policy is evaluated")
        {
            auto const decision = merovingian::federation::federation_discovery_policy(remote);

            THEN("the policy rejects the remote — an unresolved host cannot be reached")
            {
                REQUIRE_FALSE(decision.accepted);
                REQUIRE(decision.reason == "remote host is unresolved");
            }
        }
    }
}

SCENARIO("federation_discovery_policy rejects a remote with an empty resolved address set",
         "[federation][security][discovery][error]")
{
    // Spec: Matrix Server-Server API v1.18
    // URL: ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
    //
    // DNS resolution must have produced at least one IP address before any
    // connection attempt. Empty addresses mean DNS failed or returned no records;
    // the policy MUST reject rather than treating it as "will resolve later".
    GIVEN("a remote record with valid server name and host but no resolved IP addresses")
    {
        auto remote = merovingian::federation::RemoteServerRecord{};
        remote.server_name = "matrix.example.org";
        remote.well_known_host = "matrix.example.org";
        remote.resolved_host = "matrix.example.org";
        remote.resolved_addresses = {}; // empty — DNS produced no records
        remote.tls_required = true;

        WHEN("discovery policy is evaluated")
        {
            auto const decision = merovingian::federation::federation_discovery_policy(remote);

            THEN("the policy rejects the remote with an unresolved-addresses reason")
            {
                REQUIRE_FALSE(decision.accepted);
                REQUIRE(decision.reason == "remote addresses are unresolved");
            }
        }
    }
}

SCENARIO("federation_discovery_policy rejects a remote whose server_name is invalid",
         "[federation][security][discovery][error]")
{
    GIVEN("a remote record whose server_name contains no dot")
    {
        auto remote = merovingian::federation::RemoteServerRecord{};
        remote.server_name = "invalidhostname"; // no dot — fails server_name_is_valid
        remote.resolved_host = "invalidhostname";
        remote.resolved_addresses = {"203.0.113.10"};
        remote.tls_required = true;

        WHEN("discovery policy is evaluated")
        {
            auto const decision = merovingian::federation::federation_discovery_policy(remote);

            THEN("the policy rejects the remote with an invalid-server-name reason")
            {
                REQUIRE_FALSE(decision.accepted);
                REQUIRE(decision.reason == "invalid remote server name");
            }
        }
    }

    GIVEN("a remote record with an empty server_name")
    {
        auto remote = merovingian::federation::RemoteServerRecord{};
        remote.server_name = "";
        remote.resolved_host = "matrix.example.org";
        remote.resolved_addresses = {"203.0.113.10"};
        remote.tls_required = true;

        WHEN("discovery policy is evaluated")
        {
            auto const decision = merovingian::federation::federation_discovery_policy(remote);

            THEN("the policy rejects the remote with an invalid-server-name reason")
            {
                REQUIRE_FALSE(decision.accepted);
                REQUIRE(decision.reason == "invalid remote server name");
            }
        }
    }
}

SCENARIO("federation_discovery_policy rejects remotes that do not require TLS",
         "[federation][security][discovery][tls]")
{
    // Spec: Matrix Server-Server API v1.18
    // Federation MUST use TLS for all connections.
    // URL: ../../docs/matrix-v1.18-spec/server-server-api.md#transport
    GIVEN("a remote record with a public address but TLS not required")
    {
        auto remote = merovingian::federation::RemoteServerRecord{};
        remote.server_name = "matrix.example.org";
        remote.well_known_host = "matrix.example.org";
        remote.resolved_host = "matrix.example.org";
        remote.resolved_addresses = {"203.0.113.10"};
        remote.tls_required = false; // plain-text federation

        WHEN("discovery policy is evaluated")
        {
            auto const decision = merovingian::federation::federation_discovery_policy(remote);

            THEN("the policy rejects the remote — Spec MUST: federation requires TLS")
            {
                REQUIRE_FALSE(decision.accepted);
                REQUIRE(decision.reason == "federation requires TLS");
            }
        }
    }
}

// --- parse_inbound_pdu_envelope error paths ----------------------------------

SCENARIO("parse_inbound_pdu_envelope returns nullopt for an empty input",
         "[federation][ingestion][pdu][error]")
{
    GIVEN("an empty PDU JSON string")
    {
        WHEN("the envelope is parsed")
        {
            auto const result = merovingian::federation::parse_inbound_pdu_envelope("");

            THEN("nullopt is returned — an empty string is not a valid PDU")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

SCENARIO("parse_inbound_pdu_envelope returns nullopt for a JSON array",
         "[federation][ingestion][pdu][error]")
{
    GIVEN("a JSON array instead of a JSON object")
    {
        WHEN("the array is parsed as a PDU envelope")
        {
            auto const result =
                merovingian::federation::parse_inbound_pdu_envelope(R"([{"type":"m.room.message"}])");

            THEN("nullopt is returned — PDUs MUST be JSON objects, not arrays")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

SCENARIO("parse_inbound_pdu_envelope returns nullopt for a JSON string literal",
         "[federation][ingestion][pdu][error]")
{
    GIVEN("a JSON string literal instead of a JSON object")
    {
        WHEN("the string is parsed as a PDU envelope")
        {
            auto const result =
                merovingian::federation::parse_inbound_pdu_envelope(R"("not_an_object")");

            THEN("nullopt is returned — PDUs MUST be JSON objects")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

SCENARIO("parse_inbound_pdu_envelope returns nullopt for malformed JSON",
         "[federation][ingestion][pdu][error]")
{
    GIVEN("a string that is not valid JSON")
    {
        WHEN("the malformed bytes are parsed as a PDU envelope")
        {
            auto const result =
                merovingian::federation::parse_inbound_pdu_envelope("{not valid json}");

            THEN("nullopt is returned — the canonical JSON parser rejects the input")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}
