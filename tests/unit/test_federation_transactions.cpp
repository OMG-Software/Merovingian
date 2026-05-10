// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/federation/transactions.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Federation route scaffold covers transactions, joins, leaves, invites, backfill, and EDUs", "[federation][transactions][routes]")
{
    GIVEN("federation methods and targets")
    {
        WHEN("routes are matched")
        {
            auto const transaction = merovingian::federation::match_federation_route("PUT", "/_matrix/federation/v1/send/txn123");
            auto const send_join = merovingian::federation::match_federation_route("PUT", "/_matrix/federation/v2/send_join/!room:event/$event");
            auto const send_leave = merovingian::federation::match_federation_route("PUT", "/_matrix/federation/v2/send_leave/!room:event/$event");
            auto const invite = merovingian::federation::match_federation_route("PUT", "/_matrix/federation/v2/invite/!room:event/$event");
            auto const backfill = merovingian::federation::match_federation_route("GET", "/_matrix/federation/v1/backfill/!room:event");
            auto const edu = merovingian::federation::match_federation_route("PUT", "/_matrix/federation/v1/send_edu/m.typing/txn123");

            THEN("all Milestone 12 federation endpoints are represented")
            {
                REQUIRE(transaction.matched);
                REQUIRE(send_join.matched);
                REQUIRE(send_leave.matched);
                REQUIRE(invite.matched);
                REQUIRE(backfill.matched);
                REQUIRE(edu.matched);
                REQUIRE(transaction.route.endpoint == merovingian::federation::FederationEndpoint::transaction);
                REQUIRE(send_join.route.endpoint == merovingian::federation::FederationEndpoint::send_join);
                REQUIRE(edu.route.endpoint == merovingian::federation::FederationEndpoint::edu);
                REQUIRE(transaction.route.requires_request_signature);
                REQUIRE(send_join.route.requires_event_signatures);
                REQUIRE_FALSE(edu.route.requires_event_signatures);
            }
        }
    }
}

SCENARIO("Federation transaction validation accepts bounded transactions and rejects malformed ones", "[federation][transactions]")
{
    GIVEN("valid, oversized, empty, and anonymous transactions")
    {
        auto valid = merovingian::federation::FederationTransaction{};
        valid.origin = "matrix.example.org";
        valid.transaction_id = "txn123";
        valid.pdus = {"$event"};
        valid.byte_size = 1024U;

        auto oversized = valid;
        oversized.byte_size = 2048U;
        auto empty = valid;
        empty.pdus.clear();
        empty.edus.clear();
        auto anonymous = valid;
        anonymous.origin.clear();

        WHEN("transactions are validated")
        {
            auto const accepted = merovingian::federation::validate_federation_transaction(valid, 1024U);
            auto const rejected_oversized = merovingian::federation::validate_federation_transaction(oversized, 1024U);
            auto const rejected_empty = merovingian::federation::validate_federation_transaction(empty, 1024U);
            auto const rejected_anonymous = merovingian::federation::validate_federation_transaction(anonymous, 1024U);

            THEN("only bounded, identified transactions with content are accepted")
            {
                REQUIRE(accepted.accepted);
                REQUIRE_FALSE(rejected_oversized.accepted);
                REQUIRE(rejected_oversized.reason == "transaction exceeds configured byte limit");
                REQUIRE_FALSE(rejected_empty.accepted);
                REQUIRE(rejected_empty.reason == "transaction must contain PDUs or EDUs");
                REQUIRE_FALSE(rejected_anonymous.accepted);
                REQUIRE(rejected_anonymous.reason == "invalid transaction origin");
            }
        }
    }
}

SCENARIO("Federation EDU scaffold accepts only ephemeral EDUs with valid origins", "[federation][transactions][edu]")
{
    GIVEN("valid and invalid EDUs")
    {
        auto valid = merovingian::federation::FederationEdu{"m.typing", "matrix.example.org", true};
        auto persistent = valid;
        persistent.ephemeral = false;
        auto anonymous = valid;
        anonymous.origin.clear();

        WHEN("EDU policy is evaluated")
        {
            auto const accepted = merovingian::federation::edu_is_allowed(valid);
            auto const rejected_persistent = merovingian::federation::edu_is_allowed(persistent);
            auto const rejected_anonymous = merovingian::federation::edu_is_allowed(anonymous);

            THEN("only valid ephemeral EDUs are accepted")
            {
                REQUIRE(accepted.accepted);
                REQUIRE_FALSE(rejected_persistent.accepted);
                REQUIRE(rejected_persistent.reason == "EDUs must remain ephemeral");
                REQUIRE_FALSE(rejected_anonymous.accepted);
                REQUIRE(rejected_anonymous.reason == "invalid EDU origin");
            }
        }
    }
}

SCENARIO("Federation routes expose audit event names", "[federation][transactions][audit]")
{
    GIVEN("a send_join route")
    {
        auto const route = merovingian::federation::match_federation_route("PUT", "/_matrix/federation/v2/send_join/!room:event/$event");

        WHEN("an audit event name is generated")
        {
            auto const event = merovingian::federation::federation_route_audit_event(route.route, "matrix.example.org");

            THEN("the endpoint and origin are represented")
            {
                REQUIRE(event.find("federation.send_join") != std::string::npos);
                REQUIRE(event.find("origin=matrix.example.org") != std::string::npos);
            }
        }
    }
}
