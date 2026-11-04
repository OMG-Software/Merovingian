// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Third-party invite bodies are chosen by whoever sends them (ADR-0484): what the parsers refuse or drop, and where the
// two endpoints are answered.

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/federation/third_party_invite.hpp"
#include "merovingian/homeserver/federation_request_routing.hpp"
#include "merovingian/homeserver/local_http_router.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace
{

namespace fed = merovingian::federation;

auto const signed_ok =
    std::string{R"({"mxid":"@bob:example.org","signatures":{"is.example":{"ed25519:0":"c2ln"}},"token":"tok"})"};

[[nodiscard]] auto exchange_body(std::string const& signed_json, std::string const& extra_content = {}) -> std::string
{
    return R"({"content":{"membership":"invite",)" + extra_content +
           R"("third_party_invite":{"display_name":"b","signed":)" + signed_json +
           R"(}},"room_id":"!r:example.org","sender":"@alice:example.org","state_key":"@bob:example.org",)"
           R"("type":"m.room.member"})";
}

[[nodiscard]] auto invite_entry(std::string const& mxid, std::string const& signed_json) -> std::string
{
    return R"({"address":"bob@example.net","medium":"email","mxid":")" + mxid +
           R"(","room_id":"!r:example.org","sender":"@alice:example.org","signed":)" + signed_json + "}";
}

[[nodiscard]] auto bind_body(std::string const& invites) -> std::string
{
    return R"({"address":"bob@example.net","invites":[)" + invites + R"(],"medium":"email","mxid":"@bob:example.org"})";
}

} // namespace

SCENARIO("An exchange_third_party_invite body is accepted only when every field is as the spec requires",
         "[federation][3pid][parsing]")
{
    GIVEN("a well-formed body")
    {
        WHEN("it is parsed against the room ID in the path")
        {
            auto const parsed = fed::parse_third_party_invite_exchange(exchange_body(signed_ok), "!r:example.org");

            THEN("the checked fields are returned and the signed object is kept whole")
            {
                REQUIRE(parsed.exchange.has_value());
                REQUIRE(parsed.exchange->sender == "@alice:example.org");
                REQUIRE(parsed.exchange->target_user_id == "@bob:example.org");
                REQUIRE(parsed.exchange->signed_invite.token == "tok");
                REQUIRE(parsed.exchange->signed_invite.json.find("\"signatures\"") != std::string::npos);
            }
        }

        WHEN("it is parsed against another room ID")
        {
            THEN("it is refused")
            {
                REQUIRE_FALSE(fed::parse_third_party_invite_exchange(exchange_body(signed_ok), "!x:example.org")
                                  .exchange.has_value());
            }
        }
    }

    GIVEN("signed objects that lack a field, hold a bad value or are over a bound")
    {
        auto const many_servers = [] {
            auto servers = std::string{};
            for (auto index = 0; index < 9; ++index)
            {
                servers += (servers.empty() ? "" : ",") + std::string{"\"s"} + std::to_string(index) +
                           R"(":{"ed25519:0":"c2ln"})";
            }
            return R"({"mxid":"@bob:example.org","signatures":{)" + servers + R"(},"token":"tok"})";
        }();
        auto const bad = std::vector<std::string>{
            R"({"mxid":"@bob:example.org","signatures":{"is.example":{"ed25519:0":"c2ln"}}})",
            R"({"signatures":{"is.example":{"ed25519:0":"c2ln"}},"token":"tok"})",
            R"({"mxid":"@bob:example.org","token":"tok"})",
            R"({"mxid":"bob","signatures":{"is.example":{"ed25519:0":"c2ln"}},"token":"tok"})",
            R"({"mxid":"@bob:example.org","signatures":{"is.example":{"ed25519:0":"c2ln"}},"token":""})",
            R"({"mxid":"@bob:example.org","signatures":{"is.example":{"ed25519:0":7}},"token":"tok"})",
            R"({"mxid":"@bob:example.org","signatures":{},"token":"tok"})",
            R"({"mxid":"@bob:example.org","signatures":{"is.example":{}},"token":"tok"})",
            R"({"mxid":"@bob:example.org","signatures":{"is.example":{"ed25519:0":"c2ln"}},"token":")" +
                std::string(256U, 't') + R"("})",
            R"({"mxid":"@bob:example.org","signatures":{"is.example":{"ed25519:0":"c2ln"}},"token":"tok","pad":")" +
                std::string(5000U, 'p') + R"("})",
            many_servers,
            "[]",
        };

        WHEN("each is parsed")
        {
            THEN("none is accepted")
            {
                for (auto const& signed_json : bad)
                {
                    CAPTURE(signed_json.substr(0U, 80U));
                    REQUIRE_FALSE(fed::parse_third_party_invite_exchange(exchange_body(signed_json), "!r:example.org")
                                      .exchange.has_value());
                }
            }
        }
    }

    GIVEN("bodies with another type, another membership, no third_party_invite or a bad identifier")
    {
        auto const base = exchange_body(signed_ok);
        auto const swap = [&](std::string const& from, std::string const& to) {
            auto copy = base;
            copy.replace(copy.find(from), from.size(), to);
            return copy;
        };
        auto const bad = std::vector<std::string>{
            swap("m.room.member", "m.room.message"),
            swap(R"("membership":"invite")", R"("membership":"join")"),
            swap(R"("sender":"@alice:example.org")", R"("sender":"alice")"),
            swap(R"("state_key":"@bob:example.org")", R"("state_key":"bob")"),
            swap(R"("third_party_invite")", R"("other")"),
            swap(R"("room_id":"!r:example.org")", R"("room_id":"r")"),
        };

        WHEN("each is parsed")
        {
            THEN("none is accepted")
            {
                for (auto const& body : bad)
                {
                    CAPTURE(body);
                    REQUIRE_FALSE(fed::parse_third_party_invite_exchange(body, "!r:example.org").exchange.has_value());
                }
            }
        }
    }
}

// Spec: Server-Server API v1.19, PUT /exchange_third_party_invite/{roomId}: `content.third_party_invite.display_name`
// is "Required: A name which can be displayed to represent the user instead of their third-party identifier".
SCENARIO("The exchange body this server sends carries every field the spec requires", "[federation][3pid][parsing]")
{
    GIVEN("an exchange to be requested from the inviting server")
    {
        auto const exchange =
            fed::parse_third_party_invite_exchange(exchange_body(signed_ok), "!r:example.org").exchange;
        REQUIRE(exchange.has_value());

        WHEN("the request body is built")
        {
            auto const body = fed::build_third_party_invite_exchange_body(*exchange);
            auto const parsed = merovingian::canonicaljson::parse_json(body);

            THEN("the third_party_invite holds a string display_name (empty: onbind supplies none) and the signed object")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const object_in = [](merovingian::canonicaljson::Object const& parent, std::string_view key) {
                    for (auto const& member : parent)
                    {
                        if (member.key == key)
                        {
                            return std::get_if<merovingian::canonicaljson::Object>(&member.value->storage());
                        }
                    }
                    return static_cast<merovingian::canonicaljson::Object const*>(nullptr);
                };
                auto const* content = object_in(*root, "content");
                REQUIRE(content != nullptr);
                auto const* invite = object_in(*content, "third_party_invite");
                REQUIRE(invite != nullptr);
                auto display_name = static_cast<std::string const*>(nullptr);
                for (auto const& member : *invite)
                {
                    if (member.key == "display_name")
                    {
                        display_name = std::get_if<std::string>(&member.value->storage());
                    }
                }
                REQUIRE(display_name != nullptr);
                REQUIRE(display_name->empty());
                REQUIRE(object_in(*invite, "signed") != nullptr);
            }

            THEN("the receiving side's parser accepts it")
            {
                REQUIRE(fed::parse_third_party_invite_exchange(body, "!r:example.org").exchange.has_value());
            }
        }
    }
}

SCENARIO("A 3pid onbind body is bounded and an entry that is not about the bound user is dropped",
         "[federation][3pid][parsing][onbind]")
{
    GIVEN("a body with one good entry and one naming another user")
    {
        auto const body = bind_body(invite_entry("@bob:example.org", signed_ok) + "," +
                                    invite_entry("@carol:example.org", signed_ok));

        WHEN("it is parsed")
        {
            auto const parsed = fed::parse_third_party_bind_notification(body);

            THEN("the good entry is kept and the other counted as dropped")
            {
                REQUIRE(parsed.notification.has_value());
                REQUIRE(parsed.notification->invites.size() == 1U);
                REQUIRE(parsed.notification->dropped == 1U);
                REQUIRE(parsed.notification->mxid == "@bob:example.org");
            }
        }
    }

    GIVEN("a body with one invite more than the bound")
    {
        auto invites = std::string{};
        for (auto index = 0U; index <= fed::max_third_party_bind_invites; ++index)
        {
            invites += (invites.empty() ? "" : ",") + invite_entry("@bob:example.org", signed_ok);
        }

        WHEN("it is parsed")
        {
            auto const parsed = fed::parse_third_party_bind_notification(bind_body(invites));

            THEN("the first invites up to the bound are kept and the rest counted as dropped")
            {
                // The spec gives no status for too many invites, and refusing the body would lose every invite the
                // identity server holds for the user.
                REQUIRE(parsed.notification.has_value());
                REQUIRE(parsed.notification->invites.size() == fed::max_third_party_bind_invites);
                REQUIRE(parsed.notification->dropped == 1U);
            }
        }
    }

    GIVEN("bodies without a required field or with a bad user")
    {
        auto const bad = std::vector<std::string>{
            "[]",
            R"({"address":"a","invites":[],"medium":"email"})",
            R"({"address":"a","invites":[],"medium":"email","mxid":"bob"})",
            R"({"address":"a","invites":{},"medium":"email","mxid":"@bob:example.org"})",
            R"({"invites":[],"medium":"email","mxid":"@bob:example.org"})",
        };

        WHEN("each is parsed")
        {
            THEN("none is accepted")
            {
                for (auto const& body : bad)
                {
                    CAPTURE(body);
                    REQUIRE_FALSE(fed::parse_third_party_bind_notification(body).notification.has_value());
                }
            }
        }
    }
}

SCENARIO("The exchange runs in main and onbind is answered without an X-Matrix signature",
         "[federation][3pid][routing]")
{
    GIVEN("requests for the two endpoints")
    {
        auto exchange = merovingian::homeserver::LocalHttpRequest{};
        exchange.method = "PUT";
        exchange.target = "/_matrix/federation/v1/exchange_third_party_invite/!r:example.org";
        auto other = merovingian::homeserver::LocalHttpRequest{};
        other.method = "PUT";
        other.target = "/_matrix/federation/v1/invite/!r:example.org/$e";

        WHEN("the proxy decides whether a worker may see them")
        {
            THEN("the exchange bypasses the worker and an ordinary invite does not")
            {
                REQUIRE(merovingian::homeserver::federation_request_should_bypass_worker(exchange));
                REQUIRE_FALSE(merovingian::homeserver::federation_request_should_bypass_worker(other));
            }
        }

        WHEN("the onbind path is matched")
        {
            THEN("only the exact path matches, with or without a query")
            {
                using merovingian::homeserver::is_federation_3pid_onbind_endpoint;
                REQUIRE(is_federation_3pid_onbind_endpoint("/_matrix/federation/v1/3pid/onbind"));
                REQUIRE(is_federation_3pid_onbind_endpoint("/_matrix/federation/v1/3pid/onbind?x=1"));
                REQUIRE_FALSE(is_federation_3pid_onbind_endpoint("/_matrix/federation/v1/3pid/onbind/extra"));
                REQUIRE_FALSE(is_federation_3pid_onbind_endpoint("/_matrix/federation/v1/3pid/onbin"));
            }

            THEN("a GET to it is answered 405 naming PUT")
            {
                auto const allow = merovingian::homeserver::federation_unsupported_method_allow(
                    "GET", "/_matrix/federation/v1/3pid/onbind");
                REQUIRE(allow.has_value());
                REQUIRE(*allow == "PUT");
                REQUIRE_FALSE(merovingian::homeserver::federation_unsupported_method_allow(
                                  "PUT", "/_matrix/federation/v1/3pid/onbind")
                                  .has_value());
            }
        }
    }
}
