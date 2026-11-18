// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Plan P5 (ADR-0782): the in-memory authorisation codes an approval mints and the token endpoint redeems. Hashed, 60
// seconds, single use, a replay recognised until the code's own expiry, bounded, never evicting a live code.

#include "merovingian/homeserver/AuthorizationCodeRedemption.hpp"
#include "merovingian/homeserver/AuthorizationCodeStore.hpp"
#include "merovingian/homeserver/AuthorizationGrant.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>
#include <utility>
#include <variant>

namespace
{

using merovingian::homeserver::AuthorizationCodeRedemption;
using merovingian::homeserver::AuthorizationCodeStore;
using merovingian::homeserver::AuthorizationGrant;
using Outcome = merovingian::homeserver::AuthorizationCodeRedemption::Outcome;

constexpr auto start_ms = std::uint64_t{5'000'000U};

[[nodiscard]] auto grant_for(std::string client_id, std::string device_id) -> AuthorizationGrant
{
    return {std::move(client_id),
            "https://app.example.org/callback",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "@alice:example.org",
            device_id,
            "urn:matrix:client:api:* urn:matrix:client:device:" + device_id};
}

[[nodiscard]] auto code_of(std::variant<std::string, AuthorizationCodeStore::Refusal> const& issued) -> std::string
{
    REQUIRE(std::holds_alternative<std::string>(issued));
    return std::get<std::string>(issued);
}

} // namespace

SCENARIO("An authorisation code is redeemed once, and a second presentation is recognised as a replay",
         "[oauth][oauth-code]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("a store holding one code")
    {
        auto store = AuthorizationCodeStore{};
        auto const code = code_of(store.issue(grant_for("client-a", "DEVICEA"), start_ms));

        WHEN("it is redeemed twice")
        {
            auto const first = store.redeem(code, start_ms + 1U);
            auto const second = store.redeem(code, start_ms + 2U);

            THEN("the first is fresh with the whole grant")
            {
                REQUIRE(first.outcome == Outcome::fresh);
                CHECK(first.grant.client_id == "client-a");
                CHECK(first.grant.redirect_uri == "https://app.example.org/callback");
                CHECK(first.grant.code_challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
                CHECK(first.grant.user_id == "@alice:example.org");
                CHECK(first.grant.device_id == "DEVICEA");
                CHECK(first.grant.scope == "urn:matrix:client:api:* urn:matrix:client:device:DEVICEA");
            }

            THEN("the second is a replay naming the session the first was for, without the grant")
            {
                REQUIRE(second.outcome == Outcome::replayed);
                CHECK(second.user_id == "@alice:example.org");
                CHECK(second.device_id == "DEVICEA");
                CHECK(second.grant.client_id.empty());
                CHECK(second.grant.code_challenge.empty());
            }
        }

        WHEN("an unknown code and the empty code are redeemed")
        {
            auto const unknown = store.redeem(std::string(64U, 'f'), start_ms + 1U);
            auto const empty = store.redeem("", start_ms + 1U);

            THEN("both are unknown and the real code is still fresh")
            {
                CHECK(unknown.outcome == Outcome::unknown);
                CHECK(unknown.user_id.empty());
                CHECK(empty.outcome == Outcome::unknown);
                CHECK(store.redeem(code, start_ms + 2U).outcome == Outcome::fresh);
            }
        }

        WHEN("the code is looked at")
        {
            THEN("it is 64 hex digits")
            {
                REQUIRE(code.size() == 64U);
                CHECK(code.find_first_not_of("0123456789abcdef") == std::string::npos);
            }
        }
    }
}

SCENARIO("An authorisation code lives 60 seconds, to the millisecond, and so does its replay record",
         "[oauth][oauth-code]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("a code issued at a known time")
    {
        auto store = AuthorizationCodeStore{};
        auto const code = code_of(store.issue(grant_for("client-a", "DEVICEA"), start_ms));
        auto const end_ms = start_ms + AuthorizationCodeStore::lifetime_ms;

        WHEN("it is redeemed one millisecond before its end")
        {
            auto const redeemed = store.redeem(code, end_ms - 1U);

            THEN("it is fresh")
            {
                CHECK(redeemed.outcome == Outcome::fresh);
            }
        }

        WHEN("it is redeemed at exactly its end")
        {
            auto const redeemed = store.redeem(code, end_ms);

            THEN("it is unknown and removed")
            {
                CHECK(redeemed.outcome == Outcome::unknown);
                CHECK(store.size() == 0U);
            }
        }

        WHEN("it is redeemed, then presented again just before and at its end")
        {
            REQUIRE(store.redeem(code, start_ms + 1U).outcome == Outcome::fresh);
            auto const late_replay = store.redeem(code, end_ms - 1U);
            auto const after_end = store.redeem(code, end_ms);

            THEN("the replay is recognised until the code's own expiry and forgotten from then")
            {
                CHECK(late_replay.outcome == Outcome::replayed);
                CHECK(after_end.outcome == Outcome::unknown);
                CHECK(store.size() == 0U);
            }
        }
    }
}

SCENARIO("The authorisation codes are capped, purge expired codes first and never evict a live one",
         "[oauth][oauth-code][cap]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("a store holding its cap of codes, the first already redeemed")
    {
        auto store = AuthorizationCodeStore{};
        auto first = std::string{};
        auto last = std::string{};
        for (auto index = std::size_t{0U}; index < AuthorizationCodeStore::max_codes; ++index)
        {
            last = code_of(store.issue(grant_for("client-" + std::to_string(index % 4U), "DEV"), start_ms + index));
            if (index == 0U)
            {
                first = last;
            }
        }
        REQUIRE(store.redeem(first, start_ms + AuthorizationCodeStore::max_codes).outcome == Outcome::fresh);

        WHEN("another code is asked for while every code is live")
        {
            auto const refused =
                store.issue(grant_for("client-new", "DEV"), start_ms + AuthorizationCodeStore::max_codes);

            THEN("it is refused, the redeemed code still counts and is still recognised, and the last code is fresh")
            {
                REQUIRE(std::holds_alternative<AuthorizationCodeStore::Refusal>(refused));
                CHECK(std::get<AuthorizationCodeStore::Refusal>(refused) ==
                      AuthorizationCodeStore::Refusal::store_full);
                CHECK(store.size() == AuthorizationCodeStore::max_codes);
                CHECK(store.redeem(first, start_ms + AuthorizationCodeStore::max_codes).outcome == Outcome::replayed);
                CHECK(store.redeem(last, start_ms + AuthorizationCodeStore::max_codes).outcome == Outcome::fresh);
            }
        }

        WHEN("the first code has expired and another is asked for")
        {
            auto const later = start_ms + AuthorizationCodeStore::lifetime_ms;
            auto const issued = store.issue(grant_for("client-new", "DEV"), later);

            THEN("the expired code was purged to make room")
            {
                CHECK(std::holds_alternative<std::string>(issued));
                CHECK(store.size() == AuthorizationCodeStore::max_codes);
                CHECK(store.redeem(first, later).outcome == Outcome::unknown);
            }
        }
    }
}

SCENARIO("The unredeemed codes of a client are counted without a scan", "[oauth][oauth-code]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("two codes for one client, ten seconds apart, and one for another")
    {
        auto store = AuthorizationCodeStore{};
        auto const early = code_of(store.issue(grant_for("client-a", "DEV1"), start_ms));
        std::ignore = code_of(store.issue(grant_for("client-a", "DEV2"), start_ms + 10'000U));
        std::ignore = code_of(store.issue(grant_for("client-b", "DEV3"), start_ms));

        WHEN("the earlier code is redeemed")
        {
            auto const before = store.unredeemed_count_for_client("client-a", start_ms + 1U);
            REQUIRE(store.redeem(early, start_ms + 1U).outcome == Outcome::fresh);
            auto const after = store.unredeemed_count_for_client("client-a", start_ms + 1U);

            THEN("the redeemed code no longer counts, though it is still held for replay detection")
            {
                CHECK(before == 2U);
                CHECK(after == 1U);
                CHECK(store.size() == 3U);
                CHECK(store.unredeemed_count_for_client("client-b", start_ms + 1U) == 1U);
                CHECK(store.unredeemed_count_for_client("client-c", start_ms + 1U) == 0U);
            }
        }

        WHEN("the codes expire")
        {
            auto const end_early = start_ms + AuthorizationCodeStore::lifetime_ms;
            auto const end_late = end_early + 10'000U;

            THEN("the client holds a live code until its latest one ends")
            {
                CHECK(store.holds_unredeemed_code_for_client("client-a", end_early));
                CHECK(store.unredeemed_count_for_client("client-a", end_early) == 1U);
                CHECK_FALSE(store.holds_unredeemed_code_for_client("client-a", end_late));
                CHECK(store.unredeemed_count_for_client("client-a", end_late) == 0U);
            }
        }

        WHEN("a client that holds no code is asked about")
        {
            auto const unknown_client = store.holds_unredeemed_code_for_client("client-c", start_ms + 1U);

            THEN("it holds none")
            {
                CHECK_FALSE(unknown_client);
            }
        }
    }
}

SCENARIO("A replay names the session the first redemption issued, and only once one was recorded",
         "[oauth][oauth-code][oauth-replay]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("a store holding one code that has been redeemed")
    {
        auto store = AuthorizationCodeStore{};
        auto const code = code_of(store.issue(grant_for("client-a", "DEVICEA"), start_ms));
        REQUIRE(store.redeem(code, start_ms + 1U).outcome == Outcome::fresh);

        WHEN("it is presented again before any session was recorded")
        {
            auto const replay = store.redeem(code, start_ms + 2U);

            THEN("the replay names the client and no session")
            {
                REQUIRE(replay.outcome == Outcome::replayed);
                CHECK(replay.client_id == "client-a");
                CHECK_FALSE(replay.session_created_at_ms.has_value());
            }
        }

        WHEN("the session its redemption issued is recorded and the code is presented again")
        {
            auto const recorded = store.record_issued_session(code, start_ms + 7U, start_ms + 2U);
            auto const again = store.record_issued_session(code, start_ms + 9U, start_ms + 3U);
            auto const replay = store.redeem(code, start_ms + 4U);

            THEN("the replay names that session, and a second record changes nothing")
            {
                CHECK(recorded);
                CHECK_FALSE(again);
                REQUIRE(replay.outcome == Outcome::replayed);
                REQUIRE(replay.session_created_at_ms.has_value());
                CHECK(*replay.session_created_at_ms == start_ms + 7U);
            }
        }

        WHEN("a session is recorded after the code expired")
        {
            auto const recorded =
                store.record_issued_session(code, start_ms + 7U, start_ms + AuthorizationCodeStore::lifetime_ms);

            THEN("nothing is recorded")
            {
                CHECK_FALSE(recorded);
            }
        }
    }

    GIVEN("a store holding one code that was never redeemed")
    {
        auto store = AuthorizationCodeStore{};
        auto const code = code_of(store.issue(grant_for("client-a", "DEVICEA"), start_ms));

        WHEN("a session is recorded for it, or for a code never issued")
        {
            auto const unredeemed = store.record_issued_session(code, start_ms + 7U, start_ms + 1U);
            auto const unknown = store.record_issued_session(std::string(64U, 'a'), start_ms + 7U, start_ms + 1U);

            THEN("nothing is recorded, and the code is still fresh")
            {
                CHECK_FALSE(unredeemed);
                CHECK_FALSE(unknown);
                CHECK(store.redeem(code, start_ms + 2U).outcome == Outcome::fresh);
            }
        }
    }
}

SCENARIO("The creation times a code store gives OAuth sessions strictly increase", "[oauth][oauth-code][oauth-replay]")
{
    GIVEN("an empty store")
    {
        auto store = AuthorizationCodeStore{};

        WHEN("it is asked three times within one millisecond, then once later, then once with the clock back")
        {
            auto const first = store.next_session_created_at_ms(start_ms);
            auto const second = store.next_session_created_at_ms(start_ms);
            auto const third = store.next_session_created_at_ms(start_ms);
            auto const later = store.next_session_created_at_ms(start_ms + 100U);
            auto const backwards = store.next_session_created_at_ms(start_ms);

            THEN("each value is the clock or one past the last, whichever is greater")
            {
                CHECK(first == start_ms);
                CHECK(second == start_ms + 1U);
                CHECK(third == start_ms + 2U);
                CHECK(later == start_ms + 100U);
                CHECK(backwards == start_ms + 101U);
            }
        }
    }
}
