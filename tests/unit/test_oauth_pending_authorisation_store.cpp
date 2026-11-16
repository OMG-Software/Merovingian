// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Plan P5 (ADR-0782): the in-memory pending authorisations behind GET /_merovingian/oauth2/authorize. Hashed, bound to
// the browser, ten minutes, bounded, never evicting a live entry.

#include "merovingian/homeserver/OAuthSecret.hpp"
#include "merovingian/homeserver/PendingAuthorisation.hpp"
#include "merovingian/homeserver/PendingAuthorisationStore.hpp"
#include "merovingian/oauth/ResponseMode.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using merovingian::homeserver::PendingAuthorisation;
using merovingian::homeserver::PendingAuthorisationStore;

constexpr auto start_ms = std::uint64_t{1'000'000U};
constexpr auto browser = std::string_view{"browser-binding-token"};

[[nodiscard]] auto request_for(std::string client_id) -> PendingAuthorisation
{
    auto authorisation = PendingAuthorisation{};
    authorisation.client_id = std::move(client_id);
    authorisation.redirect_uri = "https://app.example.org/callback";
    authorisation.response_mode = merovingian::oauth::ResponseMode::fragment;
    authorisation.state = "client-state";
    authorisation.code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    authorisation.device_id = "DEVICEID";
    authorisation.scope = "urn:matrix:client:api:* urn:matrix:client:device:DEVICEID";
    authorisation.create_account = true;
    authorisation.login_hint = "@alice:example.org";
    // The store sets these three itself.
    authorisation.user_id = "@mallory:example.org";
    authorisation.client_address_key = "ignored";
    authorisation.created_at_ms = 7U;
    return authorisation;
}

[[nodiscard]] auto create(PendingAuthorisationStore& store, std::string client_id, std::string_view address,
                          std::uint64_t now_ms) -> std::variant<std::string, PendingAuthorisationStore::Refusal>
{
    return store.create(request_for(std::move(client_id)), browser, address, now_ms);
}

[[nodiscard]] auto identifier_of(std::variant<std::string, PendingAuthorisationStore::Refusal> const& created)
    -> std::string
{
    REQUIRE(std::holds_alternative<std::string>(created));
    return std::get<std::string>(created);
}

} // namespace

SCENARIO("A pending authorisation is stored under a fresh identifier and read back only with its browser token",
         "[oauth][oauth-pending]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("a store holding one request")
    {
        auto store = PendingAuthorisationStore{};
        auto const identifier = identifier_of(create(store, "client-a", "198.51.100.7", start_ms));

        WHEN("it is found with its identifier and its browser token")
        {
            auto const found = store.find(identifier, browser, start_ms + 1U);

            THEN("the request comes back as stored, with the fields the store owns set by the store")
            {
                REQUIRE(found.has_value());
                CHECK(found->client_id == "client-a");
                CHECK(found->redirect_uri == "https://app.example.org/callback");
                CHECK(found->response_mode == merovingian::oauth::ResponseMode::fragment);
                CHECK(found->state == "client-state");
                CHECK(found->code_challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
                CHECK(found->device_id == "DEVICEID");
                CHECK(found->scope == "urn:matrix:client:api:* urn:matrix:client:device:DEVICEID");
                CHECK(found->create_account);
                CHECK(found->login_hint == std::optional<std::string>{"@alice:example.org"});
                CHECK(found->user_id.empty());
                CHECK(found->client_address_key == "198.51.100.7");
                CHECK(found->created_at_ms == start_ms);
            }

            THEN("the identifier is 64 hex digits and is not what the store keeps")
            {
                REQUIRE(identifier.size() == 64U);
                CHECK(identifier.find_first_not_of("0123456789abcdef") == std::string::npos);
                CHECK(merovingian::homeserver::oauth_secret_hash(identifier) != std::optional<std::string>{identifier});
            }
        }

        WHEN("it is looked up with a wrong browser token, and with an unknown identifier")
        {
            auto const wrong_token = store.find(identifier, "another-browser", start_ms + 1U);
            auto const unknown = store.find(std::string(64U, 'a'), browser, start_ms + 1U);
            auto const empty_token = store.find(identifier, "", start_ms + 1U);

            THEN("both answer alike, nothing, and the entry is still held")
            {
                CHECK_FALSE(wrong_token.has_value());
                CHECK_FALSE(unknown.has_value());
                CHECK_FALSE(empty_token.has_value());
                CHECK(store.size() == 1U);
                CHECK(store.find(identifier, browser, start_ms + 2U).has_value());
            }
        }

        WHEN("a wrong browser token tries to record a user and to consume it")
        {
            auto const recorded = store.record_user(identifier, "another-browser", "@mallory:example.org", start_ms);
            auto const consumed = store.consume(identifier, "another-browser", start_ms);

            THEN("both are refused and the entry is untouched")
            {
                CHECK_FALSE(recorded);
                CHECK_FALSE(consumed.has_value());
                auto const found = store.find(identifier, browser, start_ms);
                REQUIRE(found.has_value());
                CHECK(found->user_id.empty());
            }
        }

        WHEN("the authenticated user is recorded and the entry is consumed")
        {
            REQUIRE(store.record_user(identifier, browser, "@alice:example.org", start_ms + 10U));
            auto const consumed = store.consume(identifier, browser, start_ms + 20U);
            auto const again = store.consume(identifier, browser, start_ms + 30U);

            THEN("the consumed entry names the user, and it is gone")
            {
                REQUIRE(consumed.has_value());
                CHECK(consumed->user_id == "@alice:example.org");
                CHECK_FALSE(again.has_value());
                CHECK(store.size() == 0U);
                CHECK(store.live_count_for_client("client-a", start_ms + 30U) == 0U);
            }
        }
    }

    GIVEN("an empty store")
    {
        auto store = PendingAuthorisationStore{};

        WHEN("a request is offered with no browser token")
        {
            auto const created = store.create(request_for("client-a"), "", "198.51.100.7", start_ms);

            THEN("it is refused and nothing is stored")
            {
                REQUIRE(std::holds_alternative<PendingAuthorisationStore::Refusal>(created));
                CHECK(std::get<PendingAuthorisationStore::Refusal>(created) ==
                      PendingAuthorisationStore::Refusal::no_browser_token);
                CHECK(store.size() == 0U);
            }
        }

        WHEN("two requests are stored")
        {
            auto const first = identifier_of(create(store, "client-a", "198.51.100.7", start_ms));
            auto const second = identifier_of(create(store, "client-a", "198.51.100.7", start_ms));

            THEN("each has its own identifier")
            {
                CHECK(first != second);
                CHECK(store.size() == 2U);
            }
        }
    }
}

SCENARIO("A pending authorisation lives ten minutes from its creation, to the millisecond", "[oauth][oauth-pending]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("a store holding one request created at a known time")
    {
        auto store = PendingAuthorisationStore{};
        auto const identifier = identifier_of(create(store, "client-a", "198.51.100.7", start_ms));
        auto const end_ms = start_ms + PendingAuthorisationStore::lifetime_ms;

        WHEN("it is read one millisecond before its end")
        {
            REQUIRE(store.record_user(identifier, browser, "@alice:example.org", end_ms - 2U));
            auto const found = store.find(identifier, browser, end_ms - 1U);

            THEN("it is live, and recording the user did not extend it")
            {
                REQUIRE(found.has_value());
                CHECK(store.holds_live_entry_for_client("client-a", end_ms - 1U));
                CHECK_FALSE(store.holds_live_entry_for_client("client-a", end_ms));
            }
        }

        WHEN("it is read at exactly its end")
        {
            auto const found = store.find(identifier, browser, end_ms);

            THEN("it behaves as absent and has been removed")
            {
                CHECK_FALSE(found.has_value());
                CHECK(store.size() == 0U);
                CHECK(store.live_count_for_client("client-a", end_ms) == 0U);
            }
        }

        WHEN("it is consumed at exactly its end")
        {
            auto const consumed = store.consume(identifier, browser, end_ms);

            THEN("nothing is returned")
            {
                CHECK_FALSE(consumed.has_value());
            }
        }
    }
}

SCENARIO("The pending authorisations are capped per address and in all, and a live entry is never evicted",
         "[oauth][oauth-pending][cap]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("one address holding its cap of live entries")
    {
        auto store = PendingAuthorisationStore{};
        auto identifiers = std::vector<std::string>{};
        for (auto index = std::size_t{0U}; index < PendingAuthorisationStore::max_entries_per_address; ++index)
        {
            identifiers.push_back(identifier_of(create(store, "client-a", "198.51.100.7", start_ms + index)));
        }

        WHEN("the same address asks again, and another address asks")
        {
            auto const refused = create(store, "client-a", "198.51.100.7", start_ms + 100U);
            auto const other = create(store, "client-a", "203.0.113.9", start_ms + 100U);

            THEN("the first is refused for its address, the second is stored, and every earlier entry is live")
            {
                REQUIRE(std::holds_alternative<PendingAuthorisationStore::Refusal>(refused));
                CHECK(std::get<PendingAuthorisationStore::Refusal>(refused) ==
                      PendingAuthorisationStore::Refusal::address_full);
                CHECK(std::holds_alternative<std::string>(other));
                for (auto const& identifier : identifiers)
                {
                    CHECK(store.find(identifier, browser, start_ms + 100U).has_value());
                }
            }
        }

        WHEN("the oldest entry has expired and the address asks again")
        {
            auto const later = start_ms + PendingAuthorisationStore::lifetime_ms;
            auto const created = create(store, "client-a", "198.51.100.7", later);

            THEN("the expired entry was purged to make room, and the others are still live")
            {
                CHECK(std::holds_alternative<std::string>(created));
                CHECK_FALSE(store.find(identifiers.front(), browser, later).has_value());
                CHECK(store.find(identifiers.back(), browser, later).has_value());
            }
        }

        WHEN("one entry is consumed and the address asks again")
        {
            REQUIRE(store.consume(identifiers.front(), browser, start_ms + 50U).has_value());
            auto const created = create(store, "client-a", "198.51.100.7", start_ms + 50U);

            THEN("the freed place is used")
            {
                CHECK(std::holds_alternative<std::string>(created));
            }
        }
    }

    GIVEN("a store holding its total cap of live entries from many addresses")
    {
        auto store = PendingAuthorisationStore{};
        auto first = std::string{};
        for (auto index = std::size_t{0U}; index < PendingAuthorisationStore::max_entries; ++index)
        {
            auto const address =
                "address-" + std::to_string(index / PendingAuthorisationStore::max_entries_per_address);
            auto identifier = identifier_of(create(store, "client-" + std::to_string(index % 3U), address, start_ms));
            if (index == 0U)
            {
                first = std::move(identifier);
            }
        }

        WHEN("a new address asks while every entry is live")
        {
            auto const refused = create(store, "client-new", "203.0.113.200", start_ms + 1U);

            THEN("it is refused, nothing was evicted, and the first entry is still live")
            {
                REQUIRE(std::holds_alternative<PendingAuthorisationStore::Refusal>(refused));
                CHECK(std::get<PendingAuthorisationStore::Refusal>(refused) ==
                      PendingAuthorisationStore::Refusal::store_full);
                CHECK(store.size() == PendingAuthorisationStore::max_entries);
                CHECK(store.find(first, browser, start_ms + 1U).has_value());
            }
        }

        WHEN("the entries have expired and a new address asks")
        {
            auto const later = start_ms + PendingAuthorisationStore::lifetime_ms;
            auto const created = create(store, "client-new", "203.0.113.200", later);

            THEN("the expired entries were purged and it is stored")
            {
                CHECK(std::holds_alternative<std::string>(created));
                CHECK(store.size() == 1U);
            }
        }
    }
}

SCENARIO("The live pending authorisations of a client are counted without a scan", "[oauth][oauth-pending]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("two entries for one client, made a minute apart, and one for another")
    {
        auto store = PendingAuthorisationStore{};
        auto const early = identifier_of(create(store, "client-a", "198.51.100.7", start_ms));
        std::ignore = identifier_of(create(store, "client-a", "198.51.100.8", start_ms + 60'000U));
        std::ignore = identifier_of(create(store, "client-b", "198.51.100.9", start_ms));

        WHEN("the counts are read while all are live, after the earlier one expired, and after all expired")
        {
            auto const all_live = store.live_count_for_client("client-a", start_ms + 1U);
            auto const other = store.live_count_for_client("client-b", start_ms + 1U);
            auto const none = store.live_count_for_client("client-c", start_ms + 1U);
            auto const held_after_early =
                store.holds_live_entry_for_client("client-a", start_ms + PendingAuthorisationStore::lifetime_ms);
            auto const after_early =
                store.live_count_for_client("client-a", start_ms + PendingAuthorisationStore::lifetime_ms);
            auto const held_after_all = store.holds_live_entry_for_client(
                "client-a", start_ms + 60'000U + PendingAuthorisationStore::lifetime_ms);

            THEN("each answer counts only the client's live entries")
            {
                CHECK(all_live == 2U);
                CHECK(other == 1U);
                CHECK(none == 0U);
                CHECK(held_after_early);
                CHECK(after_early == 1U);
                CHECK_FALSE(held_after_all);
            }
        }

        WHEN("the earlier entry is consumed")
        {
            REQUIRE(store.consume(early, browser, start_ms + 1U).has_value());

            THEN("the client's count drops by one")
            {
                CHECK(store.live_count_for_client("client-a", start_ms + 1U) == 1U);
                CHECK(store.holds_live_entry_for_client("client-a", start_ms + 1U));
            }
        }
    }
}
