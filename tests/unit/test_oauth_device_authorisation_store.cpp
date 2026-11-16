// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Plan P11 (ADR-0804 to ADR-0806): the in-memory device authorisations behind POST /_merovingian/oauth2/device, the
// link page and the device code grant, and the per-address throttle on wrong user codes. Every operation takes the
// time, so no scenario sleeps.

#include "merovingian/homeserver/DeviceAuthorisation.hpp"
#include "merovingian/homeserver/DeviceAuthorisationState.hpp"
#include "merovingian/homeserver/DeviceAuthorisationStore.hpp"
#include "merovingian/homeserver/UserCodeAttemptThrottle.hpp"
#include "merovingian/oauth/UserCode.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using merovingian::homeserver::DeviceAuthorisationState;
using merovingian::homeserver::DeviceAuthorisationStore;
using merovingian::homeserver::UserCodeAttemptThrottle;
using PollOutcome = DeviceAuthorisationStore::PollOutcome;

constexpr auto start_ms = std::uint64_t{1'000'000U};
constexpr auto client = std::string_view{"client-a"};
constexpr auto other_client = std::string_view{"client-b"};
constexpr auto scope = std::string_view{"urn:matrix:client:api:* urn:matrix:client:device:TVDEVICE"};
constexpr auto device = std::string_view{"TVDEVICE"};
constexpr auto address = std::string_view{"198.51.100.7"};
constexpr auto browser = std::string_view{"browser-one-token"};
constexpr auto second_browser = std::string_view{"browser-two-token"};

// Hands out the byte strings it was given, in order, then fails.
[[nodiscard]] auto scripted(std::vector<std::vector<std::uint8_t>> draws) -> DeviceAuthorisationStore::RandomSource
{
    auto queue = std::make_shared<std::deque<std::vector<std::uint8_t>>>(draws.begin(), draws.end());
    return [queue](std::size_t) -> std::optional<std::vector<std::uint8_t>> {
        if (queue->empty())
        {
            return std::nullopt;
        }
        auto next = std::move(queue->front());
        queue->pop_front();
        return next;
    };
}

// A draw that gives the code whose characters are at `first` .. `first + 7` of the alphabet (modulo twenty).
[[nodiscard]] auto draw_from(std::uint8_t first) -> std::vector<std::uint8_t>
{
    auto bytes = std::vector<std::uint8_t>{};
    for (auto offset = std::uint8_t{0U}; offset < 8U; ++offset)
    {
        bytes.push_back(static_cast<std::uint8_t>(first + offset));
    }
    return bytes;
}

[[nodiscard]] auto started(std::variant<DeviceAuthorisationStore::Started, DeviceAuthorisationStore::Refusal> created)
    -> DeviceAuthorisationStore::Started
{
    REQUIRE(std::holds_alternative<DeviceAuthorisationStore::Started>(created));
    return std::get<DeviceAuthorisationStore::Started>(std::move(created));
}

[[nodiscard]] auto attached(std::variant<DeviceAuthorisationStore::Attached, DeviceAuthorisationStore::Busy,
                                         DeviceAuthorisationStore::NotFound> held) -> DeviceAuthorisationStore::Attached
{
    REQUIRE(std::holds_alternative<DeviceAuthorisationStore::Attached>(held));
    return std::get<DeviceAuthorisationStore::Attached>(std::move(held));
}

[[nodiscard]] auto address_number(std::size_t index) -> std::string
{
    return "address-" + std::to_string(index);
}

} // namespace

SCENARIO("A device authorisation hands out a device code and a user code once and keeps neither readable",
         "[oauth][oauth-device]")
{
    GIVEN("an empty store")
    {
        auto store = DeviceAuthorisationStore{};

        WHEN("a device authorisation is created")
        {
            auto const created = started(store.create(client, scope, device, address, start_ms));

            THEN("the device is told the codes, ten minutes and five seconds")
            {
                REQUIRE(created.device_code.size() == 64U);
                REQUIRE(created.user_code.size() == merovingian::oauth::user_code_length);
                REQUIRE(merovingian::oauth::normalise_user_code(created.user_code) == created.user_code);
                REQUIRE(created.expires_in_ms == 600'000U);
                REQUIRE(created.interval_ms == 5'000U);
                REQUIRE(store.size() == 1U);
            }

            AND_THEN("the user code finds the entry, which holds what was asked and no user")
            {
                auto const hold = attached(store.attach(created.user_code, browser, start_ms));
                REQUIRE(hold.key != created.device_code);
                REQUIRE(hold.authorisation.client_id == client);
                REQUIRE(hold.authorisation.scope == scope);
                REQUIRE(hold.authorisation.device_id == device);
                REQUIRE(hold.authorisation.state == DeviceAuthorisationState::pending);
                REQUIRE(hold.authorisation.user_id.empty());
            }

            AND_THEN("the device code does not find the entry on the link page")
            {
                REQUIRE(std::holds_alternative<DeviceAuthorisationStore::NotFound>(
                    store.attach(created.device_code, browser, start_ms)));
            }
        }
    }
}

SCENARIO("A user code that clashes with a held one is drawn again, and a source that keeps clashing refuses",
         "[oauth][oauth-device]")
{
    GIVEN("a source that gives the same code twice, then another")
    {
        auto store = DeviceAuthorisationStore{scripted({draw_from(0U), draw_from(0U), draw_from(1U)})};
        auto const first = started(store.create(client, scope, device, address, start_ms));

        WHEN("a second authorisation is created")
        {
            auto const second = started(store.create(client, scope, device, address, start_ms));

            THEN("it gets the third draw, not the clashing one")
            {
                REQUIRE(first.user_code == "BCDFGHJK");
                REQUIRE(second.user_code == "CDFGHJKL");
            }
        }
    }

    GIVEN("a source that gives only the held code")
    {
        auto draws = std::vector<std::vector<std::uint8_t>>{};
        for (auto index = std::size_t{0U}; index <= DeviceAuthorisationStore::max_user_code_draws; ++index)
        {
            draws.push_back(draw_from(0U));
        }
        auto store = DeviceAuthorisationStore{scripted(std::move(draws))};
        std::ignore = started(store.create(client, scope, device, address, start_ms));

        WHEN("another authorisation is created")
        {
            auto const refused = store.create(client, scope, device, address, start_ms);

            THEN("it is refused after the bounded number of draws, and nothing is stored")
            {
                REQUIRE(std::holds_alternative<DeviceAuthorisationStore::Refusal>(refused));
                REQUIRE(std::get<DeviceAuthorisationStore::Refusal>(refused) ==
                        DeviceAuthorisationStore::Refusal::secret_unavailable);
                REQUIRE(store.size() == 1U);
            }
        }
    }

    GIVEN("a source that fails")
    {
        auto store = DeviceAuthorisationStore{scripted({})};

        WHEN("an authorisation is created")
        {
            auto const refused = store.create(client, scope, device, address, start_ms);

            THEN("it is refused as a secret failure")
            {
                REQUIRE(std::get<DeviceAuthorisationStore::Refusal>(refused) ==
                        DeviceAuthorisationStore::Refusal::secret_unavailable);
                REQUIRE(store.size() == 0U);
            }
        }
    }
}

SCENARIO("A device authorisation ends at exactly ten minutes", "[oauth][oauth-device]")
{
    GIVEN("an authorisation")
    {
        auto store = DeviceAuthorisationStore{};
        auto const created = started(store.create(client, scope, device, address, start_ms));
        auto const ends = start_ms + DeviceAuthorisationStore::lifetime_ms;

        WHEN("it is polled and looked up one millisecond before the end")
        {
            auto const poll = store.poll(created.device_code, client, ends - 1U);

            THEN("it is still pending")
            {
                REQUIRE(poll.outcome == PollOutcome::authorization_pending);
                REQUIRE(store.holds_live_entry_for_client(client, ends - 1U));
            }
        }

        WHEN("it is polled and looked up at the end")
        {
            auto const live = store.holds_live_entry_for_client(client, ends);
            auto const poll = store.poll(created.device_code, client, ends);
            auto const link = store.attach(created.user_code, browser, ends);

            THEN("it is gone: the device hears expired_token and the code is unknown")
            {
                REQUIRE_FALSE(live);
                REQUIRE(poll.outcome == PollOutcome::expired_token);
                REQUIRE(std::holds_alternative<DeviceAuthorisationStore::NotFound>(link));
                REQUIRE(store.size() == 0U);
                REQUIRE(store.live_count_for_client(client, ends) == 0U);
            }
        }
    }
}

SCENARIO("The store refuses past its caps and never evicts a live entry", "[oauth][oauth-device][security]")
{
    GIVEN("one address holding its eight authorisations")
    {
        auto store = DeviceAuthorisationStore{};
        for (auto index = std::size_t{0U}; index < DeviceAuthorisationStore::max_entries_per_address; ++index)
        {
            std::ignore = started(store.create(client, scope, device, address, start_ms));
        }

        WHEN("it asks for a ninth, and another address asks for one")
        {
            auto const ninth = store.create(client, scope, device, address, start_ms);
            auto const elsewhere = store.create(client, scope, device, "203.0.113.9", start_ms);

            THEN("the ninth is refused for the address, and the other address is served")
            {
                REQUIRE(std::get<DeviceAuthorisationStore::Refusal>(ninth) ==
                        DeviceAuthorisationStore::Refusal::address_full);
                REQUIRE(std::holds_alternative<DeviceAuthorisationStore::Started>(elsewhere));
                REQUIRE(store.size() == DeviceAuthorisationStore::max_entries_per_address + 1U);
            }
        }

        WHEN("the eight have expired")
        {
            auto const later =
                store.create(client, scope, device, address, start_ms + DeviceAuthorisationStore::lifetime_ms);

            THEN("the address is served again")
            {
                REQUIRE(std::holds_alternative<DeviceAuthorisationStore::Started>(later));
                REQUIRE(store.size() == 1U);
            }
        }
    }

    GIVEN("a full store")
    {
        auto store = DeviceAuthorisationStore{};
        for (auto index = std::size_t{0U}; index < DeviceAuthorisationStore::max_entries; ++index)
        {
            std::ignore = started(store.create(
                client, scope, device, address_number(index / DeviceAuthorisationStore::max_entries_per_address),
                start_ms + index));
        }

        WHEN("one more is asked for before the oldest expires, and again when it has")
        {
            auto const full = store.create(client, scope, device, "fresh-address", start_ms + 10'000U);
            auto const after =
                store.create(client, scope, device, "fresh-address", start_ms + DeviceAuthorisationStore::lifetime_ms);

            THEN("the first is refused with nothing evicted, and the second takes the expired entry's place")
            {
                REQUIRE(std::get<DeviceAuthorisationStore::Refusal>(full) ==
                        DeviceAuthorisationStore::Refusal::store_full);
                REQUIRE(std::holds_alternative<DeviceAuthorisationStore::Started>(after));
                REQUIRE(store.size() == DeviceAuthorisationStore::max_entries);
            }
        }
    }
}

SCENARIO("A device polling too fast is told to slow down, and its interval grows for good", "[oauth][oauth-device]")
{
    GIVEN("a pending authorisation")
    {
        auto store = DeviceAuthorisationStore{};
        auto const created = started(store.create(client, scope, device, address, start_ms));

        WHEN("the device polls at once, then again a second later")
        {
            auto const first = store.poll(created.device_code, client, start_ms);
            auto const second = store.poll(created.device_code, client, start_ms + 1'000U);

            THEN("the first poll is pending, the second slow_down with ten seconds")
            {
                REQUIRE(first.outcome == PollOutcome::authorization_pending);
                REQUIRE(first.interval_ms == 5'000U);
                REQUIRE(second.outcome == PollOutcome::slow_down);
                REQUIRE(second.interval_ms == 10'000U);
            }

            AND_WHEN("it next polls five seconds later, then ten seconds after that")
            {
                auto const five = store.poll(created.device_code, client, start_ms + 6'000U);
                auto const ten = store.poll(created.device_code, client, start_ms + 16'000U);

                THEN("both are too soon under the grown interval, and a poll a whole interval later is in time")
                {
                    REQUIRE(five.outcome == PollOutcome::slow_down);
                    REQUIRE(five.interval_ms == 15'000U);
                    REQUIRE(ten.outcome == PollOutcome::slow_down);
                    REQUIRE(ten.interval_ms == 20'000U);
                    auto const in_time = store.poll(created.device_code, client, start_ms + 36'000U);
                    REQUIRE(in_time.outcome == PollOutcome::authorization_pending);
                    REQUIRE(in_time.interval_ms == 20'000U);
                }
            }
        }

        WHEN("the device polls exactly at its interval")
        {
            std::ignore = store.poll(created.device_code, client, start_ms);
            auto const on_time = store.poll(created.device_code, client, start_ms + 5'000U);

            THEN("it is pending, not slow_down")
            {
                REQUIRE(on_time.outcome == PollOutcome::authorization_pending);
            }
        }
    }
}

SCENARIO("A device code polled by another client, or never issued, gives the device nothing", "[oauth][oauth-device]")
{
    GIVEN("an approved authorisation")
    {
        auto store = DeviceAuthorisationStore{};
        auto const created = started(store.create(client, scope, device, address, start_ms));
        auto const hold = attached(store.attach(created.user_code, browser, start_ms));
        REQUIRE(store.decide(hold.key, hold.attachment, "@alice:example.org", "stamp", true, start_ms));

        WHEN("another client polls with its device code, and a made-up code is polled")
        {
            auto const wrong = store.poll(created.device_code, other_client, start_ms + 5'000U);
            auto const unknown = store.poll("not-a-device-code", client, start_ms + 5'000U);

            THEN("the other client is wrong_client, the made-up code expired_token, and the entry stays")
            {
                REQUIRE(wrong.outcome == PollOutcome::wrong_client);
                REQUIRE_FALSE(wrong.authorisation.has_value());
                REQUIRE(unknown.outcome == PollOutcome::expired_token);
                REQUIRE(store.size() == 1U);
            }
        }

        WHEN("its client polls twice")
        {
            auto const first = store.poll(created.device_code, client, start_ms + 5'000U);
            auto const second = store.poll(created.device_code, client, start_ms + 10'000U);

            THEN("the first redeems it with the user, and the second hears expired_token")
            {
                REQUIRE(first.outcome == PollOutcome::approved);
                REQUIRE(first.authorisation.has_value());
                REQUIRE(first.authorisation->user_id == "@alice:example.org");
                REQUIRE(first.authorisation->device_id == device);
                REQUIRE(first.authorisation->credential_stamp == "stamp");
                REQUIRE(second.outcome == PollOutcome::expired_token);
                REQUIRE(store.size() == 0U);
                REQUIRE_FALSE(store.holds_live_entry_for_client(client, start_ms + 10'000U));
            }
        }
    }

    GIVEN("a denied authorisation")
    {
        auto store = DeviceAuthorisationStore{};
        auto const created = started(store.create(client, scope, device, address, start_ms));
        auto const hold = attached(store.attach(created.user_code, browser, start_ms));
        REQUIRE(store.decide(hold.key, hold.attachment, "@alice:example.org", "stamp", false, start_ms));

        WHEN("its client polls twice, and the code is typed again")
        {
            auto const first = store.poll(created.device_code, client, start_ms + 5'000U);
            auto const second = store.poll(created.device_code, client, start_ms + 10'000U);
            auto const retyped = store.attach(created.user_code, browser, start_ms + 10'000U);

            THEN("both polls hear access_denied, and the answered code is no longer found")
            {
                REQUIRE(first.outcome == PollOutcome::access_denied);
                REQUIRE(second.outcome == PollOutcome::access_denied);
                REQUIRE(std::holds_alternative<DeviceAuthorisationStore::NotFound>(retyped));
            }
        }
    }
}

SCENARIO("One browser at a time holds a device authorisation", "[oauth][oauth-device][security]")
{
    GIVEN("a pending authorisation the first browser holds")
    {
        auto store = DeviceAuthorisationStore{};
        auto const created = started(store.create(client, scope, device, address, start_ms));
        auto const first = attached(store.attach(created.user_code, browser, start_ms));

        WHEN("a second browser types the code within the lease")
        {
            auto const busy = store.attach(created.user_code, second_browser, start_ms + 30'000U);

            THEN("it is busy until the lease ends, and the first browser still holds it")
            {
                REQUIRE(std::holds_alternative<DeviceAuthorisationStore::Busy>(busy));
                REQUIRE(std::get<DeviceAuthorisationStore::Busy>(busy).retry_after_ms == 90'000U);
                REQUIRE(store.find_attached(first.key, first.attachment, start_ms + 30'000U).has_value());
            }
        }

        WHEN("the first browser renews, and the second tries just after the original lease")
        {
            REQUIRE(store.renew(first.key, first.attachment, start_ms + 100'000U));
            auto const busy = store.attach(created.user_code, second_browser,
                                           start_ms + DeviceAuthorisationStore::attachment_lease_ms);

            THEN("the renewed lease still holds it")
            {
                REQUIRE(std::holds_alternative<DeviceAuthorisationStore::Busy>(busy));
            }
        }

        WHEN("the lease lapses and the second browser takes it over")
        {
            auto const lapse = start_ms + DeviceAuthorisationStore::attachment_lease_ms;
            auto const second = attached(store.attach(created.user_code, second_browser, lapse));

            THEN("the first browser can neither renew nor decide, and the second decides")
            {
                REQUIRE_FALSE(store.renew(first.key, first.attachment, lapse));
                REQUIRE_FALSE(store.decide(first.key, first.attachment, "@mallory:example.org", "stamp", true, lapse));
                REQUIRE_FALSE(store.find_attached(first.key, first.attachment, lapse).has_value());
                REQUIRE(store.decide(second.key, second.attachment, "@alice:example.org", "stamp", true, lapse));
                auto const poll = store.poll(created.device_code, client, lapse);
                REQUIRE(poll.outcome == PollOutcome::approved);
                REQUIRE(poll.authorisation->user_id == "@alice:example.org");
            }
        }

        WHEN("the first browser releases it")
        {
            store.release(first.key, first.attachment);
            auto const second = store.attach(created.user_code, second_browser, start_ms + 1'000U);

            THEN("the second browser takes it at once")
            {
                REQUIRE(std::holds_alternative<DeviceAuthorisationStore::Attached>(second));
            }
        }

        WHEN("the first browser types the code again")
        {
            auto const again = attached(store.attach(created.user_code, browser, start_ms + 1'000U));

            THEN("it holds a fresh attachment and the earlier one no longer decides")
            {
                REQUIRE(again.attachment != first.attachment);
                REQUIRE_FALSE(
                    store.decide(first.key, first.attachment, "@alice:example.org", "stamp", true, start_ms + 1'000U));
                REQUIRE(
                    store.decide(again.key, again.attachment, "@alice:example.org", "stamp", true, start_ms + 1'000U));
            }
        }

        WHEN("an empty browser token types the code")
        {
            auto const empty = store.attach(created.user_code, "", start_ms + 200'000U);

            THEN("it is not found")
            {
                REQUIRE(std::holds_alternative<DeviceAuthorisationStore::NotFound>(empty));
            }
        }
    }
}

SCENARIO("Live device authorisations are counted per client for client retention", "[oauth][oauth-device]")
{
    GIVEN("two authorisations for one client, created a minute apart")
    {
        auto store = DeviceAuthorisationStore{};
        std::ignore = started(store.create(client, scope, device, address, start_ms));
        std::ignore = started(store.create(client, scope, device, address, start_ms + 60'000U));

        WHEN("the store is asked before and after the first expires, and after both")
        {
            auto const both = store.live_count_for_client(client, start_ms);
            auto const one = store.live_count_for_client(client, start_ms + DeviceAuthorisationStore::lifetime_ms);
            auto const held =
                store.holds_live_entry_for_client(client, start_ms + DeviceAuthorisationStore::lifetime_ms);
            auto const none_held =
                store.holds_live_entry_for_client(client, start_ms + 60'000U + DeviceAuthorisationStore::lifetime_ms);

            THEN("the counts follow, and another client is never named")
            {
                REQUIRE(both == 2U);
                REQUIRE(one == 1U);
                REQUIRE(held);
                REQUIRE_FALSE(none_held);
                REQUIRE(store.live_count_for_client(other_client, start_ms) == 0U);
                REQUIRE_FALSE(store.holds_live_entry_for_client(other_client, start_ms));
            }
        }
    }
}

SCENARIO("Five wrong user codes from an address block it for the rest of ten minutes",
         "[oauth][oauth-device][security]")
{
    GIVEN("an empty throttle")
    {
        auto throttle = UserCodeAttemptThrottle{};

        WHEN("an address types four wrong codes")
        {
            auto reached = false;
            for (auto attempt = 0U; attempt < 4U; ++attempt)
            {
                reached = throttle.record_wrong(address, start_ms + attempt) || reached;
            }

            THEN("it is not blocked")
            {
                REQUIRE_FALSE(reached);
                REQUIRE_FALSE(throttle.blocked_for_ms(address, start_ms + 4U).has_value());
            }

            AND_WHEN("it types a fifth a minute in")
            {
                auto const fifth = throttle.record_wrong(address, start_ms + 60'000U);

                THEN("the fifth reaches the limit, and the address waits until the window ends")
                {
                    REQUIRE(fifth);
                    REQUIRE(throttle.blocked_for_ms(address, start_ms + 60'000U) ==
                            std::optional<std::uint64_t>{540'000U});
                    REQUIRE(throttle.blocked_for_ms(address, start_ms + 599'999U) == std::optional<std::uint64_t>{1U});
                    REQUIRE_FALSE(throttle.blocked_for_ms(address, start_ms + 600'000U).has_value());
                    REQUIRE_FALSE(throttle.blocked_for_ms("203.0.113.9", start_ms + 60'000U).has_value());
                    REQUIRE_FALSE(throttle.record_wrong(address, start_ms + 70'000U));
                }
            }
        }
    }

    GIVEN("a throttle holding a window for every address it can")
    {
        auto throttle = UserCodeAttemptThrottle{};
        for (auto index = std::size_t{0U}; index < UserCodeAttemptThrottle::max_addresses; ++index)
        {
            std::ignore = throttle.record_wrong(address_number(index), start_ms + index);
        }

        WHEN("an address with no window asks, before and after the oldest window ends")
        {
            auto const before = throttle.blocked_for_ms("fresh-address", start_ms + 1'000U);
            auto const counted = throttle.record_wrong("fresh-address", start_ms + 1'000U);
            auto const after = throttle.blocked_for_ms("fresh-address", start_ms + UserCodeAttemptThrottle::window_ms);

            THEN("it is blocked until the oldest window ends, fails closed, and is let in afterwards")
            {
                REQUIRE(before == std::optional<std::uint64_t>{UserCodeAttemptThrottle::window_ms - 1'000U});
                REQUIRE_FALSE(counted);
                REQUIRE_FALSE(after.has_value());
                REQUIRE(throttle.size() == UserCodeAttemptThrottle::max_addresses - 1U);
            }
        }
    }
}
