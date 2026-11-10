// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// GHSA-3p9g-gpvx-2cx9 (ADR-0594): a device keeps one fallback key per algorithm, and the algorithms it may hold are
// capped by server.client_api.max_fallback_keys_per_device. Before the cap, every distinct key-ID prefix added a row
// that was persisted, held in memory and scanned by /sync and /keys/claim. Same policy as CSAZ-10: an over-cap upload
// is refused with M_TOO_LARGE, nothing from it is stored, and nothing is evicted.

#include "../support/e2ee_caps_support.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using merovingian::tests::caps_config;
using merovingian::tests::register_and_login_alice;

// {"fallback_keys":{"<id>":"value-<id>",...}} with each key ID as given; extra members go before it.
[[nodiscard]] auto fallback_keys_body(std::initializer_list<std::string_view> key_ids,
                                      std::string_view extra_members = {}) -> std::string
{
    auto body = std::string{R"({)"};
    if (!extra_members.empty())
    {
        body += std::string{extra_members} + ",";
    }
    body += R"("fallback_keys":{)";
    auto first = true;
    for (auto const key_id : key_ids)
    {
        if (!first)
        {
            body += ",";
        }
        first = false;
        body += "\"" + std::string{key_id} + "\":\"value-" + std::string{key_id} + "\"";
    }
    body += "}}";
    return body;
}

// The (key ID, JSON) pairs held for every device, sorted, so a refused request can be shown to change nothing.
[[nodiscard]] auto stored_fallback_keys(merovingian::homeserver::ClientServerRuntime const& runtime)
    -> std::vector<std::pair<std::string, std::string>>
{
    auto rows = std::vector<std::pair<std::string, std::string>>{};
    for (auto const& key : runtime.homeserver.database.persistent_store.fallback_keys)
    {
        rows.emplace_back(key.key_id, key.json);
    }
    std::ranges::sort(rows);
    return rows;
}

[[nodiscard]] auto upload(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                          std::string body) -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/keys/upload", token, std::move(body)});
}

[[nodiscard]] auto capped_runtime_config(std::uint32_t fallback_keys) -> merovingian::config::Config
{
    auto config = caps_config(100U, 100U, 100U);
    config.server().client_api.max_fallback_keys_per_device = fallback_keys;
    return config;
}

} // namespace

SCENARIO("/keys/upload refuses fallback keys of more algorithms than the per-device cap and stores nothing",
         "[ghsa-3p9g][fallback-key-cap][e2ee][homeserver][client-server][limits]")
{
    GIVEN("a runtime capped at 3 fallback-key algorithms per device and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(capped_runtime_config(3U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);

        WHEN("keys of exactly 3 distinct algorithms are uploaded")
        {
            auto const response = upload(runtime, token, fallback_keys_body({"alg0:K", "alg1:K", "alg2:K"}));

            THEN("the upload is accepted at the cap and all three are stored")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(stored_fallback_keys(runtime).size() == 3U);
            }
        }

        WHEN("keys of 4 distinct algorithms are uploaded in one request")
        {
            auto const response = upload(runtime, token, fallback_keys_body({"alg0:K", "alg1:K", "alg2:K", "alg3:K"}));

            THEN("it is refused with M_TOO_LARGE and no fallback key is stored")
            {
                REQUIRE(response.response.status == 400U);
                REQUIRE(response.response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(stored_fallback_keys(runtime).empty());
            }
        }

        WHEN("the device is at the cap and a 4th algorithm arrives in a later request with device and one-time keys")
        {
            REQUIRE(upload(runtime, token, fallback_keys_body({"alg0:K", "alg1:K", "alg2:K"})).response.status == 200U);
            auto const before = stored_fallback_keys(runtime);
            auto const response = upload(
                runtime, token,
                fallback_keys_body(
                    {"alg3:K"},
                    R"("device_keys":{"user_id":"@alice:example.org","device_id":"DEVICE1","algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:DEVICE1":"CURVE","ed25519:DEVICE1":"ED"}},"one_time_keys":{"curve25519:OTK":"otk"})"));

            THEN("it is refused with M_TOO_LARGE and nothing from the request is stored")
            {
                REQUIRE(response.response.status == 400U);
                REQUIRE(response.response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(stored_fallback_keys(runtime) == before);
                auto const& store = runtime.homeserver.database.persistent_store;
                REQUIRE(store.device_keys.empty());
                REQUIRE(store.one_time_keys.empty());
            }
        }

        WHEN("the device is at the cap and uploads a new key for an algorithm it already holds")
        {
            REQUIRE(upload(runtime, token, fallback_keys_body({"alg0:K", "alg1:K", "alg2:K"})).response.status == 200U);
            auto const response = upload(runtime, token, fallback_keys_body({"alg1:NEW"}));

            THEN("the replacement is accepted and the old key of that algorithm is gone")
            {
                REQUIRE(response.response.status == 200U);
                auto const stored = stored_fallback_keys(runtime);
                REQUIRE(stored.size() == 3U);
                REQUIRE(std::ranges::any_of(stored, [](auto const& row) {
                    return row.first == "alg1:NEW";
                }));
                REQUIRE(std::ranges::none_of(stored, [](auto const& row) {
                    return row.first == "alg1:K";
                }));
            }
        }

        WHEN("one request names two keys of the same algorithm alongside two other algorithms")
        {
            auto const response = upload(runtime, token, fallback_keys_body({"alg0:A", "alg0:B", "alg1:K", "alg2:K"}));

            THEN(
                "the repeated algorithm counts once, the upload is accepted and the device holds one key per algorithm")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(stored_fallback_keys(runtime).size() == 3U);
            }
        }
    }
}

SCENARIO("A device already holding more fallback-key algorithms than the cap can replace them but add none",
         "[ghsa-3p9g][fallback-key-cap][e2ee][homeserver][client-server][limits]")
{
    GIVEN("a device holding keys of 3 algorithms, and then the cap lowered to 2 as a restart with a lower cap would")
    {
        auto started = merovingian::homeserver::start_client_server(capped_runtime_config(3U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);
        REQUIRE(upload(runtime, token, fallback_keys_body({"alg0:K", "alg1:K", "alg2:K"})).response.status == 200U);
        runtime.limits.max_fallback_keys_per_device = 2U;

        WHEN("the device uploads new keys for two algorithms it already holds")
        {
            auto const response = upload(runtime, token, fallback_keys_body({"alg0:NEW", "alg2:NEW"}));

            THEN("the replacements are accepted, so the device can still rotate its keys above the cap")
            {
                REQUIRE(response.response.status == 200U);
                auto const stored = stored_fallback_keys(runtime);
                REQUIRE(stored.size() == 3U);
                REQUIRE(std::ranges::any_of(stored, [](auto const& row) {
                    return row.first == "alg0:NEW";
                }));
                REQUIRE(std::ranges::any_of(stored, [](auto const& row) {
                    return row.first == "alg2:NEW";
                }));
            }
        }

        WHEN("the device uploads a replacement together with a key of an algorithm it does not hold")
        {
            auto const before = stored_fallback_keys(runtime);
            auto const response = upload(runtime, token, fallback_keys_body({"alg0:NEW", "alg3:K"}));

            THEN("it is refused with M_TOO_LARGE and not even the replacement is stored")
            {
                REQUIRE(response.response.status == 400U);
                REQUIRE(response.response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(stored_fallback_keys(runtime) == before);
            }
        }
    }
}

SCENARIO("The fallback-key cap is per device, so another device's keys are not counted",
         "[ghsa-3p9g][fallback-key-cap][e2ee][homeserver][client-server][limits]")
{
    GIVEN("a runtime capped at 2 fallback-key algorithms per device, and a second device of the user holding 2")
    {
        auto started = merovingian::homeserver::start_client_server(capped_runtime_config(2U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);
        auto const second_login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE2"})"});
        REQUIRE(second_login.response.status == 200U);
        auto const second_token = merovingian::tests::access_token_from(second_login.response.body);
        REQUIRE(upload(runtime, second_token, fallback_keys_body({"alg8:K", "alg9:K"})).response.status == 200U);

        WHEN("the first device uploads keys of 2 other algorithms")
        {
            auto const response = upload(runtime, token, fallback_keys_body({"alg0:K", "alg1:K"}));

            THEN("it is accepted, because only the first device's own algorithms count")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(stored_fallback_keys(runtime).size() == 4U);
            }
        }

        WHEN("the first device uploads keys of 3 algorithms")
        {
            auto const response = upload(runtime, token, fallback_keys_body({"alg0:K", "alg1:K", "alg2:K"}));

            THEN("it is refused at its own cap and the second device's keys are untouched")
            {
                REQUIRE(response.response.status == 400U);
                REQUIRE(response.response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(stored_fallback_keys(runtime).size() == 2U);
            }
        }
    }
}
