// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// Conformance tests for server-side key backups: which of two keys for the same session the
// server keeps.

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto backup_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

struct Reply final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> Reply
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
    return {static_cast<std::uint16_t>(result.response.status), result.response.body};
}

[[nodiscard]] auto register_and_login(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json(localpart, "CorrectHorse7!"))
                .status == 200U);
    auto const login =
        call(rt, "POST", "/_matrix/client/v3/login", {},
             std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                 R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart + R"(_DEV"})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

auto create_backup(ClientServerRuntime& rt, std::string const& token) -> void
{
    REQUIRE(
        call(
            rt, "POST", "/_matrix/client/v3/room_keys/version", token,
            R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})")
            .status == 200U);
}

constexpr auto session_path = "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org/session1?version=1";

[[nodiscard]] auto session_json(std::int64_t first_message_index, std::int64_t forwarded_count, bool is_verified,
                                std::string const& ciphertext) -> std::string
{
    return std::string{R"({"first_message_index":)"} + std::to_string(first_message_index) + R"(,"forwarded_count":)" +
           std::to_string(forwarded_count) + R"(,"is_verified":)" + (is_verified ? "true" : "false") +
           R"(,"session_data":{"ciphertext":")" + ciphertext + R"(","ephemeral":"def","mac":"ghi"}})";
}

// The ciphertext of the key the server holds for the session, which says which upload it kept.
[[nodiscard]] auto stored_ciphertext(ClientServerRuntime& rt, std::string const& token) -> std::string
{
    auto const reply = call(rt, "GET", session_path, token);
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* data = object_member_as_object(parsed, "session_data");
    REQUIRE(data != nullptr);
    auto const* ciphertext = string_member(*data, "ciphertext");
    REQUIRE(ciphertext != nullptr);
    return *ciphertext;
}

struct Key final
{
    std::int64_t first_message_index{0};
    std::int64_t forwarded_count{0};
    bool is_verified{false};
};

// Uploads `held` and then `offered` for the same session, and returns the ciphertext the server
// kept: "held" or "offered".
[[nodiscard]] auto kept_after_upload(Key held, Key offered, bool as_batch = false) -> std::string
{
    auto started = merovingian::homeserver::start_client_server(backup_config());
    REQUIRE(started.started);
    auto& rt = started.runtime;
    auto const token = register_and_login(rt, "alice");
    create_backup(rt, token);
    REQUIRE(call(rt, "PUT", session_path, token,
                 session_json(held.first_message_index, held.forwarded_count, held.is_verified, "held"))
                .status == 200U);
    auto const offer_body =
        session_json(offered.first_message_index, offered.forwarded_count, offered.is_verified, "offered");
    auto const reply = as_batch
                           ? call(rt, "PUT", "/_matrix/client/v3/room_keys/keys?version=1", token,
                                  R"({"rooms":{"!room1:example.org":{"sessions":{"session1":)" + offer_body + "}}}}")
                           : call(rt, "PUT", session_path, token, offer_body);
    REQUIRE(reply.status == 200U);
    return stored_ciphertext(rt, token);
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Server-side key backups
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#server-side-key-backups
//
// "When a client uploads a key for a session that the server already has a key for, the server
// will choose to either keep the existing key or replace it with the one just uploaded, based on the key
// metadata as follows: if the keys have different values for `is_verified`, then it will keep the
// key that has `is_verified` set to `true`; if they have the same values for `is_verified`, then
// it will keep the key with a lower `first_message_index`; and finally, if `is_verified` and
// `first_message_index` are equal, then it will keep the key with a lower `forwarded_count`."
SCENARIO("A key upload for a session the server holds keeps the better key",
         "[conformance][client-server][e2ee][key-backup][run10]")
{
    GIVEN("a backup that holds a key for a session")
    {
        WHEN("an unverified key with a lower first_message_index is uploaded over an unverified one")
        {
            // Spec: "...the key with a lower `first_message_index`".
            THEN("the offered key replaces the held one")
            {
                REQUIRE(kept_after_upload({11, 5, false}, {10, 5, false}) == "offered");
            }
        }

        WHEN("a verified key with a lower first_message_index is uploaded over a verified one")
        {
            THEN("the offered key replaces the held one")
            {
                REQUIRE(kept_after_upload({11, 5, true}, {10, 5, true}) == "offered");
            }
        }

        WHEN("an unverified key with a higher first_message_index is uploaded over an unverified one")
        {
            THEN("the held key is kept")
            {
                REQUIRE(kept_after_upload({10, 5, false}, {11, 5, false}) == "held");
            }
        }

        WHEN("a verified key with a higher first_message_index is uploaded over an unverified one")
        {
            // Spec: "if the keys have different values for `is_verified`, then it will keep the
            // key that has `is_verified` set to `true`".
            THEN("the verified key wins whatever its first_message_index")
            {
                REQUIRE(kept_after_upload({10, 5, false}, {11, 5, true}) == "offered");
            }
        }

        WHEN("an unverified key with a lower first_message_index is uploaded over a verified one")
        {
            THEN("the held verified key is kept")
            {
                REQUIRE(kept_after_upload({11, 5, true}, {10, 5, false}) == "held");
            }
        }

        WHEN("keys that differ only in forwarded_count are uploaded")
        {
            // Spec: "if `is_verified` and `first_message_index` are equal, then it will keep the
            // key with a lower `forwarded_count`".
            THEN("the lower forwarded_count is kept")
            {
                REQUIRE(kept_after_upload({10, 5, false}, {10, 2, false}) == "offered");
                REQUIRE(kept_after_upload({10, 2, false}, {10, 5, false}) == "held");
            }
        }

        WHEN("the better key is uploaded through the whole-backup endpoint")
        {
            THEN("the same rule applies")
            {
                REQUIRE(kept_after_upload({11, 5, false}, {10, 5, false}, true) == "offered");
                REQUIRE(kept_after_upload({10, 5, false}, {11, 5, false}, true) == "held");
            }
        }
    }
}
