// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The five security.encryption.* settings are enforced in createRoom, and only through
// rooms::room_creation_encryption_policy. The Matrix API has no way to ask for an unencrypted
// room, so a request is read from initial_state: the last m.room.encryption entry with an empty
// state key. Anything but algorithm m.megolm.v1.aes-sha2 in it is "unencrypted" (fail closed).
//
// Spec: CS API v1.19, POST /createRoom. `initial_state` events are sent "in the order that they
// are listed" (so the last entry for a state key is the room's state), and 400 M_INVALID_ROOM_STATE
// is "The initial state implied by the parameters to the createRoom request is invalid".
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/EncryptionSecurityConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/rooms/encryption_policy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>

#include <cstdint>
#include <initializer_list>
#include <string>
#include <utility>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;
namespace rooms = merovingian::rooms;
namespace config = merovingian::config;

constexpr auto megolm = "m.megolm.v1.aes-sha2";

[[nodiscard]] auto policy_config(config::EncryptionSecurityConfig encryption, bool federation_enabled = true)
    -> config::Config
{
    auto security = config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.encryption = encryption;
    security.federation.enabled = federation_enabled;
    return {
        config::ServerConfig{},
        config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        config::ClientRateLimitsConfig{},
        config::LogModulesConfig{},
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

[[nodiscard]] auto register_and_login(ClientServerRuntime& rt) -> std::string
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json("alice", "CorrectHorse7!"))
                .status == 200U);
    auto const login =
        call(rt, "POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},)"
             R"("password":"CorrectHorse7!","device_id":"ALICE_DEV"})");
    REQUIRE(login.status == 200U);
    return *string_member(parse_object(login.body), "access_token");
}

[[nodiscard]] auto create(ClientServerRuntime& rt, std::string const& token, std::string const& body) -> Reply
{
    return call(rt, "POST", "/_matrix/client/v3/createRoom", token, body);
}

[[nodiscard]] auto room_id_of(Reply const& created) -> std::string
{
    REQUIRE(created.status == 200U);
    return *string_member(parse_object(created.body), "room_id");
}

// The algorithm of the room's m.room.encryption state with the empty state key, or "" if none.
[[nodiscard]] auto encryption_algorithm(ClientServerRuntime& rt, std::string const& token, std::string const& room_id)
    -> std::string
{
    auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.encryption/", token);
    if (reply.status != 200U)
    {
        return {};
    }
    auto const content = parse_object(reply.body);
    auto const* algorithm = string_member(content, "algorithm");
    return algorithm == nullptr ? std::string{} : *algorithm;
}

[[nodiscard]] auto is_encrypted(ClientServerRuntime& rt, std::string const& token, std::string const& room_id) -> bool
{
    return encryption_algorithm(rt, token, room_id) == megolm;
}

[[nodiscard]] auto entry(std::string const& state_key_json, std::string const& content_json) -> std::string
{
    return R"({"type":"m.room.encryption",)" + state_key_json + R"("content":)" + content_json + "}";
}

[[nodiscard]] auto good_entry() -> std::string
{
    return entry(R"("state_key":"",)", R"({"algorithm":"m.megolm.v1.aes-sha2"})");
}

[[nodiscard]] auto bad_entry() -> std::string
{
    return entry(R"("state_key":"",)", R"({"algorithm":"none"})");
}

[[nodiscard]] auto body_with(std::string const& preset, std::initializer_list<std::string> entries,
                             std::string const& extra = {}) -> std::string
{
    auto list = std::string{};
    for (auto const& item : entries)
    {
        list += (list.empty() ? "" : ",") + item;
    }
    return R"({"preset":")" + preset + R"(","initial_state":[)" + list + "]" + extra + "}";
}

void require_refused_and_nothing_stored(ClientServerRuntime& rt, Reply const& reply, std::size_t rooms_before)
{
    CAPTURE(reply.body);
    REQUIRE(reply.status == 400U);
    REQUIRE(*string_member(parse_object(reply.body), "errcode") == "M_INVALID_ROOM_STATE");
    REQUIRE(rt.homeserver.database.persistent_store.rooms.size() == rooms_before);
}

} // namespace

SCENARIO("Default settings encrypt private and direct rooms and leave plain public rooms alone",
         "[homeserver][rooms][create-room][encryption-policy]")
{
    GIVEN("a server with the default encryption settings and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(policy_config({}));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt);

        WHEN("it creates a private_chat, a trusted_private_chat and a direct room without asking for encryption")
        {
            auto const private_room = room_id_of(create(rt, token, R"({"preset":"private_chat"})"));
            auto const trusted_room = room_id_of(create(rt, token, R"({"preset":"trusted_private_chat"})"));
            auto const direct_room = room_id_of(create(rt, token, R"({"preset":"public_chat","is_direct":true})"));

            THEN("each has megolm encryption in its state")
            {
                REQUIRE(is_encrypted(rt, token, private_room));
                REQUIRE(is_encrypted(rt, token, trusted_room));
                REQUIRE(is_encrypted(rt, token, direct_room));
            }
        }

        WHEN("it creates a public room that is not direct")
        {
            auto const public_room = room_id_of(create(rt, token, R"({"preset":"public_chat"})"));

            THEN("the room has no encryption")
            {
                REQUIRE(encryption_algorithm(rt, token, public_room).empty());
            }
        }

        WHEN("it creates a room with a preset the server does not know")
        {
            auto const room = room_id_of(create(rt, token, R"({"preset":"made_up_preset"})"));

            THEN("the room is treated as private, never as public, and is encrypted")
            {
                REQUIRE(is_encrypted(rt, token, room));
            }
        }
    }
}

SCENARIO("Default settings refuse an explicitly unencrypted private or direct room before storing anything",
         "[homeserver][rooms][create-room][encryption-policy]")
{
    GIVEN("a server with the default encryption settings and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(policy_config({}));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt);
        auto const rooms_before = rt.homeserver.database.persistent_store.rooms.size();
        auto const events_before = rt.homeserver.database.persistent_store.events.size();

        auto const body = GENERATE_COPY(
            as<std::string>{}, body_with("private_chat", {bad_entry()}),
            body_with("trusted_private_chat", {bad_entry()}),
            body_with("public_chat", {bad_entry()}, R"(,"is_direct":true)"),
            // Fail closed: a missing algorithm, a non-string algorithm and empty content are all "unencrypted".
            body_with("private_chat", {entry(R"("state_key":"",)", "{}")}),
            body_with("private_chat", {entry(R"("state_key":"",)", R"({"algorithm":5})")}),
            body_with("private_chat", {entry(R"("state_key":"",)", R"({"algorithm":"m.megolm.v2"})")}),
            // An absent state_key is the empty state key.
            body_with("private_chat", {entry("", R"({"algorithm":"none"})")}),
            body_with("made_up_preset", {bad_entry()}));

        WHEN("it asks for such a room")
        {
            auto const reply = create(rt, token, body);

            THEN("the request is 400 M_INVALID_ROOM_STATE and no room or event is stored")
            {
                CAPTURE(body);
                require_refused_and_nothing_stored(rt, reply, rooms_before);
                REQUIRE(rt.homeserver.database.persistent_store.events.size() == events_before);
            }
        }
    }
}

SCENARIO("An m.room.encryption entry with a non-empty state key does not cancel default encryption",
         "[homeserver][rooms][create-room][encryption-policy]")
{
    GIVEN("a server with the default encryption settings and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(policy_config({}));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt);

        WHEN("a private room is created with an encryption entry under state key \"x\"")
        {
            auto const room = room_id_of(create(
                rt, token, body_with("private_chat", {entry(R"("state_key":"x",)", R"({"algorithm":"none"})")})));

            THEN("the room is still encrypted under the empty state key")
            {
                REQUIRE(is_encrypted(rt, token, room));
            }
        }

        WHEN("a private room is created with an empty-content encryption entry under state key \"x\"")
        {
            auto const room =
                room_id_of(create(rt, token, body_with("private_chat", {entry(R"("state_key":"x",)", "{}")})));

            THEN("the room is still encrypted under the empty state key")
            {
                REQUIRE(is_encrypted(rt, token, room));
            }
        }
    }
}

SCENARIO("The last empty-state-key encryption entry is the one the policy judges and the room keeps",
         "[homeserver][rooms][create-room][encryption-policy]")
{
    GIVEN("a server with the default encryption settings and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(policy_config({}));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt);

        WHEN("a good entry is followed by a bad one")
        {
            auto const rooms_before = rt.homeserver.database.persistent_store.rooms.size();
            auto const reply = create(rt, token, body_with("private_chat", {good_entry(), bad_entry()}));

            THEN("the bad one is judged and the request is refused")
            {
                require_refused_and_nothing_stored(rt, reply, rooms_before);
            }
        }

        WHEN("a bad entry is followed by a good one")
        {
            auto const room = room_id_of(create(rt, token, body_with("private_chat", {bad_entry(), good_entry()})));

            THEN("the good one is judged and is the room's state")
            {
                REQUIRE(is_encrypted(rt, token, room));
            }
        }

        WHEN("a bad entry under another state key follows a good one")
        {
            auto const room = room_id_of(create(
                rt, token,
                body_with("private_chat", {good_entry(), entry(R"("state_key":"x",)", R"({"algorithm":"none"})")})));

            THEN("it does not count and the room is encrypted")
            {
                REQUIRE(is_encrypted(rt, token, room));
            }
        }
    }
}

SCENARIO("allow_unencrypted_public_rooms=false makes public rooms encrypted",
         "[homeserver][rooms][create-room][encryption-policy]")
{
    GIVEN("a server that does not allow unencrypted public rooms")
    {
        auto settings = config::EncryptionSecurityConfig{};
        settings.allow_unencrypted_public_rooms = false;
        auto started = merovingian::homeserver::start_client_server(policy_config(settings));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt);

        WHEN("a public room is created without asking for encryption")
        {
            auto const room = room_id_of(create(rt, token, R"({"preset":"public_chat"})"));

            THEN("it is encrypted")
            {
                REQUIRE(is_encrypted(rt, token, room));
            }
        }

        WHEN("a public room explicitly asks to be unencrypted")
        {
            auto const rooms_before = rt.homeserver.database.persistent_store.rooms.size();
            auto const reply = create(rt, token, body_with("public_chat", {bad_entry()}));

            THEN("the request is refused and nothing is stored")
            {
                require_refused_and_nothing_stored(rt, reply, rooms_before);
            }
        }
    }
}

SCENARIO("require_for_private_rooms=false lets an explicitly unencrypted private room be created",
         "[homeserver][rooms][create-room][encryption-policy]")
{
    GIVEN("a server that does not require encryption for private rooms or for federated private rooms")
    {
        auto settings = config::EncryptionSecurityConfig{};
        settings.require_for_private_rooms = false;
        settings.block_unencrypted_federated_private_rooms = false;
        auto started = merovingian::homeserver::start_client_server(policy_config(settings));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt);

        WHEN("a private room explicitly asks to be unencrypted")
        {
            auto const room = room_id_of(create(rt, token, body_with("private_chat", {bad_entry()})));

            THEN("it is created and has no working encryption")
            {
                REQUIRE_FALSE(is_encrypted(rt, token, room));
            }
        }

        WHEN("a private room does not mention encryption")
        {
            auto const room = room_id_of(create(rt, token, R"({"preset":"private_chat"})"));

            THEN("default_for_new_rooms still encrypts it")
            {
                REQUIRE(is_encrypted(rt, token, room));
            }
        }

        WHEN("a direct room explicitly asks to be unencrypted")
        {
            auto const rooms_before = rt.homeserver.database.persistent_store.rooms.size();
            auto const reply = create(rt, token, body_with("private_chat", {bad_entry()}, R"(,"is_direct":true)"));

            THEN("it is still refused, direct messages being required")
            {
                require_refused_and_nothing_stored(rt, reply, rooms_before);
            }
        }
    }
}

SCENARIO("block_unencrypted_federated_private_rooms applies only to rooms that can federate",
         "[homeserver][rooms][create-room][encryption-policy]")
{
    GIVEN("a server that blocks unencrypted federated private rooms but does not require encryption otherwise")
    {
        auto settings = config::EncryptionSecurityConfig{};
        settings.require_for_private_rooms = false;
        settings.block_unencrypted_federated_private_rooms = true;
        auto started = merovingian::homeserver::start_client_server(policy_config(settings));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt);

        WHEN("an unencrypted private room can federate")
        {
            auto const rooms_before = rt.homeserver.database.persistent_store.rooms.size();
            auto const reply = create(rt, token, body_with("private_chat", {bad_entry()}));

            THEN("it is refused")
            {
                require_refused_and_nothing_stored(rt, reply, rooms_before);
            }
        }

        WHEN("an unencrypted private room sets m.federate to a non-boolean")
        {
            auto const rooms_before = rt.homeserver.database.persistent_store.rooms.size();
            auto const reply = create(
                rt, token, body_with("private_chat", {bad_entry()}, R"(,"creation_content":{"m.federate":"false"})"));

            THEN("it counts as federated (the create-event auth rule only honours boolean false) and is refused")
            {
                require_refused_and_nothing_stored(rt, reply, rooms_before);
            }
        }

        WHEN("an unencrypted private room sets m.federate to false")
        {
            auto const room = room_id_of(create(
                rt, token, body_with("private_chat", {bad_entry()}, R"(,"creation_content":{"m.federate":false})")));

            THEN("it is created, because it cannot federate")
            {
                REQUIRE_FALSE(is_encrypted(rt, token, room));
            }
        }
    }

    GIVEN("a server with federation switched off")
    {
        auto settings = config::EncryptionSecurityConfig{};
        settings.require_for_private_rooms = false;
        auto started = merovingian::homeserver::start_client_server(policy_config(settings, false));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt);

        WHEN("a private room explicitly asks to be unencrypted")
        {
            auto const room = room_id_of(create(rt, token, body_with("private_chat", {bad_entry()})));

            THEN("it is created, because no room here can federate")
            {
                REQUIRE_FALSE(is_encrypted(rt, token, room));
            }
        }
    }
}

namespace
{

// The decision table, written out independently of the implementation.
struct Expected final
{
    bool required{false};
    bool by_default{false};
    bool allowed{false};
    bool enabled{false};
};

[[nodiscard]] auto expected_for(rooms::RoomCreationEncryptionRequest const& request) -> Expected
{
    auto const& s = request.settings;
    auto const is_private = request.preset != rooms::RoomPreset::public_chat;
    auto const is_public = !is_private;
    auto const required = (request.direct_message && s.require_for_direct_messages) ||
                          (is_private && s.require_for_private_rooms) ||
                          (is_public && !s.allow_unencrypted_public_rooms) ||
                          (request.federated && is_private && s.block_unencrypted_federated_private_rooms);
    auto const by_default = s.default_for_new_rooms && (is_private || request.direct_message);
    switch (request.encryption)
    {
    case rooms::RoomEncryptionRequest::unspecified:
        return {required, by_default, true, required || by_default};
    case rooms::RoomEncryptionRequest::encrypted:
        return {required, by_default, true, true};
    case rooms::RoomEncryptionRequest::unencrypted:
        return {required, by_default, !required, false};
    }
    return {};
}

} // namespace

SCENARIO("The creation encryption policy decides every combination of the five settings",
         "[rooms][encryption][encryption-policy]")
{
    GIVEN("every preset, direct flag, federation flag, request and setting combination")
    {
        auto const preset = GENERATE(rooms::RoomPreset::public_chat, rooms::RoomPreset::private_chat,
                                     rooms::RoomPreset::trusted_private_chat);
        auto const direct = GENERATE(false, true);
        auto const federated = GENERATE(false, true);
        auto const encryption =
            GENERATE(rooms::RoomEncryptionRequest::unspecified, rooms::RoomEncryptionRequest::encrypted,
                     rooms::RoomEncryptionRequest::unencrypted);
        auto const settings_bits = GENERATE(range(0, 32));
        auto settings = config::EncryptionSecurityConfig{};
        settings.default_for_new_rooms = (settings_bits & 1) != 0;
        settings.require_for_direct_messages = (settings_bits & 2) != 0;
        settings.require_for_private_rooms = (settings_bits & 4) != 0;
        settings.allow_unencrypted_public_rooms = (settings_bits & 8) != 0;
        settings.block_unencrypted_federated_private_rooms = (settings_bits & 16) != 0;
        auto const request = rooms::RoomCreationEncryptionRequest{preset, direct, federated, encryption, settings};

        WHEN("the policy is evaluated")
        {
            auto const decision = rooms::room_creation_encryption_policy(request);

            THEN("it follows the decision table, and a refusal always says why")
            {
                auto const expected = expected_for(request);
                CAPTURE(static_cast<int>(preset), direct, federated, static_cast<int>(encryption), settings_bits);
                REQUIRE(decision.allowed == expected.allowed);
                REQUIRE(decision.encryption_required == expected.required);
                REQUIRE(decision.encryption_enabled_by_default == expected.by_default);
                REQUIRE(decision.encryption_enabled == expected.enabled);
                REQUIRE(decision.reason.empty() == decision.allowed);
            }
        }
    }
}

SCENARIO("A refusal names the setting that required encryption", "[rooms][encryption][encryption-policy]")
{
    GIVEN("a request for an unencrypted room and settings that each demand encryption alone")
    {
        auto none = config::EncryptionSecurityConfig{false, false, false, true, false};

        WHEN("only direct-message encryption is required")
        {
            none.require_for_direct_messages = true;
            auto const decision = rooms::room_creation_encryption_policy(
                {rooms::RoomPreset::public_chat, true, false, rooms::RoomEncryptionRequest::unencrypted, none});
            THEN("the reason is the direct-message one")
            {
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.reason == "direct messages must be encrypted");
            }
        }

        WHEN("only private rooms are required to be encrypted")
        {
            none.require_for_private_rooms = true;
            auto const decision = rooms::room_creation_encryption_policy(
                {rooms::RoomPreset::private_chat, false, false, rooms::RoomEncryptionRequest::unencrypted, none});
            THEN("the reason is the private-room one")
            {
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.reason == "private rooms must be encrypted");
            }
        }

        WHEN("only unencrypted public rooms are disallowed")
        {
            none.allow_unencrypted_public_rooms = false;
            auto const decision = rooms::room_creation_encryption_policy(
                {rooms::RoomPreset::public_chat, false, false, rooms::RoomEncryptionRequest::unencrypted, none});
            THEN("the reason is the public-room one")
            {
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.reason == "public rooms must be encrypted");
            }
        }

        WHEN("only unencrypted federated private rooms are blocked")
        {
            none.block_unencrypted_federated_private_rooms = true;
            auto const decision = rooms::room_creation_encryption_policy(
                {rooms::RoomPreset::private_chat, false, true, rooms::RoomEncryptionRequest::unencrypted, none});
            THEN("the reason is the federated private-room one")
            {
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.reason == "federated private rooms must be encrypted");
            }
        }
    }
}
