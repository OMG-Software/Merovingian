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
#include "merovingian/rooms/RoomCreationEncryptionRequest.hpp"
#include "merovingian/rooms/RoomEncryptionRequest.hpp"
#include "merovingian/rooms/RoomPreset.hpp"
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
namespace rooms = merovingian::rooms;
namespace config = merovingian::config;

} // namespace

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
