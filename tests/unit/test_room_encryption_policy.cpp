// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/rooms/encryption_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Room creation policy defaults private rooms and DMs to encrypted", "[rooms][encryption]")
{
    GIVEN("private room and direct-message creation requests without explicit encryption")
    {
        auto const private_room = merovingian::rooms::RoomCreationEncryptionRequest{
            merovingian::rooms::RoomPreset::private_chat,
            false,
            false,
            merovingian::rooms::RoomEncryptionRequest::unspecified,
        };
        auto const direct_message = merovingian::rooms::RoomCreationEncryptionRequest{
            merovingian::rooms::RoomPreset::private_chat,
            true,
            false,
            merovingian::rooms::RoomEncryptionRequest::unspecified,
        };

        WHEN("room creation encryption policy is evaluated")
        {
            auto const private_decision = merovingian::rooms::room_creation_encryption_policy(private_room);
            auto const dm_decision = merovingian::rooms::room_creation_encryption_policy(direct_message);

            THEN("both are allowed and encrypted by default")
            {
                REQUIRE(private_decision.allowed);
                REQUIRE(private_decision.encryption_required);
                REQUIRE(private_decision.encryption_enabled_by_default);
                REQUIRE(private_decision.encryption_enabled);
                REQUIRE(dm_decision.allowed);
                REQUIRE(dm_decision.encryption_required);
                REQUIRE(dm_decision.encryption_enabled_by_default);
                REQUIRE(dm_decision.encryption_enabled);
            }
        }
    }
}

SCENARIO("Room creation policy rejects explicit unencrypted private rooms and DMs", "[rooms][encryption]")
{
    GIVEN("private, federated-private, and direct-message requests that explicitly disable encryption")
    {
        auto const private_room = merovingian::rooms::RoomCreationEncryptionRequest{
            merovingian::rooms::RoomPreset::private_chat,
            false,
            false,
            merovingian::rooms::RoomEncryptionRequest::unencrypted,
        };
        auto const federated_private_room = merovingian::rooms::RoomCreationEncryptionRequest{
            merovingian::rooms::RoomPreset::private_chat,
            false,
            true,
            merovingian::rooms::RoomEncryptionRequest::unencrypted,
        };
        auto const direct_message = merovingian::rooms::RoomCreationEncryptionRequest{
            merovingian::rooms::RoomPreset::private_chat,
            true,
            false,
            merovingian::rooms::RoomEncryptionRequest::unencrypted,
        };

        WHEN("room creation encryption policy is evaluated")
        {
            auto const private_decision = merovingian::rooms::room_creation_encryption_policy(private_room);
            auto const federated_private_decision =
                merovingian::rooms::room_creation_encryption_policy(federated_private_room);
            auto const dm_decision = merovingian::rooms::room_creation_encryption_policy(direct_message);

            THEN("all required-encryption requests fail closed")
            {
                REQUIRE_FALSE(private_decision.allowed);
                REQUIRE(private_decision.reason == "private rooms must be encrypted");
                REQUIRE_FALSE(federated_private_decision.allowed);
                REQUIRE(federated_private_decision.reason == "federated private rooms must be encrypted");
                REQUIRE_FALSE(dm_decision.allowed);
                REQUIRE(dm_decision.reason == "direct messages must be encrypted");
            }
        }
    }
}

SCENARIO("Room creation policy permits unencrypted public rooms only when explicitly public", "[rooms][encryption]")
{
    GIVEN("a public room request that explicitly disables encryption")
    {
        auto const public_room = merovingian::rooms::RoomCreationEncryptionRequest{
            merovingian::rooms::RoomPreset::public_chat,
            false,
            false,
            merovingian::rooms::RoomEncryptionRequest::unencrypted,
        };

        WHEN("room creation encryption policy is evaluated")
        {
            auto const decision = merovingian::rooms::room_creation_encryption_policy(public_room);

            THEN("the public room can remain unencrypted")
            {
                REQUIRE(decision.allowed);
                REQUIRE_FALSE(decision.encryption_required);
                REQUIRE_FALSE(decision.encryption_enabled_by_default);
                REQUIRE_FALSE(decision.encryption_enabled);
            }
        }
    }
}

SCENARIO("Encrypted event log summaries never include encrypted payload content", "[rooms][encryption][logging]")
{
    GIVEN("an encrypted event payload")
    {
        auto constexpr payload = "ciphertext-and-session-material";

        WHEN("the payload is evaluated for logging and summarized")
        {
            auto const loggable = merovingian::rooms::encrypted_event_payload_is_loggable(payload);
            auto const summary = merovingian::rooms::make_encrypted_event_log_summary(
                "m.room.encrypted", "!room:example.org", "@alice:example.org", payload);
            auto const summary_text = merovingian::rooms::encrypted_event_log_summary_text(summary);

            THEN("only redacted metadata is exposed")
            {
                REQUIRE_FALSE(loggable);
                REQUIRE(summary.payload == "[encrypted-payload:redacted]");
                REQUIRE(summary_text.find(payload) == std::string::npos);
                REQUIRE(summary_text.find("m.room.encrypted") != std::string::npos);
            }
        }
    }
}
