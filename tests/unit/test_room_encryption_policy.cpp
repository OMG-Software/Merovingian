// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MEROVINGIAN ROOM ENCRYPTION POLICY TESTS                        |
// |                                                                         |
// |  Spec: Merovingian mandatory encryption policy (stricter than Matrix)   |
// |  Ref:  Matrix Client-Server API v1.18, Sec. 13 End-to-end encryption        |
// |  URL:  https://spec.matrix.org/v1.18/client-server-api/                 |
// |        #end-to-end-encryption                                            |
// |                                                                         |
// |  Note: The Matrix spec allows unencrypted private rooms. Merovingian    |
// |  does not - private rooms and DMs MUST be encrypted. This is an         |
// |  intentional security hardening decision, not a spec deviation.         |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  These tests encode hard security invariants. If a test fails:          |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it enforces the policy.                  |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT relax the encryption requirement for private rooms or DMs   |
// |      without an explicit, reviewed security decision recorded here.     |
// |                                                                         |
// +-------------------------------------------------------------------------+

#include "merovingian/rooms/encryption_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

// --- default encryption for private rooms and DMs ----------------------------
// Policy: Merovingian mandatory encryption
//
// Private rooms (preset=private_chat) and direct messages MUST be encrypted
// by default. A user who creates a private room or DM without specifying an
// encryption preference receives an encrypted room.
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
                // Security invariant: private rooms and DMs must be encrypted.
                // Do NOT change encryption_required to false - this is a deliberate
                // hardening decision that prevents accidental plaintext private rooms.
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

// --- rejection of explicit unencrypted private rooms -------------------------
// Policy: Merovingian mandatory encryption
//
// A client that explicitly requests an unencrypted private room, federated
// private room, or DM MUST be rejected. The server should never create a
// plaintext private channel even when the client asks for one.
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
                // Security invariant: explicit unencrypted request MUST be rejected.
                // Do NOT change to allowed - this gate prevents clients from creating
                // private rooms without encryption even when they explicitly ask.
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

// --- unencrypted public rooms -------------------------------------------------
// Policy: Merovingian encryption policy
//
// Public rooms (preset=public_chat) may be unencrypted - this is the common
// case for open community rooms and is consistent with Matrix convention.
// Encryption is neither required nor enabled by default for public rooms.
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
                // Public rooms may be unencrypted - this is intentional and
                // consistent with the Matrix spec for public community rooms.
                REQUIRE(decision.allowed);
                REQUIRE_FALSE(decision.encryption_required);
                REQUIRE_FALSE(decision.encryption_enabled_by_default);
                REQUIRE_FALSE(decision.encryption_enabled);
            }
        }
    }
}

// --- encrypted payload log redaction -----------------------------------------
// Spec: Merovingian security policy - no plaintext from encrypted events in logs
// Ref:  Matrix Client-Server API v1.18, Sec. 13.9.4 m.room.encrypted
// URL:  https://spec.matrix.org/v1.18/client-server-api/#mroomencrypted
//
// Encrypted event ciphertext and session material MUST NOT appear in diagnostic
// logs or audit trails. The log summary MUST redact the payload entirely.
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
                // Security MUST: encrypted payload must never be logged.
                // Do NOT change loggable to true - this prevents key material
                // and ciphertext leaking into log aggregation systems.
                REQUIRE_FALSE(loggable);
                REQUIRE(summary.payload == "[encrypted-payload:redacted]");
                // Security MUST: the original payload must not appear in the summary text.
                REQUIRE(summary_text.find(payload) == std::string::npos);
                REQUIRE(summary_text.find("m.room.encrypted") != std::string::npos);
            }
        }
    }
}
