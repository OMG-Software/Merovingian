// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              MATRIX EVENT CONFORMANCE TESTS                             |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.18                                   |
// |  URL:  https://spec.matrix.org/v1.18/server-server-api/                 |
// |                                                                         |
// |  Also covers:                                                           |
// |    Matrix Client-Server API v1.18 (redactions)                          |
// |    https://spec.matrix.org/v1.18/client-server-api/#redactions          |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST or SHOULD from the Matrix    |
// |  specification. If a test fails:                                        |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// |  The spec section is cited above each SCENARIO. Cross-check it before   |
// |  concluding that a failing assertion is wrong.                           |
// +-------------------------------------------------------------------------+

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/events/event.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/events/redaction.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace
{

class FixedSigningKeyStore final : public merovingian::crypto::SigningKeyStore
{
public:
    explicit FixedSigningKeyStore(merovingian::crypto::SigningKeyRecord key)
        : m_key{std::move(key)}
    {
    }

    [[nodiscard]] auto active_key_for_server(std::string_view server_name)
        -> merovingian::crypto::SigningKeyLookupResult override
    {
        if (server_name != m_key.server_name)
        {
            return {{}, "signing key not found"};
        }

        return {m_key, {}};
    }

private:
    merovingian::crypto::SigningKeyRecord m_key{};
};

class CapturingEd25519Provider final : public merovingian::crypto::Ed25519Provider
{
public:
    [[nodiscard]] auto sign(merovingian::crypto::Ed25519SecretKeyHandle const& key,
                            std::string_view message) -> merovingian::crypto::SignatureResult override
    {
        if (key.key_id != "ed25519:auto")
        {
            return {{}, "unknown key"};
        }

        signed_message = std::string{message};
        return {merovingian::crypto::Ed25519Signature{std::string(64U, 's')}, {}};
    }

    [[nodiscard]] auto verify(merovingian::crypto::Ed25519PublicKey const& public_key, std::string_view message,
                              merovingian::crypto::Ed25519Signature const& signature)
        -> merovingian::crypto::VerificationResult override
    {
        auto const valid = public_key.bytes == std::string(32U, 'p') && message == signed_message &&
                           signature.bytes == std::string(64U, 's');
        return {valid, valid ? std::string{} : std::string{"signature verification failed"}};
    }

    std::string signed_message{};
};

} // namespace

// --- Event ID determinism (canonical JSON) -----------------------------------
// Spec: Matrix Server-Server API v1.18
// Section: Room Version 4 - Event IDs
// URL: https://spec.matrix.org/v1.18/rooms/v4/
//
// Event IDs in room version 4+ are a URL-safe unpadded base64 encoding of the
// SHA-256 reference hash of the event. Because the hash is computed over the
// canonical JSON form, two JSON objects that differ only in key ordering MUST
// produce identical event IDs.
SCENARIO("Event IDs are deterministic over canonical JSON", "[events]")
{
    GIVEN("equivalent JSON objects with different key order")
    {
        auto const first = merovingian::canonicaljson::parse_lossless("{\"b\":2,\"a\":1}");
        auto const second = merovingian::canonicaljson::parse_lossless("{\"a\":1,\"b\":2}");

        WHEN("content hash IDs are generated")
        {
            auto const first_id = merovingian::events::make_content_hash_id(first.value);
            auto const second_id = merovingian::events::make_content_hash_id(second.value);

            THEN("the event IDs match")
            {
                // Spec MUST: event IDs derived from the same event data must be identical
                // regardless of the serialisation order of JSON keys.
                // Do NOT remove/change - two servers exchanging the same event via
                // federation must agree on its ID; a mismatch breaks room DAG integrity.
                REQUIRE(first_id.error.empty());
                REQUIRE(first_id.event_id == second_id.event_id);
                // Spec MUST: event IDs must match the URL-safe base64 format "$<hash>".
                // Do NOT remove/change - malformed IDs are rejected by all conformant servers.
                REQUIRE(merovingian::events::event_id_is_valid(first_id.event_id));
            }
        }
    }
}

// --- Content hash and reference hash computation -----------------------------
// Spec: Matrix Server-Server API v1.18
// Section: Calculating the content hash for an event
// URL: https://spec.matrix.org/v1.18/server-server-api/#calculating-the-content-hash-for-an-event
//
// The hashes.sha256 field is the URL-safe unpadded base64 of the SHA-256 digest
// of the canonical JSON of the event with the "unsigned", "signatures", and
// "hashes" fields removed. The reference hash used to derive the event_id is
// computed over the redacted event body with only the "hashes" field present.
// Both values MUST match exactly or federation peers will reject the PDU.
SCENARIO("Matrix event hashes follow content and reference hash rules", "[events][signing]")
{
    GIVEN("a room v11 event with excluded and redacted fields")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("11");
        REQUIRE(policy != nullptr);
        auto const parsed = merovingian::canonicaljson::parse_lossless(
            "{\"type\":\"m.room.message\",\"room_id\":\"!room:example.org\",\"sender\":\"@alice:example.org\","
            "\"content\":{\"body\":\"hi\",\"msgtype\":\"m.text\"},\"origin_server_ts\":1,"
            "\"unsigned\":{\"age\":1},\"signatures\":{\"evil\":{\"ed25519:x\":\"sig\"}},"
            "\"hashes\":{\"sha256\":\"old\"}}");

        WHEN("content and reference hashes are calculated")
        {
            auto const content_hash = merovingian::events::make_content_hash(parsed.value);
            auto hashed_event = merovingian::canonicaljson::parse_lossless(
                "{\"type\":\"m.room.message\",\"room_id\":\"!room:example.org\",\"sender\":\"@alice:example.org\","
                "\"content\":{\"body\":\"hi\",\"msgtype\":\"m.text\"},\"origin_server_ts\":1,"
                "\"hashes\":{\"sha256\":\"gsjDCjzrjqiMPUvnSb9TrBx6Jf7B5rbwNep8hWlcTFQ\"},"
                "\"unsigned\":{\"age\":1},\"signatures\":{\"evil\":{\"ed25519:x\":\"sig\"}}}");
            auto const reference_hash = merovingian::events::make_reference_hash(hashed_event.value, *policy);
            auto const event_id = merovingian::events::make_reference_hash_event_id(hashed_event.value, *policy);

            THEN("the hashes match Matrix canonical JSON SHA-256 encodings")
            {
                REQUIRE(content_hash.error.empty());
                // Spec MUST: hashes.sha256 must equal the URL-safe base64 SHA-256 of the
                // canonical JSON with "unsigned", "signatures", and "hashes" removed.
                // Do NOT remove/change - federation peers verify this field during auth;
                // a wrong value causes the PDU to be rejected as "invalid hash".
                REQUIRE(content_hash.sha256 == "gsjDCjzrjqiMPUvnSb9TrBx6Jf7B5rbwNep8hWlcTFQ");
                REQUIRE(reference_hash.error.empty());
                // Spec MUST: the reference hash is the SHA-256 of the redacted event body
                // (with hashes present). This value must be stable - it is used as event_id.
                // Do NOT remove/change - altering the expected value breaks all event ID
                // derivation for events carrying this exact canonical body.
                REQUIRE(reference_hash.sha256 == "F-VEjF2TNVE5ODdeaHi7OADldkLgev_kV60OIIVlkEg");
                REQUIRE(event_id.event_id == "$F-VEjF2TNVE5ODdeaHi7OADldkLgev_kV60OIIVlkEg");
                // Spec MUST: the event_id must be a valid URL-safe base64 string prefixed with "$".
                // Do NOT remove/change - malformed event IDs are unconditionally rejected by
                // conformant servers.
                REQUIRE(merovingian::events::event_id_is_valid(event_id.event_id));
            }
        }
    }
}

// --- Event envelope parsing ---------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Section: PDU Fields
// URL: https://spec.matrix.org/v1.18/server-server-api/#pdus
//
// Every PDU MUST contain the fields room_id, type, sender, and origin_server_ts.
// Parsing MUST fail (or report an error) if any of these mandatory fields are
// absent, and MUST extract them correctly when present.
SCENARIO("Event envelope parser validates core Matrix fields", "[events]")
{
    GIVEN("an event JSON object with required Matrix fields")
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless(
            "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_"
            "server_ts\":1,\"content\":{}}");

        WHEN("the event envelope is parsed")
        {
            auto const event = merovingian::events::parse_event_envelope(parsed.value);

            THEN("core Matrix fields are extracted")
            {
                REQUIRE(event.error.empty());
                // Spec MUST: room_id, type, and sender MUST be extracted without modification.
                // Do NOT remove/change - downstream auth checks and routing depend on the
                // exact values of these fields as specified in the PDU.
                REQUIRE(event.event.room_id == "!room:example.org");
                REQUIRE(event.event.event_type == "m.room.message");
                REQUIRE(event.event.sender == "@alice:example.org");
            }
        }
    }
}

// --- Event signing payload - field exclusion ---------------------------------
// Spec: Matrix Server-Server API v1.18
// Section: Signing Events
// URL: https://spec.matrix.org/v1.18/server-server-api/#signing-events
//
// The signing payload is the canonical JSON of the event with the "unsigned"
// and "signatures" fields removed. Signing over those fields is explicitly
// forbidden by the spec; including them would make signature verification
// fail against any other server that follows the spec.
SCENARIO("Event signing payload excludes unsigned and signatures", "[events][signing]")
{
    GIVEN("an event containing unsigned data and signatures")
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless(
            "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_"
            "server_ts\":1,\"unsigned\":{\"age\":1},\"signatures\":{\"example.org\":{\"ed25519:a\":\"sig\"}},"
            "\"content\":{}}");

        WHEN("the signing payload is created")
        {
            auto const payload = merovingian::events::make_event_signing_payload(parsed.value);

            THEN("excluded fields are omitted from the canonical payload")
            {
                REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
                // Spec MUST: "unsigned" MUST NOT appear in the signing payload.
                // Do NOT remove/change - including "unsigned" causes cross-server signature
                // verification to fail because remote servers strip it before verifying.
                REQUIRE(payload.output.find("unsigned") == std::string::npos);
                // Spec MUST: "signatures" MUST NOT appear in the signing payload.
                // Do NOT remove/change - including existing signatures in the payload is
                // circular and breaks Ed25519 verification on all conformant servers.
                REQUIRE(payload.output.find("signatures") == std::string::npos);
                REQUIRE(payload.output.find("m.room.message") != std::string::npos);
            }
        }
    }
}

// --- Event signing payload - content and hashes preservation -----------------
// Spec: Matrix Server-Server API v1.18
// Section: Signing Events
// URL: https://spec.matrix.org/v1.18/server-server-api/#signing-events
//
// The signing payload strips only "unsigned" and "signatures". All other fields,
// including "content" and "hashes", MUST remain in the payload exactly as they
// appear in the event. Stripping content fields would invalidate the signature
// produced by the origin server.
SCENARIO("Event signing payload removes unsigned metadata but keeps event content", "[events][signing]")
{
    GIVEN("a room v11 event with unsigned data signatures and message content")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("11");
        REQUIRE(policy != nullptr);
        auto const parsed = merovingian::canonicaljson::parse_lossless(
            "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\","
            "\"origin_server_ts\":1,\"hashes\":{\"sha256\":\"hash\"},\"unsigned\":{\"age\":1},"
            "\"signatures\":{\"example.org\":{\"ed25519:a\":\"sig\"}},"
            "\"content\":{\"body\":\"secret\",\"msgtype\":\"m.text\"}}");

        WHEN("the Matrix signing payload is created")
        {
            auto const payload = merovingian::events::make_event_signing_payload(parsed.value, *policy);

            THEN("unsigned metadata is omitted, but the canonical event content remains signable")
            {
                REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
                // Spec MUST: "unsigned" MUST NOT appear in the signing payload.
                // Do NOT remove/change - see signing-events spec section above.
                REQUIRE(payload.output.find("unsigned") == std::string::npos);
                // Spec MUST: "signatures" MUST NOT appear in the signing payload.
                // Do NOT remove/change - see signing-events spec section above.
                REQUIRE(payload.output.find("signatures") == std::string::npos);
                // Spec MUST: the signing payload is the PRUNED (redacted) form of the
                // event. For m.room.message, the content is empty after pruning.
                // The full content is authenticated via hashes.sha256 instead.
                REQUIRE(payload.output.find(R"("content":{})") != std::string::npos);
                // Spec MUST: "hashes" MUST be present in the signing payload so that the
                // content hash is itself covered by the Ed25519 signature.
                // Do NOT remove/change - a missing hashes field means the content hash is
                // unauthenticated, allowing an attacker to substitute a different hash.
                REQUIRE(payload.output.find(R"("hashes":{"sha256":"hash"})") != std::string::npos);
            }
        }
    }
}

// --- Signing payload strips event_id for room v4+ PDUs -----------------------
// Spec: Matrix Server-Server API v1.18
// Section: Room Version 4 - Event IDs / Signing Events
// URL: https://spec.matrix.org/v1.18/rooms/v4/
// URL: https://spec.matrix.org/v1.18/server-server-api/#signing-events
//
// In room versions 4+, event_id is NOT part of the canonical event body - it is
// derived from the content. Federation senders (e.g. Synapse) may include it as
// a convenience hint for receivers, but they do NOT include it in the signing
// payload. Our verification payload MUST match what the sender signed, so
// event_id MUST be stripped before signing or verifying.
//
// Regression: failing to strip event_id caused crypto_sign_verify_detached to
// fail for every inbound PDU from Synapse.
// Regression: Synapse (and some other federation senders) include event_id in
// outbound PDUs as a convenience hint for the receiver, even though for room
// versions 4+ the event_id is derived from the content hash and is NOT part of
// the canonical event body. The signing payload Synapse computed when creating
// the event therefore does NOT contain event_id. If we include event_id when
// building our verification payload, crypto_sign_verify_detached fails.
//
// Fix: make_event_signing_payload(event, policy) strips event_id whenever
// policy.event_id_format == EventIdFormat::reference_hash (all room versions 4+).
SCENARIO("Signing payload for room v4+ PDUs strips event_id included by federation senders",
         "[events][signing][federation]")
{
    // A real m.room.encrypted PDU body as Synapse would send it in a transaction:
    // event_id is present as a convenience field (signed content did NOT include it).
    auto const pdu_with_event_id =
        std::string{R"({"auth_events":["$aaa","$bbb"],"content":{"algorithm":"m.megolm.v1.aes-sha2",)"
                    R"("ciphertext":"DEADBEEF","device_id":"DEVICE1","sender_key":"senderkey123",)"
                    R"("session_id":"session456"},"depth":10,"event_id":"$abcdef1234567890:matrix.ping.me.uk",)"
                    R"("hashes":{"sha256":"contenthashbase64"},"origin_server_ts":1748300000000,)"
                    R"("prev_events":["$ccc"],"room_id":"!room:matrix.ping.me.uk",)"
                    R"("sender":"@alice:matrix.ping.me.uk","type":"m.room.encrypted"})"};

    // The same PDU without event_id - what was actually signed by Synapse.
    auto const pdu_without_event_id =
        std::string{R"({"auth_events":["$aaa","$bbb"],"content":{"algorithm":"m.megolm.v1.aes-sha2",)"
                    R"("ciphertext":"DEADBEEF","device_id":"DEVICE1","sender_key":"senderkey123",)"
                    R"("session_id":"session456"},"depth":10,)"
                    R"("hashes":{"sha256":"contenthashbase64"},"origin_server_ts":1748300000000,)"
                    R"("prev_events":["$ccc"],"room_id":"!room:matrix.ping.me.uk",)"
                    R"("sender":"@alice:matrix.ping.me.uk","type":"m.room.encrypted"})"};

    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(policy != nullptr);
    // Confirm the policy uses reference-hash event IDs (room v4+).
    REQUIRE(policy->event_id_format == merovingian::rooms::EventIdFormat::reference_hash);

    GIVEN("a PDU that includes event_id as a federation hint")
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless(pdu_with_event_id);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the signing payload is built with a room-v12 policy")
        {
            auto const payload = merovingian::events::make_event_signing_payload(parsed.value, *policy);

            THEN("event_id is absent from the payload")
            {
                REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
                // Spec MUST: event_id MUST NOT appear in the signing payload for room v4+.
                // Do NOT remove/change - including event_id causes signature verification
                // to fail against Synapse and all other spec-compliant servers.
                REQUIRE(payload.output.find("event_id") == std::string::npos);
            }

            THEN("all canonical event fields are still present")
            {
                REQUIRE(payload.output.find("m.room.encrypted") != std::string::npos);
                REQUIRE(payload.output.find("contenthashbase64") != std::string::npos);
                REQUIRE(payload.output.find("1748300000000") != std::string::npos);
                REQUIRE(payload.output.find("@alice:matrix.ping.me.uk") != std::string::npos);
            }

            THEN("unsigned and signatures remain absent from the payload")
            {
                REQUIRE(payload.output.find("unsigned") == std::string::npos);
                REQUIRE(payload.output.find("signatures") == std::string::npos);
            }

            THEN("the payload matches what would be produced from a PDU that never had event_id")
            {
                auto const parsed_no_id = merovingian::canonicaljson::parse_lossless(pdu_without_event_id);
                REQUIRE(parsed_no_id.error == merovingian::canonicaljson::ParseError::none);
                auto const payload_no_id = merovingian::events::make_event_signing_payload(parsed_no_id.value, *policy);
                REQUIRE(payload_no_id.error == merovingian::canonicaljson::CanonicalJsonError::none);
                // Spec MUST: the canonical signing payloads must be byte-identical whether or
                // not the inbound PDU carried an event_id convenience field.
                // Do NOT remove/change - this is what allows crypto_sign_verify_detached to
                // succeed: Synapse signed the no-event_id form; we must verify the same form.
                REQUIRE(payload.output == payload_no_id.output);
            }
        }
    }

    GIVEN("a PDU that does not include event_id (spec-compliant sender)")
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless(pdu_without_event_id);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the signing payload is built with a room-v12 policy")
        {
            auto const payload = merovingian::events::make_event_signing_payload(parsed.value, *policy);

            THEN("the payload is unchanged - stripping is idempotent")
            {
                REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(payload.output.find("event_id") == std::string::npos);
                REQUIRE(payload.output.find("m.room.encrypted") != std::string::npos);
            }
        }
    }
}

// --- Signing payload prunes event content (Synapse parity) --------------------
// Spec: Matrix Server-Server API v1.18
// Section: Signing Events
// URL: https://spec.matrix.org/v1.18/server-server-api/#signing-events
//
// Synapse signs the PRUNED (redacted) form of the event, not the full event.
// For m.room.member events, the pruned content keeps only "membership" —
// extra fields like "is_direct" are stripped before computing the signing
// payload. If we sign the full content, Synapse verification fails with
// BadSignatureError because the canonical JSON bytes differ.
SCENARIO("Signing payload for m.room.member prunes content to membership only", "[events][signing][federation]")
{
    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(policy != nullptr);

    GIVEN("an m.room.member invite event with is_direct in the content")
    {
        auto const event_json = std::string{R"({"auth_events":[],"content":{"is_direct":true,"membership":"invite"},)"
                                            R"("depth":1,"hashes":{"sha256":"abc123"},)"
                                            R"("origin_server_ts":1748300000000,"prev_events":[],)"
                                            R"("room_id":"!room:pong.ping.me.uk","sender":"@alice:pong.ping.me.uk",)"
                                            R"("state_key":"@bob:matrix.ping.me.uk","type":"m.room.member"})"};
        auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the signing payload is built with a room-v12 policy")
        {
            auto const payload = merovingian::events::make_event_signing_payload(parsed.value, *policy);
            THEN("the payload contains only membership in content — is_direct is pruned")
            {
                REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
                // Spec MUST: Synapse signs the pruned event where m.room.member
                // content keeps only "membership". Including is_direct causes
                // BadSignatureError because the canonical bytes differ.
                REQUIRE(payload.output.find("is_direct") == std::string::npos);
                REQUIRE(payload.output.find("\"membership\":\"invite\"") != std::string::npos);
            }
        }
    }

    GIVEN("an m.room.member join event with displayname and avatar_url")
    {
        auto const event_json =
            std::string{R"({"auth_events":[],"content":{"avatar_url":"mxc://example.org/abc","displayname":"Bob",)"
                        R"("membership":"join"},"depth":1,"hashes":{"sha256":"abc123"},)"
                        R"("origin_server_ts":1748300000000,"prev_events":[],)"
                        R"("room_id":"!room:pong.ping.me.uk","sender":"@alice:pong.ping.me.uk",)"
                        R"("state_key":"@bob:pong.ping.me.uk","type":"m.room.member"})"};
        auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the signing payload is built with a room-v12 policy")
        {
            auto const payload = merovingian::events::make_event_signing_payload(parsed.value, *policy);
            THEN("displayname and avatar_url are pruned from content")
            {
                REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(payload.output.find("displayname") == std::string::npos);
                REQUIRE(payload.output.find("avatar_url") == std::string::npos);
                REQUIRE(payload.output.find("\"membership\":\"join\"") != std::string::npos);
            }
        }
    }
}

// --- Event signature attachment and presence detection -----------------------
// Spec: Matrix Server-Server API v1.18
// Section: Signing Events
// URL: https://spec.matrix.org/v1.18/server-server-api/#signing-events
//
// After signing, the Ed25519 signature MUST be stored under
// event["signatures"][<server_name>][<key_id>] as a URL-safe unpadded base64
// string. The presence of a signature for a given key MUST be detectable without
// performing cryptographic verification.
SCENARIO("Event signature scaffold attaches and detects signatures", "[events][signing]")
{
    GIVEN("an unsigned event and signing key ID")
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless(
            "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_"
            "server_ts\":1,\"content\":{}}");
        auto const key_id = merovingian::events::SigningKeyId{"example.org", "ed25519:auto"};

        WHEN("a signature is attached and the event is reparsed")
        {
            auto const signed_json = merovingian::events::attach_event_signature(
                parsed.value, key_id,
                "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ");
            auto const reparsed = merovingian::canonicaljson::parse_lossless(signed_json.output);
            auto const verified = merovingian::events::verify_event_signature_presence(reparsed.value, key_id);

            THEN("the signature is present")
            {
                REQUIRE(signed_json.error == merovingian::canonicaljson::CanonicalJsonError::none);
                // Spec MUST: a signature attached under the correct server/key path MUST be
                // detectable via the presence check. Do NOT remove/change - federation auth
                // checks rely on this to confirm the event was signed by the origin server.
                REQUIRE(verified.valid);
                REQUIRE(verified.error.empty());
            }
        }
    }
}

// --- Full sign-and-verify round trip -----------------------------------------
// Spec: Matrix Server-Server API v1.18
// Section: Signing Events
// URL: https://spec.matrix.org/v1.18/server-server-api/#signing-events
//
// Events MUST be signed with the server's active Ed25519 key before being sent
// to federation peers. The resulting signature MUST be stored as URL-safe
// unpadded base64 and MUST be verifiable against the signing payload using the
// corresponding public key.
SCENARIO("Event signing stores Matrix base64 Ed25519 signatures and verifies the signed payload", "[events][signing]")
{
    GIVEN("a signable room v11 event and active server signing key")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("11");
        REQUIRE(policy != nullptr);
        auto parsed = merovingian::canonicaljson::parse_lossless(
            "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\","
            "\"origin_server_ts\":1,\"hashes\":{\"sha256\":\"hash\"},\"content\":{\"body\":\"secret\"}}");
        auto store = FixedSigningKeyStore{
            merovingian::crypto::SigningKeyRecord{
                                                  "example.org", "ed25519:auto",
                                                  merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')},
                                                  true, }
        };
        auto provider = CapturingEd25519Provider{};

        WHEN("the event is signed and verified")
        {
            auto const signed_event =
                merovingian::events::sign_event_for_server(parsed.value, *policy, store, provider, "example.org");
            auto const reparsed = merovingian::canonicaljson::parse_lossless(signed_event.event_json);
            auto const verified = merovingian::events::verify_event_signature(
                reparsed.value, *policy, {"example.org", "ed25519:auto"},
                merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')}, provider);

            THEN("the signature is base64 encoded and bound to the canonical event payload")
            {
                REQUIRE(signed_event.error.empty());
                // Spec MUST: the stored signature must be a valid URL-safe base64 encoding of
                // the raw Ed25519 signature bytes (64 bytes -> 86 base64 chars without padding).
                // Do NOT remove/change - a malformed base64 value causes all federation peers
                // to reject the event during signature verification.
                REQUIRE(signed_event.signature ==
                        "c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzcw");
                // Spec MUST: the signing payload is the pruned (redacted) form.
                // For m.room.message the content is empty after pruning; the full
                // content is authenticated via hashes.sha256 instead.
                REQUIRE(provider.signed_message.find("secret") == std::string::npos);
                // Spec MUST: the signature must verify correctly against the signing payload
                // using the server's public key. Do NOT remove/change - if round-trip
                // verification fails, the event cannot be authenticated by federation peers.
                REQUIRE(verified.valid);
                REQUIRE(verified.error.empty());
            }
        }
    }
}

// --- Signing payload prunes member profile fields (Synapse parity) ------------
// Spec: Matrix Server-Server API v1.18
// Section: Signing Events / m.room.member redaction rules
// URL: https://spec.matrix.org/v1.18/server-server-api/#signing-events
// URL: https://spec.matrix.org/v1.18/server-server-api/#redactions
//
// For m.room.member events, only "membership" survives redaction in the
// content. Profile fields like "displayname" and "avatar_url" are stripped
// by Synapse's prune_event_dict before signing. Our signing payload must
// match to avoid BadSignatureError.
SCENARIO("Event signing prunes member profile fields from the signed payload", "[events][signing][member]")
{
    GIVEN("a room v12 member event with a displayname")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto parsed = merovingian::canonicaljson::parse_lossless(
            "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.member\",\"sender\":\"@alice:example.org\","
            "\"state_key\":\"@alice:example.org\",\"origin_server_ts\":1,\"hashes\":{\"sha256\":\"hash\"},"
            "\"content\":{\"membership\":\"join\",\"displayname\":\"Alice\"}}");
        auto store = FixedSigningKeyStore{
            merovingian::crypto::SigningKeyRecord{
                                                  "example.org", "ed25519:auto",
                                                  merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')},
                                                  true, }
        };
        auto provider = CapturingEd25519Provider{};

        WHEN("the event is signed")
        {
            auto const signed_event =
                merovingian::events::sign_event_for_server(parsed.value, *policy, store, provider, "example.org");

            THEN("the signed payload prunes displayname — only membership remains")
            {
                REQUIRE(signed_event.error.empty());
                // Spec MUST: Synapse signs the pruned form. For m.room.member,
                // only "membership" survives pruning. Including displayname
                // causes BadSignatureError because canonical bytes differ.
                REQUIRE(provider.signed_message.find("\"displayname\":\"Alice\"") == std::string::npos);
                REQUIRE(provider.signed_message.find("\"membership\":\"join\"") != std::string::npos);
            }
        }
    }
}

// --- Signature accumulation (multi-server signing) ---------------------------
// Spec: Matrix Server-Server API v1.18
// Section: Signing Events
// URL: https://spec.matrix.org/v1.18/server-server-api/#signing-events
//
// An event may carry signatures from multiple servers under separate entries in
// the "signatures" object. Attaching a new signature MUST NOT remove or alter
// any existing signatures - all parties that signed the event must remain
// verifiable.
SCENARIO("Event signature scaffold preserves existing signatures", "[events][signing]")
{
    GIVEN("an event with an existing signature and a new signing key")
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless(
            "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_"
            "server_ts\":1,\"content\":{},\"signatures\":{\"old.example.org\":{\"ed25519:old\":"
            "\"b29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vbw\"}}}");
        auto const old_key_id = merovingian::events::SigningKeyId{"old.example.org", "ed25519:old"};
        auto const new_key_id = merovingian::events::SigningKeyId{"example.org", "ed25519:new"};

        WHEN("the new signature is attached")
        {
            auto const signed_json = merovingian::events::attach_event_signature(
                parsed.value, new_key_id,
                "bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubg");
            auto const reparsed = merovingian::canonicaljson::parse_lossless(signed_json.output);
            auto const old_signature = merovingian::events::verify_event_signature_presence(reparsed.value, old_key_id);
            auto const new_signature = merovingian::events::verify_event_signature_presence(reparsed.value, new_key_id);

            THEN("both old and new signatures are present")
            {
                REQUIRE(signed_json.error == merovingian::canonicaljson::CanonicalJsonError::none);
                // Spec MUST: pre-existing signatures from other servers MUST be preserved
                // when a new signature is added. Do NOT remove/change - dropping an existing
                // signature invalidates auth checks performed by federation peers that rely
                // on that server's signature being present.
                REQUIRE(old_signature.valid);
                // Spec MUST: the newly attached signature MUST be detectable under the new
                // server/key path. Do NOT remove/change - the receiving server verifies its
                // own signature is present before forwarding the event.
                REQUIRE(new_signature.valid);
            }
        }
    }
}

// --- Event redaction - non-auth field stripping -------------------------------
// Spec: Matrix Client-Server API v1.18
// Section: Redactions
// URL: https://spec.matrix.org/v1.18/client-server-api/#redactions
// Spec: Matrix Server-Server API v1.18
// Section: Redactions
// URL: https://spec.matrix.org/v1.18/server-server-api/#redactions
//
// A redacted event MUST retain only the top-level fields defined by the room
// version's redaction rules (e.g. room_id, type, sender, state_key, depth,
// auth_events, prev_events, hashes, signatures). All other top-level fields and
// all content sub-fields that are not redaction-preserved MUST be removed.
SCENARIO("Event redaction keeps only allowed keys", "[events][redaction]")
{
    GIVEN("an event with allowed and disallowed top-level keys")
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless(
            "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_"
            "server_ts\":1,\"content\":{\"body\":\"secret\"},\"extra\":\"drop\"}");
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        WHEN("the event is redacted")
        {
            auto const redacted = merovingian::events::redact_event(parsed.value, *policy);
            auto const output = merovingian::canonicaljson::serialize_canonical(redacted.event);

            THEN("disallowed keys are dropped")
            {
                REQUIRE(redacted.error.empty());
                // Spec MUST: non-auth top-level fields MUST be absent after redaction.
                // Do NOT remove/change - retaining extra fields would expose data that the
                // redaction was intended to hide, violating user privacy guarantees.
                REQUIRE(output.output.find("extra") == std::string::npos);
                // Spec MUST: non-preserved content sub-fields MUST be absent after redaction.
                // Do NOT remove/change - leaking message body after redaction is a spec
                // violation and a privacy breach.
                REQUIRE(output.output.find("secret") == std::string::npos);
                // Spec MUST: room_id MUST be retained after redaction - it is an auth field.
                // Do NOT remove/change - without room_id the redacted event cannot be routed
                // or authenticated by any server.
                REQUIRE(output.output.find("\"room_id\"") != std::string::npos);
            }
        }
    }
}

// --- Room-version-specific redaction rules ------------------------------------
// Spec: Matrix Server-Server API v1.18
// Section: Redactions
// URL: https://spec.matrix.org/v1.18/server-server-api/#redactions
//
// Room versions 1-10 preserve additional legacy top-level fields ("origin",
// "prev_state", "membership") that were removed in room version 11. The redaction
// implementation MUST apply the policy for the room's actual version; using the
// wrong policy corrupts the reference hash and invalidates the event ID.
SCENARIO("Event redaction uses room-version-specific top-level keys", "[events][redaction]")
{
    GIVEN("an event and two room-version policies")
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless(
            "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_"
            "server_ts\":1,\"content\":{},\"origin\":\"example.org\",\"prev_state\":[],\"membership\":\"join\","
            "\"unsigned\":{}}");
        auto const* room_v10 = merovingian::rooms::find_room_version_policy("10");
        auto const* room_v12 = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(room_v10 != nullptr);
        REQUIRE(room_v12 != nullptr);

        WHEN("the event is redacted under each policy")
        {
            auto const redacted_v10 = merovingian::events::redact_event(parsed.value, *room_v10);
            auto const redacted_v12 = merovingian::events::redact_event(parsed.value, *room_v12);
            auto const output_v10 = merovingian::canonicaljson::serialize_canonical(redacted_v10.event);
            auto const output_v12 = merovingian::canonicaljson::serialize_canonical(redacted_v12.event);

            THEN("each policy keeps the expected version-specific keys")
            {
                // Spec MUST (room v1-v10): "origin", "prev_state", and "membership" are
                // redaction-preserved in legacy room versions.
                // Do NOT remove/change - reference hash computation for legacy events depends
                // on these fields being present after redaction.
                REQUIRE(output_v10.output.find("\"origin\"") != std::string::npos);
                REQUIRE(output_v10.output.find("\"prev_state\"") != std::string::npos);
                REQUIRE(output_v10.output.find("\"membership\"") != std::string::npos);
                // Spec MUST: "unsigned" is never redaction-preserved in any room version.
                // Do NOT remove/change - retaining "unsigned" after redaction exposes
                // ephemeral metadata that the spec explicitly excludes from the auth chain.
                REQUIRE(output_v10.output.find("\"unsigned\"") == std::string::npos);
                // Spec MUST (room v11+): "origin", "prev_state", and "membership" are NOT
                // redaction-preserved - they were removed from the redaction rules in v11.
                // Do NOT remove/change - including them in v11+ redacted events corrupts the
                // reference hash and therefore the event ID.
                REQUIRE(output_v12.output.find("\"origin\"") == std::string::npos);
                REQUIRE(output_v12.output.find("\"prev_state\"") == std::string::npos);
                REQUIRE(output_v12.output.find("\"membership\"") == std::string::npos);
                REQUIRE(output_v12.output.find("\"unsigned\"") == std::string::npos);
            }
        }
    }
}

// --- Join event hashes.sha256 required for send_join -------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 11.5.1
// Section: PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}
// URL: https://spec.matrix.org/v1.18/server-server-api/#put_matrixfederationv2send_joinroomideventid
//
// Every PDU sent to the send_join endpoint MUST carry a valid hashes.sha256
// field computed before the event is signed. Remote servers (including Synapse)
// return HTTP 400 "Malformed 'hashes': <class 'NoneType'>" if this field is
// absent. The content hash MUST be computed and embedded before sign_event_for_server
// is called.
SCENARIO("Join event prepared for send_join must carry a content hash", "[events][signing][federation]")
{
    // Regression: join_room's remote-join path was signing the event without
    // first calling make_content_hash and attaching the result as hashes.sha256.
    // Synapse rejected the resulting send_join body with:
    //   SynapseError: 400 - Malformed 'hashes': <class 'NoneType'>
    // The Matrix spec (room versions >= 2) requires every PDU to carry a
    // canonical-JSON SHA-256 content hash before any signature is attached.
    GIVEN("a make_join response event template that lacks a hashes field")
    {
        // Minimal m.room.member join event as returned by a remote server's
        // make_join response - no hashes, no signatures yet.
        auto const template_json =
            std::string{R"({"auth_events":[],"content":{"membership":"join"},"depth":5,)"
                        R"("origin_server_ts":1748300000000,"prev_events":[],"room_id":"!room:remote.example.com",)"
                        R"("sender":"@user:local.example.com","state_key":"@user:local.example.com",)"
                        R"("type":"m.room.member"})"};

        auto const parsed = merovingian::canonicaljson::parse_lossless(template_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
        REQUIRE(obj != nullptr);

        WHEN("the content hash is computed and embedded before signing")
        {
            // Step 1: compute SHA-256 content hash.
            auto const content_hash = merovingian::events::make_content_hash(parsed.value);
            REQUIRE(content_hash.error.empty());
            REQUIRE_FALSE(content_hash.sha256.empty());

            // Step 2: attach hashes field to the event object.
            auto event_with_hash = *obj;
            auto hashes_obj = merovingian::canonicaljson::Object{};
            hashes_obj.push_back(merovingian::canonicaljson::make_member(
                "sha256", merovingian::canonicaljson::Value{content_hash.sha256}));
            event_with_hash.push_back(merovingian::canonicaljson::make_member(
                "hashes", merovingian::canonicaljson::Value{std::move(hashes_obj)}));
            auto hashed_event = merovingian::canonicaljson::Value{std::move(event_with_hash)};

            // Step 3: sign.
            auto const* policy = merovingian::rooms::find_room_version_policy("10");
            REQUIRE(policy != nullptr);
            auto key_store = FixedSigningKeyStore{
                merovingian::crypto::SigningKeyRecord{"local.example.com", "ed25519:auto",
                                                      merovingian::crypto::Ed25519PublicKey{std::string(32U, '\x01')},
                                                      true}
            };
            auto provider = CapturingEd25519Provider{};
            auto const signed_result = merovingian::events::sign_event_for_server(hashed_event, *policy, key_store,
                                                                                  provider, "local.example.com");

            THEN("the signed event JSON carries hashes.sha256 - accepted by send_join peers")
            {
                REQUIRE(signed_result.error.empty());
                // Spec MUST: every PDU sent to send_join MUST include hashes.sha256.
                // Do NOT remove/change - Synapse and all conformant servers return HTTP 400
                // if this field is absent, preventing the local user from joining the room.
                REQUIRE(signed_result.event_json.find(R"("hashes":{"sha256":)") != std::string::npos);
            }
        }

        WHEN("the event is signed WITHOUT computing the content hash first")
        {
            // This reproduces the pre-fix bug: the old code passed event_to_sign
            // directly to sign_event_for_server without attaching hashes.
            auto const* policy = merovingian::rooms::find_room_version_policy("10");
            REQUIRE(policy != nullptr);
            auto key_store = FixedSigningKeyStore{
                merovingian::crypto::SigningKeyRecord{"local.example.com", "ed25519:auto",
                                                      merovingian::crypto::Ed25519PublicKey{std::string(32U, '\x01')},
                                                      true}
            };
            auto provider = CapturingEd25519Provider{};
            auto const signed_result = merovingian::events::sign_event_for_server(parsed.value, *policy, key_store,
                                                                                  provider, "local.example.com");

            THEN("hashes.sha256 is absent - documents the Synapse rejection this fix prevents")
            {
                REQUIRE(signed_result.error.empty());
                // Without the fix this was the event sent to send_join - no hashes field.
                REQUIRE(signed_result.event_json.find(R"("hashes":{"sha256":)") == std::string::npos);
            }
        }
    }
}

// --- Room version registry ----------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Section: Room Versions
// URL: https://spec.matrix.org/v1.18/rooms/
//
// A conformant server MUST support the stable room versions it advertises in its
// server capabilities. Versions 10, 11, and 12 are the stable modern versions;
// legacy versions (1-9) SHOULD NOT be supported by new implementations.
SCENARIO("Room version registry exposes stable modern room versions", "[rooms]")
{
    GIVEN("known and unsupported room-version IDs")
    {
        auto constexpr known_version = "12";
        auto constexpr unsupported_version = "1";

        WHEN("room-version support is checked")
        {
            auto const known_supported = merovingian::rooms::room_version_is_supported(known_version);
            auto const unsupported_supported = merovingian::rooms::room_version_is_supported(unsupported_version);

            THEN("modern stable versions are supported")
            {
                // Spec MUST: stable room versions 10, 11, and 12 MUST be supported.
                // Do NOT remove/change - advertising support for a version and then failing
                // to handle it breaks federation room join for those room versions.
                REQUIRE(merovingian::rooms::room_version_is_supported("10"));
                REQUIRE(merovingian::rooms::room_version_is_supported("11"));
                REQUIRE(known_supported);
                // Spec: legacy room version 1 SHOULD NOT be supported by this server.
                // Do NOT remove/change - inadvertently enabling legacy versions exposes the
                // server to room version downgrade attacks and old auth rule bugs.
                REQUIRE_FALSE(unsupported_supported);
            }
        }
    }
}

// --- Room version policy fixture pin -----------------------------------------
// Spec: Matrix Server-Server API v1.18
// Section: Room Versions - v10, v11, v12
// URL: https://spec.matrix.org/v1.18/rooms/v10/
// URL: https://spec.matrix.org/v1.18/rooms/v11/
// URL: https://spec.matrix.org/v1.18/rooms/v12/ (draft)
//
// All three modern stable room versions use reference-hash event IDs (room v4+
// format). Room versions 1-10 use the legacy redaction rule set; versions 11+
// use the updated rule set that drops "origin", "prev_state", and "membership".
// These policy differences MUST be correctly encoded in the room version registry.
SCENARIO("Room-version fixtures pin Matrix v10 v11 and v12 policy differences", "[rooms][events]")
{
    GIVEN("the supported modern room-version fixture set")
    {
        auto const* room_v10 = merovingian::rooms::find_room_version_policy("10");
        auto const* room_v11 = merovingian::rooms::find_room_version_policy("11");
        auto const* room_v12 = merovingian::rooms::find_room_version_policy("12");

        WHEN("the room-version policies are inspected")
        {
            auto const fixtures = merovingian::rooms::known_room_versions();

            THEN("each stable version uses reference-hash event IDs and the expected redaction split")
            {
                REQUIRE(room_v10 != nullptr);
                REQUIRE(room_v11 != nullptr);
                REQUIRE(room_v12 != nullptr);
                // Spec MUST: exactly three stable room versions must be registered.
                // Do NOT remove/change - adding or removing versions without updating the
                // capability advertisement breaks federation negotiation.
                REQUIRE(fixtures.size() == 3U);
                // Spec MUST: all three modern room versions MUST be marked stable.
                // Do NOT remove/change - non-stable versions MUST NOT be advertised as
                // the default version for new rooms.
                REQUIRE(room_v10->stable);
                REQUIRE(room_v11->stable);
                REQUIRE(room_v12->stable);
                // Spec MUST: room versions 10, 11, and 12 all use reference-hash event IDs
                // (the format introduced in room version 4).
                // Do NOT remove/change - an incorrect EventIdFormat causes event ID
                // computation to use the wrong algorithm, breaking the entire room DAG.
                REQUIRE(room_v10->event_id_format == merovingian::rooms::EventIdFormat::reference_hash);
                REQUIRE(room_v11->event_id_format == merovingian::rooms::EventIdFormat::reference_hash);
                REQUIRE(room_v12->event_id_format == merovingian::rooms::EventIdFormat::reference_hash);
                // Spec MUST: room version 10 uses the legacy (v1-v10) redaction rule set.
                // Do NOT remove/change - assigning the wrong redaction rules corrupts the
                // reference hash for all events in rooms using that version.
                REQUIRE(room_v10->redaction_rules == merovingian::rooms::RedactionRules::room_v1_v10);
                // Spec MUST: room versions 11 and 12 use the updated (v11+) redaction rules.
                // Do NOT remove/change - using the legacy rules for v11+ events keeps
                // obsolete fields in the reference hash, producing wrong event IDs.
                REQUIRE(room_v11->redaction_rules == merovingian::rooms::RedactionRules::room_v11_plus);
                REQUIRE(room_v12->redaction_rules == merovingian::rooms::RedactionRules::room_v11_plus);
            }
        }
    }
}
