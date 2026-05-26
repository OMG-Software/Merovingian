// SPDX-License-Identifier: GPL-3.0-or-later

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
    [[nodiscard]] auto sign(merovingian::crypto::Ed25519SecretKeyHandle const& key, std::string_view message)
        -> merovingian::crypto::SignatureResult override
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
                REQUIRE(first_id.error.empty());
                REQUIRE(first_id.event_id == second_id.event_id);
                REQUIRE(merovingian::events::event_id_is_valid(first_id.event_id));
            }
        }
    }
}

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
                REQUIRE(content_hash.sha256 == "gsjDCjzrjqiMPUvnSb9TrBx6Jf7B5rbwNep8hWlcTFQ");
                REQUIRE(reference_hash.error.empty());
                REQUIRE(reference_hash.sha256 == "F-VEjF2TNVE5ODdeaHi7OADldkLgev_kV60OIIVlkEg");
                REQUIRE(event_id.event_id == "$F-VEjF2TNVE5ODdeaHi7OADldkLgev_kV60OIIVlkEg");
                REQUIRE(merovingian::events::event_id_is_valid(event_id.event_id));
            }
        }
    }
}

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
                REQUIRE(event.event.room_id == "!room:example.org");
                REQUIRE(event.event.event_type == "m.room.message");
                REQUIRE(event.event.sender == "@alice:example.org");
            }
        }
    }
}

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
                REQUIRE(payload.output.find("unsigned") == std::string::npos);
                REQUIRE(payload.output.find("signatures") == std::string::npos);
                REQUIRE(payload.output.find("m.room.message") != std::string::npos);
            }
        }
    }
}

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
                REQUIRE(payload.output.find("unsigned") == std::string::npos);
                REQUIRE(payload.output.find("signatures") == std::string::npos);
                REQUIRE(payload.output.find("secret") != std::string::npos);
                REQUIRE(payload.output.find(R"("content":{"body":"secret","msgtype":"m.text"})") !=
                        std::string::npos);
                REQUIRE(payload.output.find(R"("hashes":{"sha256":"hash"})") != std::string::npos);
            }
        }
    }
}

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
                REQUIRE(verified.valid);
                REQUIRE(verified.error.empty());
            }
        }
    }
}

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
                REQUIRE(signed_event.signature ==
                        "c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzcw");
                REQUIRE(provider.signed_message.find("secret") != std::string::npos);
                REQUIRE(verified.valid);
                REQUIRE(verified.error.empty());
            }
        }
    }
}

SCENARIO("Event signing keeps member profile fields in the signed payload", "[events][signing][member]")
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

            THEN("the signed payload still contains the member displayname")
            {
                REQUIRE(signed_event.error.empty());
                REQUIRE(provider.signed_message.find("\"displayname\":\"Alice\"") != std::string::npos);
            }
        }
    }
}

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
                REQUIRE(old_signature.valid);
                REQUIRE(new_signature.valid);
            }
        }
    }
}

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
                REQUIRE(output.output.find("extra") == std::string::npos);
                REQUIRE(output.output.find("secret") == std::string::npos);
                REQUIRE(output.output.find("\"room_id\"") != std::string::npos);
            }
        }
    }
}

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
                REQUIRE(output_v10.output.find("\"origin\"") != std::string::npos);
                REQUIRE(output_v10.output.find("\"prev_state\"") != std::string::npos);
                REQUIRE(output_v10.output.find("\"membership\"") != std::string::npos);
                REQUIRE(output_v10.output.find("\"unsigned\"") == std::string::npos);
                REQUIRE(output_v12.output.find("\"origin\"") == std::string::npos);
                REQUIRE(output_v12.output.find("\"prev_state\"") == std::string::npos);
                REQUIRE(output_v12.output.find("\"membership\"") == std::string::npos);
                REQUIRE(output_v12.output.find("\"unsigned\"") == std::string::npos);
            }
        }
    }
}

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
                REQUIRE(merovingian::rooms::room_version_is_supported("10"));
                REQUIRE(merovingian::rooms::room_version_is_supported("11"));
                REQUIRE(known_supported);
                REQUIRE_FALSE(unsupported_supported);
            }
        }
    }
}

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
                REQUIRE(fixtures.size() == 3U);
                REQUIRE(room_v10->stable);
                REQUIRE(room_v11->stable);
                REQUIRE(room_v12->stable);
                REQUIRE(room_v10->event_id_format == merovingian::rooms::EventIdFormat::reference_hash);
                REQUIRE(room_v11->event_id_format == merovingian::rooms::EventIdFormat::reference_hash);
                REQUIRE(room_v12->event_id_format == merovingian::rooms::EventIdFormat::reference_hash);
                REQUIRE(room_v10->redaction_rules == merovingian::rooms::RedactionRules::room_v1_v10);
                REQUIRE(room_v11->redaction_rules == merovingian::rooms::RedactionRules::room_v11_plus);
                REQUIRE(room_v12->redaction_rules == merovingian::rooms::RedactionRules::room_v11_plus);
            }
        }
    }
}
