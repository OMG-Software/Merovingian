// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Unit tests for events/event_signer.cpp: signing_key_id_is_valid, base64
// helpers, make_event_signing_payload, attach_event_signature,
// sign_event_for_server, verify_event_signature_presence,
// verify_event_signature.

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

#include <sodium.h>

namespace
{

[[nodiscard]] auto sodium_ready() noexcept -> bool
{
    static auto const ready = sodium_init() >= 0;
    return ready;
}

[[nodiscard]] auto parse_json(std::string_view json) -> merovingian::canonicaljson::Value
{
    auto result = merovingian::canonicaljson::parse_lossless(json);
    REQUIRE(result.error == merovingian::canonicaljson::ParseError::none);
    return std::move(result.value);
}

// All fields required by redaction and signing pipelines.
[[nodiscard]] auto minimal_event_json() -> std::string_view
{
    return R"({"auth_events":[],"content":{},"depth":1,"origin_server_ts":1,"prev_events":[],"room_id":"!room:example.org","sender":"@alice:example.org","type":"m.room.message"})";
}

[[nodiscard]] auto default_policy() -> merovingian::rooms::RoomVersionPolicy
{
    return {}; // room_v11_plus redaction, v6_plus auth — sufficient for unit tests
}

class StubSigningKeyStore final : public merovingian::crypto::SigningKeyStore
{
public:
    explicit StubSigningKeyStore(merovingian::crypto::SigningKeyRecord key)
        : m_key{std::move(key)}
    {
    }

    [[nodiscard]] auto active_key_for_server(std::string_view server_name)
        -> merovingian::crypto::SigningKeyLookupResult override
    {
        if (server_name != m_key.server_name)
        {
            return {{}, "signing key not found for server"};
        }
        return {m_key, {}};
    }

private:
    merovingian::crypto::SigningKeyRecord m_key{};
};

// Provider whose verify outcome is controlled by m_verify_succeeds.
class StubEd25519Provider final : public merovingian::crypto::Ed25519Provider
{
public:
    explicit StubEd25519Provider(bool verify_succeeds = true)
        : m_verify_succeeds{verify_succeeds}
    {
    }

    [[nodiscard]] auto sign(merovingian::crypto::Ed25519SecretKeyHandle const& key, std::string_view message)
        -> merovingian::crypto::SignatureResult override
    {
        if (key.key_id != "ed25519:auto" || message.empty())
        {
            return {{}, "sign rejected"};
        }
        return {merovingian::crypto::Ed25519Signature{std::string(64U, 's')}, {}};
    }

    [[nodiscard]] auto verify(merovingian::crypto::Ed25519PublicKey const& public_key, std::string_view message,
                              merovingian::crypto::Ed25519Signature const& signature)
        -> merovingian::crypto::VerificationResult override
    {
        if (!m_verify_succeeds)
        {
            return {false, "signature verification failed"};
        }
        auto const ok = public_key.bytes.size() == 32U && !message.empty() && signature.bytes == std::string(64U, 's');
        return {ok, ok ? std::string{} : std::string{"signature verification failed"}};
    }

private:
    bool m_verify_succeeds{true};
};

[[nodiscard]] auto valid_stub_store() -> StubSigningKeyStore
{
    return StubSigningKeyStore{
        merovingian::crypto::SigningKeyRecord{
                                              "example.org", "ed25519:auto",
                                              merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')},
                                              true, }
    };
}

// Returns a base64 string that decodes to exactly 64 bytes — passes
// signature_is_valid_shape().
[[nodiscard]] auto valid_sig_b64() -> std::string
{
    REQUIRE(sodium_ready());
    return merovingian::events::matrix_base64_from_bytes(std::string(64U, 's'));
}

} // namespace

// ---------------------------------------------------------------------------
// signing_key_id_is_valid
// ---------------------------------------------------------------------------

SCENARIO("signing_key_id_is_valid accepts printable key IDs and rejects malformed ones",
         "[events][event-signer][key-id]")
{
    GIVEN("various SigningKeyId inputs")
    {
        REQUIRE(sodium_ready());

        WHEN("both fields are non-empty and printable")
        {
            THEN("the key ID is valid")
            {
                REQUIRE(merovingian::events::signing_key_id_is_valid({"example.org", "ed25519:auto"}));
            }
        }

        WHEN("server_name is empty")
        {
            THEN("the key ID is rejected")
            {
                REQUIRE_FALSE(merovingian::events::signing_key_id_is_valid({"", "ed25519:auto"}));
            }
        }

        WHEN("key_id is empty")
        {
            THEN("the key ID is rejected")
            {
                REQUIRE_FALSE(merovingian::events::signing_key_id_is_valid({"example.org", ""}));
            }
        }

        WHEN("server_name contains a control character (0x01)")
        {
            THEN("the key ID is rejected — control characters are forbidden in server names")
            {
                REQUIRE_FALSE(merovingian::events::signing_key_id_is_valid({"exam\x01ple.org", "ed25519:auto"}));
            }
        }

        WHEN("key_id contains a space character")
        {
            THEN("the key ID is rejected — spaces are forbidden in key IDs")
            {
                REQUIRE_FALSE(merovingian::events::signing_key_id_is_valid({"example.org", "ed25519 auto"}));
            }
        }

        WHEN("key_id contains DEL (0x7F)")
        {
            THEN("the key ID is rejected")
            {
                REQUIRE_FALSE(merovingian::events::signing_key_id_is_valid({"example.org", "ed25519:\x7f"}));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// matrix_base64_from_bytes / matrix_bytes_from_base64
// ---------------------------------------------------------------------------

SCENARIO("matrix_base64_from_bytes and matrix_bytes_from_base64 round-trip binary data",
         "[events][event-signer][base64]")
{
    GIVEN("arbitrary binary data including null and high bytes")
    {
        REQUIRE(sodium_ready());
        auto const input = std::string{"\x00\x01\x7f\xfe\xff", 5U};

        WHEN("the data is encoded then decoded")
        {
            auto const encoded = merovingian::events::matrix_base64_from_bytes(input);
            auto const decoded = merovingian::events::matrix_bytes_from_base64(encoded);

            THEN("the decoded bytes match the original")
            {
                REQUIRE_FALSE(encoded.empty());
                REQUIRE(decoded == input);
            }
        }
    }
}

SCENARIO("matrix_base64_from_bytes returns empty for empty input", "[events][event-signer][base64][boundary]")
{
    GIVEN("an empty byte string")
    {
        REQUIRE(sodium_ready());

        WHEN("encoding is attempted")
        {
            auto const encoded = merovingian::events::matrix_base64_from_bytes("");

            THEN("the result is empty — nothing to encode")
            {
                REQUIRE(encoded.empty());
            }
        }
    }
}

SCENARIO("matrix_bytes_from_base64 returns empty for invalid base64", "[events][event-signer][base64][boundary]")
{
    GIVEN("a string that is not valid unpadded base64")
    {
        REQUIRE(sodium_ready());

        WHEN("decoding is attempted")
        {
            auto const decoded = merovingian::events::matrix_bytes_from_base64("not-valid-base64!!!");

            THEN("the result is empty — invalid input is rejected")
            {
                REQUIRE(decoded.empty());
            }
        }
    }
}

SCENARIO("matrix_bytes_from_base64 returns empty for empty input", "[events][event-signer][base64][boundary]")
{
    GIVEN("an empty encoded string")
    {
        REQUIRE(sodium_ready());

        WHEN("decoding is attempted")
        {
            auto const decoded = merovingian::events::matrix_bytes_from_base64("");

            THEN("the result is empty")
            {
                REQUIRE(decoded.empty());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// make_event_signing_payload (no policy)
// ---------------------------------------------------------------------------

SCENARIO("make_event_signing_payload strips unsigned and signatures fields", "[events][event-signer][payload]")
{
    GIVEN("a JSON object containing unsigned and signatures fields")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(
            R"({"content":{},"signatures":{"e.org":{"ed25519:auto":"sig"}},"type":"m.test","unsigned":{"age":42}})");

        WHEN("the signing payload is constructed")
        {
            auto const result = merovingian::events::make_event_signing_payload(event);

            THEN("unsigned and signatures are absent from the payload")
            {
                REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(result.output.find("\"unsigned\"") == std::string::npos);
                REQUIRE(result.output.find("\"signatures\"") == std::string::npos);
                REQUIRE(result.output.find("\"content\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("make_event_signing_payload fails for a non-object JSON value", "[events][event-signer][payload][error]")
{
    GIVEN("a JSON string value instead of an object")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(R"("not-an-object")");

        WHEN("the signing payload is constructed")
        {
            auto const result = merovingian::events::make_event_signing_payload(event);

            THEN("an error is returned — only objects can be signed")
            {
                REQUIRE(result.error != merovingian::canonicaljson::CanonicalJsonError::none);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// make_event_signing_payload (with RoomVersionPolicy)
// ---------------------------------------------------------------------------

SCENARIO("make_event_signing_payload with policy redacts and strips event_id",
         "[events][event-signer][payload][redaction]")
{
    GIVEN("a valid room event and a default room version policy")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(minimal_event_json());
        auto const policy = default_policy();

        WHEN("the signing payload is constructed")
        {
            auto const result = merovingian::events::make_event_signing_payload(event, policy);

            THEN("the payload serialises without signatures, unsigned, or event_id")
            {
                REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE_FALSE(result.output.empty());
                REQUIRE(result.output.find("\"signatures\"") == std::string::npos);
                REQUIRE(result.output.find("\"unsigned\"") == std::string::npos);
                REQUIRE(result.output.find("\"event_id\"") == std::string::npos);
            }
        }
    }
}

SCENARIO("make_event_signing_payload with policy fails for a non-object event",
         "[events][event-signer][payload][error]")
{
    GIVEN("a JSON array instead of an event object")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(R"([1, 2, 3])");
        auto const policy = default_policy();

        WHEN("the signing payload is constructed")
        {
            auto const result = merovingian::events::make_event_signing_payload(event, policy);

            THEN("an error is returned — arrays cannot be signed as events")
            {
                REQUIRE(result.error != merovingian::canonicaljson::CanonicalJsonError::none);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// attach_event_signature
// ---------------------------------------------------------------------------

SCENARIO("attach_event_signature embeds a valid signature into an event JSON",
         "[events][event-signer][attach-signature]")
{
    GIVEN("a valid event, key ID, and base64-encoded Ed25519 signature")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(minimal_event_json());
        auto const key_id = merovingian::events::SigningKeyId{"example.org", "ed25519:auto"};
        auto const sig = valid_sig_b64();

        WHEN("the signature is attached")
        {
            auto const result = merovingian::events::attach_event_signature(event, key_id, sig);

            THEN("the result includes a properly nested signatures block")
            {
                REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(result.output.find("\"signatures\"") != std::string::npos);
                REQUIRE(result.output.find("\"example.org\"") != std::string::npos);
                REQUIRE(result.output.find("\"ed25519:auto\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("attach_event_signature fails when the key ID has an empty server_name",
         "[events][event-signer][attach-signature][error]")
{
    GIVEN("an empty server_name in the key ID")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(minimal_event_json());
        auto const key_id = merovingian::events::SigningKeyId{"", "ed25519:auto"};
        auto const sig = valid_sig_b64();

        WHEN("the signature is attached")
        {
            auto const result = merovingian::events::attach_event_signature(event, key_id, sig);

            THEN("attachment fails — empty server_name is invalid")
            {
                REQUIRE(result.error != merovingian::canonicaljson::CanonicalJsonError::none);
            }
        }
    }
}

SCENARIO("attach_event_signature fails when the signature decodes to the wrong byte count",
         "[events][event-signer][attach-signature][error]")
{
    GIVEN("a base64 string that decodes to fewer than 64 bytes")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(minimal_event_json());
        auto const key_id = merovingian::events::SigningKeyId{"example.org", "ed25519:auto"};
        // "c2hvcnQ" decodes to "short" (5 bytes, not 64)
        auto const bad_sig = std::string{"c2hvcnQ"};

        WHEN("the signature is attached")
        {
            auto const result = merovingian::events::attach_event_signature(event, key_id, bad_sig);

            THEN("attachment fails — invalid signature shape is rejected")
            {
                REQUIRE(result.error != merovingian::canonicaljson::CanonicalJsonError::none);
            }
        }
    }
}

SCENARIO("attach_event_signature fails when the event is not a JSON object",
         "[events][event-signer][attach-signature][error]")
{
    GIVEN("a JSON array in place of an event object")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(R"([])");
        auto const key_id = merovingian::events::SigningKeyId{"example.org", "ed25519:auto"};
        auto const sig = valid_sig_b64();

        WHEN("the signature is attached")
        {
            auto const result = merovingian::events::attach_event_signature(event, key_id, sig);

            THEN("attachment fails — only objects can carry signatures")
            {
                REQUIRE(result.error != merovingian::canonicaljson::CanonicalJsonError::none);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// sign_event_for_server
// ---------------------------------------------------------------------------

SCENARIO("sign_event_for_server signs a valid event with the active server key", "[events][event-signer][sign-event]")
{
    GIVEN("a minimal event, default policy, and a valid signing key store")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(minimal_event_json());
        auto const policy = default_policy();
        auto store = valid_stub_store();
        auto provider = StubEd25519Provider{};

        WHEN("the event is signed for example.org")
        {
            auto const result =
                merovingian::events::sign_event_for_server(event, policy, store, provider, "example.org");

            THEN("signing succeeds and the result carries server_name, key_id, and signature")
            {
                REQUIRE(result.error.empty());
                REQUIRE(result.server_name == "example.org");
                REQUIRE(result.key_id == "ed25519:auto");
                REQUIRE_FALSE(result.signature.empty());
                REQUIRE_FALSE(result.event_json.empty());
                REQUIRE(result.event_json.find("\"signatures\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("sign_event_for_server fails when the event is not a JSON object", "[events][event-signer][sign-event][error]")
{
    GIVEN("a JSON string in place of an event")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(R"("not-an-event")");
        auto const policy = default_policy();
        auto store = valid_stub_store();
        auto provider = StubEd25519Provider{};

        WHEN("signing is attempted")
        {
            auto const result =
                merovingian::events::sign_event_for_server(event, policy, store, provider, "example.org");

            THEN("signing fails — payload construction requires an object")
            {
                REQUIRE_FALSE(result.error.empty());
            }
        }
    }
}

SCENARIO("sign_event_for_server fails when no key exists for the requested server",
         "[events][event-signer][sign-event][error]")
{
    GIVEN("a valid event but a key store that only holds a key for example.org")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(minimal_event_json());
        auto const policy = default_policy();
        auto store = valid_stub_store();
        auto provider = StubEd25519Provider{};

        WHEN("signing is requested for a server with no key")
        {
            auto const result =
                merovingian::events::sign_event_for_server(event, policy, store, provider, "no-key.org");

            THEN("signing fails — key store has no entry for no-key.org")
            {
                REQUIRE_FALSE(result.error.empty());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// verify_event_signature_presence
// ---------------------------------------------------------------------------

SCENARIO("verify_event_signature_presence rejects an invalid signing key ID",
         "[events][event-signer][verify-presence][error]")
{
    GIVEN("a key ID with an empty server_name")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(minimal_event_json());

        WHEN("presence is checked with an empty key ID")
        {
            auto const result = merovingian::events::verify_event_signature_presence(event, {"", "ed25519:auto"});

            THEN("verification fails with 'invalid signing key id'")
            {
                REQUIRE_FALSE(result.valid);
                REQUIRE(result.error == "invalid signing key id");
            }
        }
    }
}

SCENARIO("verify_event_signature_presence rejects a non-object event", "[events][event-signer][verify-presence][error]")
{
    GIVEN("a JSON array instead of an event")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(R"([])");

        WHEN("presence is checked")
        {
            auto const result =
                merovingian::events::verify_event_signature_presence(event, {"example.org", "ed25519:auto"});

            THEN("verification fails with 'event must be an object'")
            {
                REQUIRE_FALSE(result.valid);
                REQUIRE(result.error == "event must be an object");
            }
        }
    }
}

SCENARIO("verify_event_signature_presence rejects an event with no signatures field",
         "[events][event-signer][verify-presence][error]")
{
    GIVEN("a minimal event that has no signatures field")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(minimal_event_json());

        WHEN("presence is checked")
        {
            auto const result =
                merovingian::events::verify_event_signature_presence(event, {"example.org", "ed25519:auto"});

            THEN("verification fails with 'missing signatures'")
            {
                REQUIRE_FALSE(result.valid);
                REQUIRE(result.error == "missing signatures");
            }
        }
    }
}

SCENARIO("verify_event_signature_presence rejects when the queried server is absent from signatures",
         "[events][event-signer][verify-presence][error]")
{
    GIVEN("an event signed by other.org but queried for example.org")
    {
        REQUIRE(sodium_ready());
        // The signature value can be any string; this test only exercises the
        // server-name lookup path, not signature shape validation.
        auto const event =
            parse_json(R"({"content":{},"signatures":{"other.org":{"ed25519:auto":"placeholder"}},"type":"m.test"})");

        WHEN("presence is checked for example.org")
        {
            auto const result =
                merovingian::events::verify_event_signature_presence(event, {"example.org", "ed25519:auto"});

            THEN("verification fails with 'missing server signature'")
            {
                REQUIRE_FALSE(result.valid);
                REQUIRE(result.error == "missing server signature");
            }
        }
    }
}

SCENARIO("verify_event_signature_presence accepts a correctly structured signature block",
         "[events][event-signer][verify-presence]")
{
    GIVEN("an event signed and then re-parsed")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(minimal_event_json());
        auto const policy = default_policy();
        auto store = valid_stub_store();
        auto provider = StubEd25519Provider{};

        auto const signed_result =
            merovingian::events::sign_event_for_server(event, policy, store, provider, "example.org");
        REQUIRE(signed_result.error.empty());

        auto const parsed = merovingian::canonicaljson::parse_lossless(signed_result.event_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("presence is checked for the signing server and key")
        {
            auto const result =
                merovingian::events::verify_event_signature_presence(parsed.value, {"example.org", "ed25519:auto"});

            THEN("presence verification succeeds")
            {
                REQUIRE(result.valid);
                REQUIRE(result.error.empty());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// verify_event_signature — end-to-end
// ---------------------------------------------------------------------------

SCENARIO("verify_event_signature validates a correctly signed event end-to-end", "[events][event-signer][verify]")
{
    GIVEN("an event signed by the stub provider")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(minimal_event_json());
        auto const policy = default_policy();
        auto store = valid_stub_store();
        auto provider = StubEd25519Provider{};

        auto const signed_result =
            merovingian::events::sign_event_for_server(event, policy, store, provider, "example.org");
        REQUIRE(signed_result.error.empty());

        auto const parsed = merovingian::canonicaljson::parse_lossless(signed_result.event_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the event is verified with the matching key and provider")
        {
            auto const public_key = merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')};
            auto const result = merovingian::events::verify_event_signature(
                parsed.value, policy, {"example.org", "ed25519:auto"}, public_key, provider);

            THEN("verification succeeds")
            {
                REQUIRE(result.valid);
                REQUIRE(result.error.empty());
            }
        }
    }
}

SCENARIO("verify_event_signature fails when the provider rejects the signature",
         "[events][event-signer][verify][error]")
{
    GIVEN("a signed event and a provider configured to fail all verifications")
    {
        REQUIRE(sodium_ready());
        auto const event = parse_json(minimal_event_json());
        auto const policy = default_policy();
        auto store = valid_stub_store();
        auto signing_provider = StubEd25519Provider{true};

        auto const signed_result =
            merovingian::events::sign_event_for_server(event, policy, store, signing_provider, "example.org");
        REQUIRE(signed_result.error.empty());

        auto const parsed = merovingian::canonicaljson::parse_lossless(signed_result.event_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        auto failing_provider = StubEd25519Provider{false}; // always fails verify

        WHEN("verification is attempted with the failing provider")
        {
            auto const public_key = merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')};
            auto const result = merovingian::events::verify_event_signature(
                parsed.value, policy, {"example.org", "ed25519:auto"}, public_key, failing_provider);

            THEN("verification fails — the provider rejected the signature")
            {
                REQUIRE_FALSE(result.valid);
                REQUIRE_FALSE(result.error.empty());
            }
        }
    }
}
