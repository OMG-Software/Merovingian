// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/canonicaljson/parser.hpp>
#include <merovingian/canonicaljson/serializer.hpp>
#include <merovingian/events/event.hpp>
#include <merovingian/events/event_id.hpp>
#include <merovingian/events/event_signer.hpp>
#include <merovingian/events/redaction.hpp>
#include <merovingian/rooms/room_version_policy.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("Event IDs are deterministic over canonical JSON", "[events]")
{
    // Given
    auto const first = merovingian::canonicaljson::parse_lossless("{\"b\":2,\"a\":1}");
    auto const second = merovingian::canonicaljson::parse_lossless("{\"a\":1,\"b\":2}");

    // When
    auto const first_id = merovingian::events::make_content_hash_id(first.value);
    auto const second_id = merovingian::events::make_content_hash_id(second.value);

    // Then
    REQUIRE(first_id.error.empty());
    REQUIRE(first_id.event_id == second_id.event_id);
    REQUIRE(merovingian::events::event_id_is_valid(first_id.event_id));
}

TEST_CASE("Event envelope parser validates core Matrix fields", "[events]")
{
    // Given
    auto const parsed = merovingian::canonicaljson::parse_lossless(
        "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_server_ts\":1,\"content\":{}}"
    );

    // When
    auto const event = merovingian::events::parse_event_envelope(parsed.value);

    // Then
    REQUIRE(event.error.empty());
    REQUIRE(event.event.room_id == "!room:example.org");
    REQUIRE(event.event.event_type == "m.room.message");
    REQUIRE(event.event.sender == "@alice:example.org");
}

TEST_CASE("Event signing payload excludes unsigned and signatures", "[events][signing]")
{
    // Given
    auto const parsed = merovingian::canonicaljson::parse_lossless(
        "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_server_ts\":1,\"unsigned\":{\"age\":1},\"signatures\":{\"example.org\":{\"ed25519:a\":\"sig\"}},\"content\":{}}"
    );

    // When
    auto const payload = merovingian::events::make_event_signing_payload(parsed.value);

    // Then
    REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(payload.output.find("unsigned") == std::string::npos);
    REQUIRE(payload.output.find("signatures") == std::string::npos);
    REQUIRE(payload.output.find("m.room.message") != std::string::npos);
}

TEST_CASE("Event signature scaffold attaches and detects signatures", "[events][signing]")
{
    // Given
    auto const parsed = merovingian::canonicaljson::parse_lossless(
        "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_server_ts\":1,\"content\":{}}"
    );
    auto const key_id = merovingian::events::SigningKeyId{"example.org", "ed25519:auto"};

    // When
    auto const signed_json = merovingian::events::attach_event_signature(parsed.value, key_id, "signature-bytes");
    auto const reparsed = merovingian::canonicaljson::parse_lossless(signed_json.output);
    auto const verified = merovingian::events::verify_event_signature_presence(reparsed.value, key_id);

    // Then
    REQUIRE(signed_json.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(verified.valid);
    REQUIRE(verified.error.empty());
}

TEST_CASE("Event signature scaffold preserves existing signatures", "[events][signing]")
{
    // Given
    auto const parsed = merovingian::canonicaljson::parse_lossless(
        "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_server_ts\":1,\"content\":{},\"signatures\":{\"old.example.org\":{\"ed25519:old\":\"old-signature\"}}}"
    );
    auto const old_key_id = merovingian::events::SigningKeyId{"old.example.org", "ed25519:old"};
    auto const new_key_id = merovingian::events::SigningKeyId{"example.org", "ed25519:new"};

    // When
    auto const signed_json = merovingian::events::attach_event_signature(parsed.value, new_key_id, "new-signature");
    auto const reparsed = merovingian::canonicaljson::parse_lossless(signed_json.output);
    auto const old_signature = merovingian::events::verify_event_signature_presence(reparsed.value, old_key_id);
    auto const new_signature = merovingian::events::verify_event_signature_presence(reparsed.value, new_key_id);

    // Then
    REQUIRE(signed_json.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(old_signature.valid);
    REQUIRE(new_signature.valid);
}

TEST_CASE("Event redaction keeps only allowed keys", "[events][redaction]")
{
    // Given
    auto const parsed = merovingian::canonicaljson::parse_lossless(
        "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_server_ts\":1,\"content\":{\"body\":\"secret\"},\"extra\":\"drop\"}"
    );
    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(policy != nullptr);

    // When
    auto const redacted = merovingian::events::redact_event(parsed.value, *policy);
    auto const output = merovingian::canonicaljson::serialize_canonical(redacted.event);

    // Then
    REQUIRE(redacted.error.empty());
    REQUIRE(output.output.find("extra") == std::string::npos);
    REQUIRE(output.output.find("\"room_id\"") != std::string::npos);
}

TEST_CASE("Event redaction uses room-version-specific top-level keys", "[events][redaction]")
{
    // Given
    auto const parsed = merovingian::canonicaljson::parse_lossless(
        "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_server_ts\":1,\"content\":{},\"origin\":\"example.org\",\"prev_state\":[],\"membership\":\"join\",\"unsigned\":{}}"
    );
    auto const* room_v10 = merovingian::rooms::find_room_version_policy("10");
    auto const* room_v12 = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(room_v10 != nullptr);
    REQUIRE(room_v12 != nullptr);

    // When
    auto const redacted_v10 = merovingian::events::redact_event(parsed.value, *room_v10);
    auto const redacted_v12 = merovingian::events::redact_event(parsed.value, *room_v12);
    auto const output_v10 = merovingian::canonicaljson::serialize_canonical(redacted_v10.event);
    auto const output_v12 = merovingian::canonicaljson::serialize_canonical(redacted_v12.event);

    // Then
    REQUIRE(output_v10.output.find("\"origin\"") != std::string::npos);
    REQUIRE(output_v10.output.find("\"prev_state\"") != std::string::npos);
    REQUIRE(output_v10.output.find("\"membership\"") != std::string::npos);
    REQUIRE(output_v10.output.find("\"unsigned\"") == std::string::npos);
    REQUIRE(output_v12.output.find("\"origin\"") == std::string::npos);
    REQUIRE(output_v12.output.find("\"prev_state\"") == std::string::npos);
    REQUIRE(output_v12.output.find("\"membership\"") == std::string::npos);
    REQUIRE(output_v12.output.find("\"unsigned\"") != std::string::npos);
}

TEST_CASE("Room version registry exposes stable modern room versions", "[rooms]")
{
    // Given
    auto constexpr known_version = "12";
    auto constexpr unsupported_version = "1";

    // When
    auto const known_supported = merovingian::rooms::room_version_is_supported(known_version);
    auto const unsupported_supported = merovingian::rooms::room_version_is_supported(unsupported_version);

    // Then
    REQUIRE(merovingian::rooms::room_version_is_supported("10"));
    REQUIRE(merovingian::rooms::room_version_is_supported("11"));
    REQUIRE(known_supported);
    REQUIRE_FALSE(unsupported_supported);
}
