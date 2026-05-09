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
    auto const first = merovingian::canonicaljson::parse_lossless("{\"b\":2,\"a\":1}");
    auto const second = merovingian::canonicaljson::parse_lossless("{\"a\":1,\"b\":2}");

    auto const first_id = merovingian::events::make_content_hash_id(first.value);
    auto const second_id = merovingian::events::make_content_hash_id(second.value);

    REQUIRE(first_id.error.empty());
    REQUIRE(first_id.event_id == second_id.event_id);
    REQUIRE(merovingian::events::event_id_is_valid(first_id.event_id));
}

TEST_CASE("Event envelope parser validates core Matrix fields", "[events]")
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(
        "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_server_ts\":1,\"content\":{}}"
    );

    auto const event = merovingian::events::parse_event_envelope(parsed.value);

    REQUIRE(event.error.empty());
    REQUIRE(event.event.room_id == "!room:example.org");
    REQUIRE(event.event.event_type == "m.room.message");
    REQUIRE(event.event.sender == "@alice:example.org");
}

TEST_CASE("Event signing payload excludes unsigned and signatures", "[events][signing]")
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(
        "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_server_ts\":1,\"unsigned\":{\"age\":1},\"signatures\":{\"example.org\":{\"ed25519:a\":\"sig\"}},\"content\":{}}"
    );

    auto const payload = merovingian::events::make_event_signing_payload(parsed.value);

    REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(payload.output.find("unsigned") == std::string::npos);
    REQUIRE(payload.output.find("signatures") == std::string::npos);
    REQUIRE(payload.output.find("m.room.message") != std::string::npos);
}

TEST_CASE("Event signature scaffold attaches and detects signatures", "[events][signing]")
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(
        "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_server_ts\":1,\"content\":{}}"
    );
    auto const key_id = merovingian::events::SigningKeyId{"example.org", "ed25519:auto"};

    auto const signed_json = merovingian::events::attach_event_signature(parsed.value, key_id, "signature-bytes");
    REQUIRE(signed_json.error == merovingian::canonicaljson::CanonicalJsonError::none);

    auto const reparsed = merovingian::canonicaljson::parse_lossless(signed_json.output);
    auto const verified = merovingian::events::verify_event_signature_presence(reparsed.value, key_id);

    REQUIRE(verified.valid);
    REQUIRE(verified.error.empty());
}

TEST_CASE("Event redaction keeps only allowed keys", "[events][redaction]")
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(
        "{\"room_id\":\"!room:example.org\",\"type\":\"m.room.message\",\"sender\":\"@alice:example.org\",\"origin_server_ts\":1,\"content\":{\"body\":\"secret\"},\"extra\":\"drop\"}"
    );
    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(policy != nullptr);

    auto const redacted = merovingian::events::redact_event(parsed.value, *policy);
    auto const output = merovingian::canonicaljson::serialize_canonical(redacted.event);

    REQUIRE(redacted.error.empty());
    REQUIRE(output.output.find("extra") == std::string::npos);
    REQUIRE(output.output.find("room_id") != std::string::npos);
}

TEST_CASE("Room version registry exposes stable modern room versions", "[rooms]")
{
    REQUIRE(merovingian::rooms::room_version_is_supported("10"));
    REQUIRE(merovingian::rooms::room_version_is_supported("11"));
    REQUIRE(merovingian::rooms::room_version_is_supported("12"));
    REQUIRE_FALSE(merovingian::rooms::room_version_is_supported("1"));
}
