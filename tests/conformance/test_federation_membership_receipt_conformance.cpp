// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Conformance audit 2026-10-17, wave 2: how the direct membership endpoints
// (send_join, send_leave, send_knock, invite; v1 and v2) apply the receipt
// checks to the event they carry.

#include "../federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/runtime_federation.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

[[nodiscard]] auto runtime_config() -> merovingian::federation::RuntimeFederationConfig
{
    auto config = merovingian::federation::RuntimeFederationConfig{};
    config.enabled = true;
    config.default_policy = "allow";
    config.require_valid_tls = true;
    config.verify_json_signatures = true;
    config.max_transaction_bytes = 16384U;
    config.remote_timeout_seconds = 30U;
    config.server_name = "local.example.org";
    return config;
}

[[nodiscard]] auto remote_for(std::string const& origin, std::string const& key_id,
                              std::string const& key_seed) -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = origin;
    remote.signing_key = {origin, key_id, 4'102'444'800'000U,
                          merovingian::federation::test::keypair_from_seed(key_seed).public_key};
    remote.discovery.server_name = origin;
    remote.discovery.well_known_host = origin;
    remote.discovery.resolved_host = origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto signed_put_request(std::string const& origin, std::string const& key_id, std::string const& key_seed,
                                      std::string const& target,
                                      std::string const& body) -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "PUT";
    request.target = target;
    request.origin = origin;
    request.destination = "local.example.org";
    request.key_id = key_id;
    request.now_ts = 1000U;
    request.canonical_json_verified = true;
    request.body = body;
    request.signature = merovingian::federation::make_federation_signature(
        request.origin, request.destination, request.method, request.target, request.body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return request;
}

// A membership event signed by `origin`, then given an extra content key the
// redaction algorithm strips. The signature covers only the redacted form, so it
// still verifies, but the content hash no longer matches: exactly the case the
// spec answers with redaction, not rejection.
struct HashMismatchedEvent final
{
    std::string json{};
    std::string event_id{};
};

[[nodiscard]] auto hash_mismatched_member_event(std::string const& origin, std::string const& key_id,
                                                std::string const& token, std::string const& room_id,
                                                std::string const& sender, std::string const& state_key,
                                                std::string const& membership) -> HashMismatchedEvent
{
    auto const unsigned_json = std::string{R"({"auth_events":[],"content":{"membership":")"} + membership +
                               R"("},"depth":2,"origin_server_ts":1000001,"prev_events":[],"room_id":")" + room_id +
                               R"(","sender":")" + sender + R"(","state_key":")" + state_key +
                               R"(","type":"m.room.member"})";
    auto json = merovingian::federation::test::make_signed_event_json(unsigned_json, origin, key_id, token, "12");
    REQUIRE_FALSE(json.empty());
    auto const original_id = merovingian::federation::test::reference_hash_event_id(json, "12");
    auto const marker = std::string{R"("content":{"membership":)"};
    auto const at = json.find(marker);
    REQUIRE(at != std::string::npos);
    json.insert(at + std::string_view{R"("content":{)"}.size(), R"("displayname":"Mallory",)");
    auto const parsed = merovingian::canonicaljson::parse_lossless(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    REQUIRE_FALSE(merovingian::events::verify_pdu_content_hash(parsed.value));
    // The reference hash is taken over the redacted event, so the ID is unchanged.
    REQUIRE(merovingian::federation::test::reference_hash_event_id(json, "12") == original_id);
    return {json, original_id};
}

// Flips one character of the signature `server`/`key_id` carries, so it no
// longer verifies.
[[nodiscard]] auto with_broken_signature(std::string json, std::string const& key_id) -> std::string
{
    auto const marker = "\"" + key_id + "\":\"";
    auto const at = json.find(marker);
    REQUIRE(at != std::string::npos);
    auto const value_at = at + marker.size();
    json[value_at] = json[value_at] == 'A' ? 'B' : 'A';
    return json;
}

struct MembershipRoute final
{
    std::string prefix{};
    std::string membership{};
};

// Lists `key_ids` under `server`'s signatures ahead of whatever it already
// carries, each with a well-formed base64 value that signs nothing.
[[nodiscard]] auto with_junk_signatures_first(std::string json, std::string const& server,
                                              std::vector<std::string> const& key_ids) -> std::string
{
    auto const marker = "\"" + server + "\":{";
    auto const at = json.find(marker);
    REQUIRE(at != std::string::npos);
    auto junk = std::string{};
    for (auto const& key_id : key_ids)
    {
        junk += "\"" + key_id + "\":\"" + std::string(86U, 'A') + "\",";
    }
    json.insert(at + marker.size(), junk);
    REQUIRE(merovingian::canonicaljson::parse_lossless(json).error == merovingian::canonicaljson::ParseError::none);
    return json;
}

[[nodiscard]] auto message_event_by(std::string const& server, std::string const& key_id,
                                    std::string const& seed) -> std::string
{
    auto const unsigned_json = std::string{R"({"auth_events":[],"content":{"body":"hi","msgtype":"m.text"},"depth":3,)"
                                           R"("origin_server_ts":1000002,"prev_events":[],"room_id":"!room:)"} +
                               server + R"(","sender":"@alice:)" + server + R"(","type":"m.room.message"})";
    auto json = merovingian::federation::test::make_signed_event_json(unsigned_json, server, key_id, seed, "12");
    REQUIRE_FALSE(json.empty());
    return json;
}

} // namespace

// Spec: Matrix Server-Server API v1.19
// Section: Checks performed on receipt of a PDU; PUT /send_join, /send_leave, /send_knock
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
//
// "3. Passes hash checks, otherwise it is redacted before being processed further."
// The endpoints themselves list only a signature failure among the reasons to
// refuse the event: "servers SHOULD return `M_INVALID_PARAM` if: The join event
// fails a signature check". A hash mismatch therefore reaches the acceptor, which
// redacts it (test_membership_acceptor_receipt_checks.cpp); a bad signature is
// still refused (audit R06).
SCENARIO("Direct membership endpoints pass a hash-mismatched event on for redaction and refuse a bad signature",
         "[federation][conformance][membership][r06]")
{
    GIVEN("a runtime whose membership acceptor records what reaches it")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"remote.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"r06-membership-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        auto calls = std::make_shared<std::size_t>(0U);
        runtime.membership_acceptor = [calls](merovingian::federation::FederationEndpoint, std::string_view,
                                              std::string_view, merovingian::federation::InboundPduEnvelope const&) {
            ++*calls;
            auto result = merovingian::federation::MembershipAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            result.room_version = "12";
            return result;
        };
        auto const route = GENERATE(MembershipRoute{"/_matrix/federation/v2/send_join/", "join"},
                                    MembershipRoute{"/_matrix/federation/v1/send_join/", "join"},
                                    MembershipRoute{"/_matrix/federation/v2/send_leave/", "leave"},
                                    MembershipRoute{"/_matrix/federation/v1/send_leave/", "leave"},
                                    MembershipRoute{"/_matrix/federation/v1/send_knock/", "knock"});
        CAPTURE(route.prefix);
        auto const room_id = std::string{"!room:local.example.org"};
        auto const sender = std::string{"@alice:remote.example.org"};
        auto const event =
            hash_mismatched_member_event(origin, key_id, token, room_id, sender, sender, route.membership);
        auto const target = route.prefix + room_id + "/" + event.event_id;

        WHEN("an event whose content hash does not match is submitted")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_put_request(origin, key_id, token, target, event.json));

            THEN("it is not refused for its hash but handed on to be redacted and processed")
            {
                // Spec MUST: a hash failure redacts, it does not reject.
                REQUIRE(response.status == 200U);
                REQUIRE(*calls == 1U);
            }
        }

        WHEN("an event whose signature does not verify is submitted")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_put_request(origin, key_id, token, target, with_broken_signature(event.json, key_id)));

            THEN("it is refused with M_INVALID_PARAM and never reaches the acceptor")
            {
                // Spec SHOULD: M_INVALID_PARAM when the event fails a signature check.
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(*calls == 0U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Section: PUT /_matrix/federation/v1/invite and v2/invite; Checks performed on receipt of a PDU
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2inviteroomideventid
//
// "servers SHOULD return `M_INVALID_PARAM` if: The invite event fails a signature
// check" — the hash is not on that list, and step 3 of the receipt checks redacts
// on a hash mismatch. The invite handler redacts before it signs (audit R06).
SCENARIO("The invite endpoints pass a hash-mismatched invite on for redaction and refuse a bad signature",
         "[federation][conformance][membership][r06]")
{
    GIVEN("a runtime whose invite handler records what reaches it")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"remote.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"r06-invite-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        auto seen = std::make_shared<std::vector<merovingian::federation::InviteRequest>>();
        runtime.room_version_resolver = [](std::string_view) {
            return std::string{"12"};
        };
        runtime.invite_handler = [seen](merovingian::federation::InviteRequest const& request) {
            seen->push_back(request);
            auto result = merovingian::federation::InviteAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            result.signed_event_json = request.invite_event_json;
            return result;
        };
        auto const room_id = std::string{"!room:remote.example.org"};
        auto const event = hash_mismatched_member_event(origin, key_id, token, room_id, "@alice:remote.example.org",
                                                        "@bob:local.example.org", "invite");
        auto const v2 = GENERATE(true, false);
        CAPTURE(v2);
        auto const body_for = [&](std::string const& event_json) {
            return v2 ? std::string{R"({"room_version":"12","event":)"} + event_json + R"(,"invite_room_state":[]})"
                      : event_json;
        };
        auto const target = std::string{v2 ? "/_matrix/federation/v2/invite/" : "/_matrix/federation/v1/invite/"} +
                            room_id + "/" + event.event_id;

        WHEN("an invite whose content hash does not match is submitted")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_put_request(origin, key_id, token, target, body_for(event.json)));

            THEN("it reaches the invite handler, which is told the room version the event was checked under")
            {
                // Spec MUST: a hash failure redacts, it does not reject.
                REQUIRE(response.status == 200U);
                REQUIRE(seen->size() == 1U);
                REQUIRE(seen->front().room_version == "12");
            }
        }

        WHEN("an invite whose signature does not verify is submitted")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime,
                signed_put_request(origin, key_id, token, target, body_for(with_broken_signature(event.json, key_id))));

            THEN("it is refused with M_INVALID_PARAM and never reaches the handler")
            {
                // Spec SHOULD: M_INVALID_PARAM when the invite fails a signature check.
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(seen->empty());
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19 and Appendices v1.19
// Section: Validating hashes and signatures on received events; Checking for a Signature
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#validating-hashes-and-signatures-on-received-events
// URL: ../../docs/matrix-v1.19-spec/appendices.md#checking-for-a-signature
//
// "If a signature is from an unknown or expired key, it is skipped." and
// "Removes any signing key identifiers from the entry with algorithms it
// doesn't understand." The signatures object is not covered by any signature,
// so whoever relays an event can list extra key IDs: the check uses every key
// ID listed for the sender's server, not only the first, and an attacker-made
// list costs at most max_signature_keys_per_server lookups (audit R05, ADR-0179).
SCENARIO("The sender's signature is checked against every key ID listed for its server, within a bound",
         "[federation][conformance][signatures][r05]")
{
    GIVEN("an event signed by its sender's genuine key, with other key IDs listed ahead of it")
    {
        auto const server = std::string{"alice.example.org"};
        auto const genuine_id = std::string{"ed25519:zz_genuine"};
        auto const genuine_key = remote_for(server, genuine_id, "alice-genuine").signing_key;
        auto const wrong_key = remote_for(server, "ed25519:ab_wrong", "alice-other").signing_key;
        auto const genuine = message_event_by(server, genuine_id, "alice-genuine");
        auto calls = std::size_t{0U};
        auto denied_id = std::string{};
        auto const resolver =
            merovingian::federation::SignatureKeyResolver{[&](std::string_view server_name, std::string_view key_id) {
                ++calls;
                if (server_name != server)
                {
                    return merovingian::federation::VerificationKeyResolution{};
                }
                if (key_id == denied_id)
                {
                    return merovingian::federation::VerificationKeyResolution{std::nullopt, true};
                }
                if (key_id == genuine_id)
                {
                    return merovingian::federation::VerificationKeyResolution{genuine_key};
                }
                if (key_id == wrong_key.key_id)
                {
                    return merovingian::federation::VerificationKeyResolution{wrong_key};
                }
                return merovingian::federation::VerificationKeyResolution{};
            }};
        auto const pdu_of = [](std::string const& json) {
            auto pdu = merovingian::federation::parse_federation_pdu(json);
            REQUIRE_FALSE(pdu.event_id.empty());
            return pdu;
        };

        WHEN("an unknown key and a key that resolves but does not verify are listed first")
        {
            auto const pdu =
                pdu_of(with_junk_signatures_first(genuine, server, {"ed25519:aa_unknown", wrong_key.key_id}));
            auto const decision = merovingian::federation::authorize_federation_pdu_sender(pdu, std::nullopt, resolver);

            THEN("the genuine signature listed after them is found and the event is accepted")
            {
                // Spec: an unknown key is skipped; the check is not limited to the first key ID.
                REQUIRE(decision.accepted);
                REQUIRE(calls == 3U);
            }
        }

        WHEN("more key IDs than the bound are listed ahead of the genuine one")
        {
            auto junk = std::vector<std::string>{};
            for (auto i = std::size_t{0U}; i < merovingian::federation::max_signature_keys_per_server; ++i)
            {
                junk.push_back("ed25519:a" + std::to_string(i));
            }
            auto const pdu = pdu_of(with_junk_signatures_first(genuine, server, junk));
            auto const decision = merovingian::federation::authorize_federation_pdu_sender(pdu, std::nullopt, resolver);

            THEN("the event is refused, fail-closed, after no more lookups than the bound")
            {
                REQUIRE_FALSE(decision.accepted);
                REQUIRE(decision.status == 403U);
                REQUIRE(calls <= merovingian::federation::max_signature_keys_per_server);
            }
        }

        WHEN("the key IDs listed ahead of the genuine one are of an algorithm this server does not understand")
        {
            auto junk = std::vector<std::string>{};
            for (auto i = std::size_t{0U}; i < merovingian::federation::max_signature_keys_per_server; ++i)
            {
                junk.push_back("curve25519:a" + std::to_string(i));
            }
            auto const pdu = pdu_of(with_junk_signatures_first(genuine, server, junk));
            auto const decision = merovingian::federation::authorize_federation_pdu_sender(pdu, std::nullopt, resolver);

            THEN("they are removed before the bound applies and the genuine key is the only lookup")
            {
                // Spec: identifiers with algorithms the server doesn't understand are removed.
                REQUIRE(decision.accepted);
                REQUIRE(calls == 1U);
            }
        }

        WHEN("the genuine key is already in hand, as a direct request's X-Matrix key")
        {
            auto const pdu = pdu_of(with_junk_signatures_first(genuine, server, {"ed25519:aa_unknown"}));
            auto const decision = merovingian::federation::authorize_federation_pdu_sender(pdu, genuine_key, resolver);

            THEN("it is tried first and nothing is looked up")
            {
                REQUIRE(decision.accepted);
                REQUIRE(calls == 0U);
            }
        }

        WHEN("the only key that could verify is refused by local admission")
        {
            denied_id = genuine_id;
            auto const pdu = pdu_of(with_junk_signatures_first(genuine, server, {"ed25519:aa_unknown"}));
            auto const decision = merovingian::federation::authorize_federation_pdu_sender(pdu, std::nullopt, resolver);

            THEN("the outcome is a retryable 503, not a verdict on the signature")
            {
                REQUIRE_FALSE(decision.accepted);
                REQUIRE(decision.status == 503U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Section: Validating hashes and signatures on received events; PUT /send/{txnId}; PUT /send_join
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#validating-hashes-and-signatures-on-received-events
//
// The same rule at the request boundary (audit R05): a relayed PDU whose
// sender's server lists an unknown key ID first, and a send_join signed with a
// key of its origin other than the one the request was signed with.
SCENARIO("Inbound federation finds a sender's signature under any listed key ID",
         "[federation][conformance][signatures][r05]")
{
    GIVEN("a relay forwarding a PDU whose author's server lists an unknown key ID before its genuine one")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const relay = std::string{"relay.example.org"};
        auto const relay_key_id = std::string{"ed25519:relay"};
        auto const relay_seed = std::string{"r05-relay"};
        merovingian::federation::upsert_remote(runtime, remote_for(relay, relay_key_id, relay_seed));
        auto const author = std::string{"alice.example.org"};
        auto const genuine_id = std::string{"ed25519:zz_genuine"};
        auto lookups = std::make_shared<std::vector<std::string>>();
        runtime.remote_key_resolver =
            [=](std::string_view server_name,
                std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            lookups->emplace_back(key_id);
            if (server_name == author && key_id == genuine_id)
            {
                return remote_for(author, genuine_id, "r05-author");
            }
            return std::nullopt;
        };
        auto accepted = std::make_shared<std::size_t>(0U);
        runtime.pdu_sink = [accepted](merovingian::federation::InboundPduEnvelope const&) {
            ++*accepted;
            return merovingian::federation::PduIngestionResult{merovingian::federation::PduIngestionStatus::accepted,
                                                               {}};
        };
        auto const pdu = with_junk_signatures_first(message_event_by(author, genuine_id, "r05-author"), author,
                                                    {"ed25519:aa_unknown"});
        auto request = signed_put_request(relay, relay_key_id, relay_seed, "/_matrix/federation/v1/send/r05txn",
                                          std::string{R"({"origin":")"} + relay +
                                              R"(","origin_server_ts":1000,"pdus":[)" + pdu + "]}");

        WHEN("the transaction is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the PDU is verified with the genuine key and accepted")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*accepted == 1U);
                REQUIRE(response.body.find("\"error\"") == std::string::npos);
                REQUIRE(std::ranges::find(*lookups, genuine_id) != lookups->end());
            }
        }
    }

    GIVEN("a send_join signed by its origin with a key other than the one the request is signed with")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"remote.example.org"};
        auto const request_key_id = std::string{"ed25519:auto"};
        auto const request_seed = std::string{"r05-request"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, request_key_id, request_seed));
        auto const event_key_id = std::string{"ed25519:rotated"};
        runtime.remote_key_resolver =
            [=](std::string_view server_name,
                std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            if (server_name == origin && key_id == event_key_id)
            {
                return remote_for(origin, event_key_id, "r05-rotated");
            }
            return std::nullopt;
        };
        auto calls = std::make_shared<std::size_t>(0U);
        runtime.membership_acceptor = [calls](merovingian::federation::FederationEndpoint, std::string_view,
                                              std::string_view, merovingian::federation::InboundPduEnvelope const&) {
            ++*calls;
            auto result = merovingian::federation::MembershipAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            result.room_version = "12";
            return result;
        };
        auto const unsigned_join =
            std::string{R"({"auth_events":[],"content":{"membership":"join"},"depth":2,"origin_server_ts":1000001,)"
                        R"("prev_events":[],"room_id":"!room:local.example.org","sender":"@alice:remote.example.org",)"
                        R"("state_key":"@alice:remote.example.org","type":"m.room.member"})"};
        auto const join =
            merovingian::federation::test::make_signed_event_json(unsigned_join, origin, event_key_id, "r05-rotated");
        REQUIRE_FALSE(join.empty());
        auto const event_id = merovingian::federation::test::reference_hash_event_id(join, "12");

        WHEN("the send_join is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime,
                signed_put_request(origin, request_key_id, request_seed,
                                   "/_matrix/federation/v2/send_join/!room:local.example.org/" + event_id, join));

            THEN("the signature is verified with the listed key and the join reaches the acceptor")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*calls == 1U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Section: PUT /v2/send_join (`join_authorised_via_users_server`); GET /make_join (400, 403)
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2send_joinroomideventid
//
// "The resident server which owns the provided user ID must have a valid signature on
// the event. If the resident server is receiving the /send_join request, the signature
// must be added before sending or persisting the event to other servers." So a join
// naming one of THIS server's users cannot already carry this server's signature: the
// request layer leaves that one check to the acceptor, which checks the allow conditions
// and adds the signature (audit R04, ADR-0181). Every other authorising server's
// signature is still required up front, and on every other endpoint.
SCENARIO("A restricted join naming this server's user is handed to the acceptor to co-sign",
         "[federation][conformance][membership][restricted_join][r04]")
{
    GIVEN("a runtime whose membership acceptor records what reaches it")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"remote.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"r04-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        auto calls = std::make_shared<std::size_t>(0U);
        runtime.membership_acceptor = [calls](merovingian::federation::FederationEndpoint, std::string_view,
                                              std::string_view, merovingian::federation::InboundPduEnvelope const&) {
            ++*calls;
            auto result = merovingian::federation::MembershipAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            result.room_version = "12";
            return result;
        };
        auto const membership_naming = [&](std::string const& membership, std::string const& authoriser) {
            auto const unsigned_json =
                std::string{R"({"auth_events":[],"content":{"join_authorised_via_users_server":")"} + authoriser +
                R"(","membership":")" + membership +
                R"("},"depth":2,"origin_server_ts":1000001,"prev_events":[],"room_id":"!room:local.example.org",)"
                R"("sender":"@alice:remote.example.org","state_key":"@alice:remote.example.org",)"
                R"("type":"m.room.member"})";
            auto json = merovingian::federation::test::make_signed_event_json(unsigned_json, origin, key_id, token);
            REQUIRE_FALSE(json.empty());
            return std::pair{json, merovingian::federation::test::reference_hash_event_id(json, "12")};
        };

        WHEN("a send_join names a user of this server and carries no signature from it")
        {
            auto const [json, event_id] = membership_naming("join", "@admin:local.example.org");
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime,
                signed_put_request(origin, key_id, token,
                                   "/_matrix/federation/v2/send_join/!room:local.example.org/" + event_id, json));

            THEN("it reaches the acceptor, which decides and signs")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*calls == 1U);
            }
        }

        WHEN("a send_join names a user of another server that has not signed it")
        {
            auto const [json, event_id] = membership_naming("join", "@admin:third.example.org");
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime,
                signed_put_request(origin, key_id, token,
                                   "/_matrix/federation/v2/send_join/!room:local.example.org/" + event_id, json));

            THEN("it is refused before the acceptor")
            {
                // rooms/v10.md 4.2.1: not validly signed by the authorising user's server.
                REQUIRE(response.status != 200U);
                REQUIRE(*calls == 0U);
            }
        }

        WHEN("a send_knock names a user of this server")
        {
            auto const [json, event_id] = membership_naming("knock", "@admin:local.example.org");
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime,
                signed_put_request(origin, key_id, token,
                                   "/_matrix/federation/v1/send_knock/!room:local.example.org/" + event_id, json));

            THEN("it is refused: this server co-signs only joins")
            {
                REQUIRE(response.status != 200U);
                REQUIRE(*calls == 0U);
            }
        }
    }

    GIVEN("a runtime whose template provider refuses a restricted join")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"remote.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"r04-make-join-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        runtime.membership_template_provider = [](merovingian::federation::FederationEndpoint, std::string_view,
                                                  std::string_view, std::vector<std::string> const&) {
            auto refused = merovingian::federation::MembershipEventTemplate{};
            refused.room_version = "10";
            refused.error_status = 403U;
            refused.reason = R"({"errcode":"M_FORBIDDEN","error":"the user meets none of the room's conditions"})";
            return std::optional<merovingian::federation::MembershipEventTemplate>{refused};
        };

        WHEN("make_join is requested")
        {
            auto request = signed_put_request(origin, key_id, token,
                                              "/_matrix/federation/v1/make_join/!room:local.example.org/"
                                              "@alice:remote.example.org",
                                              "");
            request.method = "GET";
            request.signature = merovingian::federation::make_federation_signature(
                request.origin, request.destination, request.method, request.target, request.body,
                merovingian::federation::test::keypair_from_seed(token).secret_key);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the refusal keeps its status and errcode")
            {
                // Spec: "If the joining server fails all conditions then a 403 M_FORBIDDEN error is used".
                REQUIRE(response.status == 403U);
                REQUIRE(response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }
    }
}
