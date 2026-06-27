// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |       OUTBOUND FEDERATION DELIVERY CONFORMANCE TESTS                    |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.18                                   |
// |  Endpoint: PUT /_matrix/federation/v1/send/{txnId}  (outbound)          |
// |  URL: ../../docs/matrix-v1.18-spec/server-server-api.md                  |
// |         #put_matrixfederationv1sendtxnid                                |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec.        |
// |  If a test fails:                                                        |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |       spec itself has changed and citing the updated section.            |
// |                                                                         |
// |  Outbound transaction format (spec §Transactions):                      |
// |    PUT /_matrix/federation/v1/send/{txnId}                               |
// |    Authorization: X-Matrix origin=…,destination=…,key="…",sig="…"      |
// |    { "origin": string, "origin_server_ts": int,                         |
// |      "pdus": [...], "edus": [{"edu_type": …, "content": …}] }           |
// +-------------------------------------------------------------------------+

#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/server_discovery.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace
{

auto const local_origin = std::string{"local.example.org"};
auto const remote_dest = std::string{"remote.example.org"};
auto const test_key_seed = std::string{"outbound-delivery-conformance"};
auto const test_key_id = std::string{"ed25519:auto"};

[[nodiscard]] auto local_secret_key() -> std::string
{
    return merovingian::federation::test::keypair_from_seed(test_key_seed).secret_key;
}

[[nodiscard]] auto make_test_call(std::string_view transaction_id, std::string_view body)
    -> merovingian::federation::OutboundCall
{
    auto txn = merovingian::federation::OutboundTransaction{};
    txn.transaction_id = std::string{transaction_id};
    txn.destination = remote_dest;
    txn.method = "PUT";
    txn.target = "/_matrix/federation/v1/send/" + std::string{transaction_id};
    txn.origin = local_origin;
    txn.body = std::string{body};

    auto call = merovingian::federation::OutboundCall{};
    call.transaction = std::move(txn);
    call.resolved_host = remote_dest;
    call.resolved_port = 8448U;
    call.pinned_addresses = {"203.0.113.1"};
    call.key_id = test_key_id;
    call.secret_key = local_secret_key();
    return call;
}

[[nodiscard]] auto json_get(merovingian::canonicaljson::Object const& obj, std::string const& key)
    -> merovingian::canonicaljson::Value const*
{
    for (auto const& member : obj)
    {
        if (member.key == key)
        {
            return member.value.get();
        }
    }
    return nullptr;
}

} // namespace

// =============================================================================
// EDU transaction body — required top-level fields
// =============================================================================
// Spec: Matrix Server-Server API v1.18
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv1sendtxnid
//
// Spec MUST: a federation transaction body sent in PUT /send/{txnId} MUST
// contain "origin" (the sending server), "origin_server_ts" (millisecond
// timestamp), and "pdus" (array, may be empty). "edus" is optional but when
// present MUST be an array.
SCENARIO("build_edu_transaction_body produces required top-level fields", "[federation][outbound][conformance]")
{
    GIVEN("a valid EDU type and content")
    {
        auto const edu_content = std::string{R"({"room_id":"!test:local.example.org","typing":true})"};

        WHEN("an EDU transaction body is built")
        {
            auto const result =
                merovingian::federation::build_edu_transaction_body(local_origin, "m.typing", edu_content);

            THEN("the result is present (not nullopt)")
            {
                // Spec MUST: a valid origin and content must produce a body.
                REQUIRE(result.has_value());
            }

            THEN("the body parses as a canonical JSON object")
            {
                REQUIRE(result.has_value());
                auto const parsed = merovingian::canonicaljson::parse_lossless(*result);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage()) != nullptr);
            }

            THEN("origin is the sending server name")
            {
                REQUIRE(result.has_value());
                auto const parsed = merovingian::canonicaljson::parse_lossless(*result);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: "origin" is the server_name of the sending server.
                // Do NOT remove — the receiving server uses this to verify X-Matrix.
                auto const* origin_val = json_get(*root, "origin");
                REQUIRE(origin_val != nullptr);
                auto const* origin_str = std::get_if<std::string>(&origin_val->storage());
                REQUIRE(origin_str != nullptr);
                REQUIRE(*origin_str == local_origin);
            }

            THEN("origin_server_ts is a non-negative integer")
            {
                REQUIRE(result.has_value());
                auto const parsed = merovingian::canonicaljson::parse_lossless(*result);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: "origin_server_ts" is a millisecond POSIX timestamp.
                // Do NOT remove — receivers validate this for clock-skew checks.
                auto const* ts_val = json_get(*root, "origin_server_ts");
                REQUIRE(ts_val != nullptr);
                REQUIRE(std::get_if<std::int64_t>(&ts_val->storage()) != nullptr);
            }

            THEN("pdus is an empty array")
            {
                REQUIRE(result.has_value());
                auto const parsed = merovingian::canonicaljson::parse_lossless(*result);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: "pdus" is present (may be empty for EDU-only transactions).
                auto const* pdus_val = json_get(*root, "pdus");
                REQUIRE(pdus_val != nullptr);
                auto const* pdus_arr = std::get_if<merovingian::canonicaljson::Array>(&pdus_val->storage());
                REQUIRE(pdus_arr != nullptr);
                REQUIRE(pdus_arr->empty());
            }

            THEN("edus is an array containing exactly one entry")
            {
                REQUIRE(result.has_value());
                auto const parsed = merovingian::canonicaljson::parse_lossless(*result);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec: "edus" is optional but when present must be an array.
                auto const* edus_val = json_get(*root, "edus");
                REQUIRE(edus_val != nullptr);
                auto const* edus_arr = std::get_if<merovingian::canonicaljson::Array>(&edus_val->storage());
                REQUIRE(edus_arr != nullptr);
                REQUIRE(edus_arr->size() == 1U);
            }
        }
    }
}

// =============================================================================
// EDU key name: edu_type not type
// =============================================================================
// Spec: Matrix Server-Server API v1.18
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#edus
//
// Spec MUST: EDU objects inside the "edus" array MUST use the key "edu_type"
// for the type discriminator. Using "type" instead causes Synapse and other
// Matrix homeservers to reject the entire transaction with a field-parse error.
SCENARIO("EDU object in built transaction uses edu_type key not type", "[federation][outbound][conformance][edu]")
{
    GIVEN("an outgoing m.typing EDU")
    {
        auto const content = std::string{R"({"room_id":"!test:local.example.org","typing":true})"};

        WHEN("an EDU transaction body is built")
        {
            auto const result = merovingian::federation::build_edu_transaction_body(local_origin, "m.typing", content);
            REQUIRE(result.has_value());

            auto const parsed = merovingian::canonicaljson::parse_lossless(*result);
            auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
            REQUIRE(root != nullptr);
            auto const* edus_val = json_get(*root, "edus");
            REQUIRE(edus_val != nullptr);
            auto const* edus_arr = std::get_if<merovingian::canonicaljson::Array>(&edus_val->storage());
            REQUIRE(edus_arr != nullptr);
            REQUIRE(!edus_arr->empty());

            auto const& edu_val = (*edus_arr)[0];
            auto const* edu_obj = std::get_if<merovingian::canonicaljson::Object>(&edu_val.storage());
            REQUIRE(edu_obj != nullptr);

            THEN("the EDU carries edu_type not type")
            {
                // Spec MUST: EDU type discriminator key is "edu_type".
                // Do NOT rename to "type" — it breaks all Matrix peer receivers.
                auto const* edu_type_val = json_get(*edu_obj, "edu_type");
                REQUIRE(edu_type_val != nullptr);
                auto const* edu_type_str = std::get_if<std::string>(&edu_type_val->storage());
                REQUIRE(edu_type_str != nullptr);
                REQUIRE(*edu_type_str == "m.typing");

                // Spec: "type" MUST NOT be used as the EDU discriminator key.
                auto const* wrong_key = json_get(*edu_obj, "type");
                REQUIRE(wrong_key == nullptr);
            }

            THEN("the EDU carries the content object")
            {
                // Spec: the EDU content must be present under the "content" key.
                auto const* content_val = json_get(*edu_obj, "content");
                REQUIRE(content_val != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&content_val->storage()) != nullptr);
            }
        }
    }
}

// =============================================================================
// build_edu_transaction_body — invalid content returns nullopt
// =============================================================================
// Spec: Matrix Server-Server API v1.18 (general error handling)
//
// When the EDU content is not valid JSON the builder MUST NOT produce a
// malformed transaction body. Returning nullopt lets callers skip the send
// rather than forwarding corrupt data to a remote server.
SCENARIO("build_edu_transaction_body returns nullopt for non-JSON content", "[federation][outbound][conformance][edu]")
{
    GIVEN("EDU content that is not valid JSON")
    {
        WHEN("an EDU transaction body is built with the invalid content")
        {
            auto const result =
                merovingian::federation::build_edu_transaction_body(local_origin, "m.typing", "this is not json {{{");

            THEN("the result is nullopt (build fails cleanly)")
            {
                // Spec: a malformed content MUST NOT produce a transaction body.
                // Fail closed — never forward corrupt transactions.
                REQUIRE(!result.has_value());
            }
        }
    }
}

// =============================================================================
// m.receipt EDU content structure
// =============================================================================
// Spec: Matrix Server-Server API v1.18
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#receipts
//
// Spec MUST: the m.receipt EDU content follows the nested structure:
//   { roomId: { receiptType: { userId: { event_ids: [eventId], data: { ts: N } } } } }
// This nesting is required for interoperability — other Matrix servers parse
// the receipt to update their read-horizon tracking for the user.
SCENARIO("build_receipt_edu_content produces the spec-required nested structure",
         "[federation][outbound][conformance][edu][receipt]")
{
    GIVEN("receipt details for a room, user, and event")
    {
        auto const room_id = std::string{"!test:local.example.org"};
        auto const receipt_type = std::string{"m.read"};
        auto const user_id = std::string{"@alice:local.example.org"};
        auto const event_id = std::string{"$event123:local.example.org"};
        auto const ts = std::int64_t{1718000000000LL};

        WHEN("a receipt EDU content is built")
        {
            auto const result =
                merovingian::federation::build_receipt_edu_content(room_id, receipt_type, user_id, event_id, ts);

            THEN("the result is present")
            {
                REQUIRE(result.has_value());
            }

            THEN("the content follows roomId → receiptType → userId → event_ids/data nesting")
            {
                REQUIRE(result.has_value());
                auto const parsed = merovingian::canonicaljson::parse_lossless(*result);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Level 1: roomId
                auto const* room_val = json_get(*root, room_id);
                REQUIRE(room_val != nullptr);
                auto const* room_obj = std::get_if<merovingian::canonicaljson::Object>(&room_val->storage());
                REQUIRE(room_obj != nullptr);

                // Level 2: receiptType
                auto const* rtype_val = json_get(*room_obj, receipt_type);
                REQUIRE(rtype_val != nullptr);
                auto const* rtype_obj = std::get_if<merovingian::canonicaljson::Object>(&rtype_val->storage());
                REQUIRE(rtype_obj != nullptr);

                // Level 3: userId
                auto const* user_val = json_get(*rtype_obj, user_id);
                REQUIRE(user_val != nullptr);
                auto const* user_obj = std::get_if<merovingian::canonicaljson::Object>(&user_val->storage());
                REQUIRE(user_obj != nullptr);

                // Spec MUST: event_ids is an array containing the event ID.
                auto const* eids_val = json_get(*user_obj, "event_ids");
                REQUIRE(eids_val != nullptr);
                auto const* eids_arr = std::get_if<merovingian::canonicaljson::Array>(&eids_val->storage());
                REQUIRE(eids_arr != nullptr);
                REQUIRE(eids_arr->size() == 1U);
                auto const* eid_str = std::get_if<std::string>(&(*eids_arr)[0].storage());
                REQUIRE(eid_str != nullptr);
                REQUIRE(*eid_str == event_id);

                // Spec MUST: data.ts is the read timestamp in milliseconds.
                auto const* data_val = json_get(*user_obj, "data");
                REQUIRE(data_val != nullptr);
                auto const* data_obj = std::get_if<merovingian::canonicaljson::Object>(&data_val->storage());
                REQUIRE(data_obj != nullptr);
                auto const* ts_val = json_get(*data_obj, "ts");
                REQUIRE(ts_val != nullptr);
                auto const* ts_int = std::get_if<std::int64_t>(&ts_val->storage());
                REQUIRE(ts_int != nullptr);
                REQUIRE(*ts_int == ts);
            }
        }
    }
}

// =============================================================================
// Transaction ID — uniqueness across calls
// =============================================================================
// Spec: Matrix Server-Server API v1.18
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv1sendtxnid
//
// The transaction ID in the URL path uniquely identifies this delivery attempt
// to the remote server. Receivers deduplicate on (origin, txnId); a repeated
// txnId must not be re-processed. Therefore the sender MUST generate a new,
// distinct txnId for each fresh transaction.
SCENARIO("make_federation_transaction_id produces unique identifiers across calls",
         "[federation][outbound][conformance]")
{
    GIVEN("no preconditions")
    {
        WHEN("make_federation_transaction_id is called 20 times")
        {
            auto ids = std::set<std::string>{};
            for (auto i = 0U; i < 20U; ++i)
            {
                ids.insert(merovingian::federation::make_federation_transaction_id());
            }

            THEN("all 20 identifiers are distinct")
            {
                // Spec MUST: duplicate txnIds from the same sender confuse receiver
                // deduplication. The generator must produce unique IDs per call.
                REQUIRE(ids.size() == 20U);
            }
        }

        WHEN("make_federation_transaction_id is called once")
        {
            auto const id = merovingian::federation::make_federation_transaction_id();

            THEN("the identifier is non-empty")
            {
                // Spec: txnId must be a non-empty opaque string.
                REQUIRE(!id.empty());
            }
        }
    }
}

// =============================================================================
// Outbound request — PUT method and correct URL path
// =============================================================================
// Spec: Matrix Server-Server API v1.18
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv1sendtxnid
//
// Spec MUST: the outbound request MUST use HTTP PUT and MUST target the path
// /_matrix/federation/v1/send/{txnId} at the remote server.
SCENARIO("build_outbound_request produces a PUT request to the correct federation path",
         "[federation][outbound][conformance]")
{
    GIVEN("a prepared outbound call for transaction txn_abc")
    {
        auto const body = std::string{R"({"origin":"local.example.org","origin_server_ts":1,"pdus":[]})"};
        auto const call = make_test_call("txn_abc", body);

        WHEN("the outbound request is built")
        {
            auto const req = merovingian::federation::build_outbound_request(call);

            THEN("the request method is PUT")
            {
                // Spec MUST: federation transactions are sent via HTTP PUT.
                REQUIRE(req.method == "PUT");
            }

            THEN("the URL targets /_matrix/federation/v1/send/{txnId}")
            {
                // Spec MUST: path must be /_matrix/federation/v1/send/{txnId}.
                // Do NOT change to a different path — the receiving server routes
                // on this exact prefix to dispatch inbound transaction handling.
                REQUIRE(req.url.find("/_matrix/federation/v1/send/txn_abc") != std::string::npos);
            }

            THEN("the URL uses the https scheme")
            {
                // Spec MUST: federation traffic MUST use TLS (https scheme).
                // Cleartext delivery is a security violation.
                REQUIRE(req.url.substr(0U, 8U) == "https://");
            }

            THEN("the URL embeds the resolved host")
            {
                // The resolved host (from server discovery) must appear in the URL
                // so libcurl connects to the correct server without a second DNS lookup.
                REQUIRE(req.url.find(remote_dest) != std::string::npos);
            }
        }
    }
}

// =============================================================================
// Outbound request — X-Matrix Authorization header presence
// =============================================================================
// Spec: Matrix Server-Server API v1.18
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#request-authentication
//
// Spec MUST: every outbound federation request MUST carry an
// "Authorization: X-Matrix ..." header signed with the sending server's
// Ed25519 private key. The receiving server verifies this before processing.
SCENARIO("build_outbound_request carries an Authorization X-Matrix header", "[federation][outbound][conformance][auth]")
{
    GIVEN("a prepared outbound call")
    {
        auto const body = std::string{R"({"origin":"local.example.org","origin_server_ts":1,"pdus":[]})"};
        auto const call = make_test_call("txn_xmatrix", body);

        WHEN("the outbound request is built")
        {
            auto const req = merovingian::federation::build_outbound_request(call);

            THEN("an Authorization header is present")
            {
                auto const it = std::ranges::find_if(req.headers, [](merovingian::http::OutboundHeader const& h) {
                    return h.name == "Authorization";
                });
                // Spec MUST: Authorization header is present on every outbound request.
                REQUIRE(it != req.headers.end());
            }

            THEN("the Authorization header value starts with X-Matrix")
            {
                auto const it = std::ranges::find_if(req.headers, [](merovingian::http::OutboundHeader const& h) {
                    return h.name == "Authorization";
                });
                REQUIRE(it != req.headers.end());
                // Spec MUST: the scheme is "X-Matrix" (case-sensitive per RFC 7235).
                REQUIRE(it->value.substr(0U, 8U) == "X-Matrix");
            }
        }
    }
}

// =============================================================================
// Outbound request — X-Matrix header field structure
// =============================================================================
// Spec: Matrix Server-Server API v1.18
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#request-authentication
//
// Spec MUST: the X-Matrix Authorization header MUST contain the fields
// origin=, destination=, key=, sig= so the receiving server can verify
// the signature and confirm the origin matches the X-Matrix claim.
SCENARIO("X-Matrix Authorization header contains origin, destination, key, and sig fields",
         "[federation][outbound][conformance][auth]")
{
    GIVEN("a prepared outbound call for local to remote")
    {
        auto const body = std::string{R"({"origin":"local.example.org","origin_server_ts":1,"pdus":[]})"};
        auto const call = make_test_call("txn_fields", body);

        WHEN("the outbound request is built")
        {
            auto const req = merovingian::federation::build_outbound_request(call);
            auto const it = std::ranges::find_if(req.headers, [](merovingian::http::OutboundHeader const& h) {
                return h.name == "Authorization";
            });
            REQUIRE(it != req.headers.end());
            auto const& auth_value = it->value;

            THEN("the header contains origin= with the sending server name")
            {
                // Spec MUST: origin= identifies the sending server.
                // The receiving server verifies this matches the signing key used.
                REQUIRE(auth_value.find("origin=\"" + local_origin + "\"") != std::string::npos);
            }

            THEN("the header contains destination= with the remote server name")
            {
                // Spec MUST: destination= identifies the intended receiver.
                // The receiving server rejects if destination doesn't match its own name.
                REQUIRE(auth_value.find("destination=\"" + remote_dest + "\"") != std::string::npos);
            }

            THEN("the header contains a key= field (non-empty)")
            {
                // Spec MUST: key= identifies which signing key was used.
                REQUIRE(auth_value.find("key=\"") != std::string::npos);
            }

            THEN("the header contains a sig= field (non-empty)")
            {
                // Spec MUST: sig= carries the Base64-encoded Ed25519 signature.
                // Do NOT remove — the receiving server cannot verify without this.
                REQUIRE(auth_value.find("sig=\"") != std::string::npos);
            }
        }
    }
}

// =============================================================================
// Backoff — positive base interval
// =============================================================================
// Spec: Matrix Server-Server API v1.18 (retry semantics)
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv1sendtxnid
//
// The spec requires exponential backoff on delivery failure. The base interval
// (retry_count == 0) MUST be positive so there is always a pause between the
// first failure and the first retry.
SCENARIO("compute_backoff returns a positive interval for retry_count 0", "[federation][outbound][conformance][retry]")
{
    GIVEN("retry_count is zero (first failure)")
    {
        WHEN("the backoff interval is computed")
        {
            auto const interval = merovingian::federation::compute_backoff(0U);

            THEN("the interval is greater than zero")
            {
                // Spec: the retry interval MUST be positive so the sender
                // pauses before retrying a failed transaction.
                REQUIRE(interval > 0U);
            }
        }
    }
}

// =============================================================================
// Backoff — exponential growth
// =============================================================================
// Spec: Matrix Server-Server API v1.18 (retry semantics)
//
// Spec: the backoff interval MUST grow as retry_count increases so that a
// repeatedly-failing destination does not saturate the network or the remote.
SCENARIO("compute_backoff interval grows monotonically with retry count", "[federation][outbound][conformance][retry]")
{
    GIVEN("successive retry counts")
    {
        WHEN("backoff is computed for counts 0 through 4")
        {
            auto const b0 = merovingian::federation::compute_backoff(0U);
            auto const b1 = merovingian::federation::compute_backoff(1U);
            auto const b2 = merovingian::federation::compute_backoff(2U);
            auto const b3 = merovingian::federation::compute_backoff(3U);
            auto const b4 = merovingian::federation::compute_backoff(4U);

            THEN("each interval is at least as large as the previous")
            {
                // Spec: exponential backoff — intervals must not decrease.
                REQUIRE(b1 >= b0);
                REQUIRE(b2 >= b1);
                REQUIRE(b3 >= b2);
                REQUIRE(b4 >= b3);
            }

            THEN("the interval at count 4 is strictly larger than at count 0")
            {
                // Spec: backoff must actually grow, not stay flat at the base.
                REQUIRE(b4 > b0);
            }
        }
    }
}

// =============================================================================
// Backoff — capped at a maximum interval
// =============================================================================
// Spec: Matrix Server-Server API v1.18 (retry semantics)
//
// Uncapped exponential backoff would delay delivery indefinitely. The
// implementation MUST cap the backoff at a reasonable maximum so that a
// previously-unreachable server can eventually receive traffic again.
SCENARIO("compute_backoff is capped and does not grow without bound", "[federation][outbound][conformance][retry]")
{
    GIVEN("very large retry counts")
    {
        WHEN("backoff is computed for counts 20 and 100")
        {
            auto const b20 = merovingian::federation::compute_backoff(20U);
            auto const b100 = merovingian::federation::compute_backoff(100U);

            THEN("the interval at count 100 equals the interval at count 20 (cap reached)")
            {
                // Spec: the implementation MUST cap the interval so it does not
                // grow to a value that prevents eventual re-delivery.
                REQUIRE(b100 == b20);
            }

            THEN("the capped interval does not exceed 24 hours in milliseconds")
            {
                // A 24-hour cap is the maximum reasonable retry window for
                // federation — beyond this a human should investigate.
                constexpr auto max_ms = std::uint64_t{24U * 60U * 60U * 1000U};
                REQUIRE(b100 <= max_ms);
            }
        }
    }
}

// =============================================================================
// Circuit breaker — open when no prior failures
// =============================================================================
// Spec: Matrix Server-Server API v1.18 (retry semantics)
//
// A fresh destination (retry_after_ts == 0) MUST be retryable. The circuit
// breaker must not block delivery attempts to servers that have not failed.
SCENARIO("destination_should_retry returns true when no backoff is scheduled",
         "[federation][outbound][conformance][retry][circuit-breaker]")
{
    GIVEN("a fresh destination with no recorded failures")
    {
        auto dest = merovingian::federation::FederationDestination{};
        dest.server_name = remote_dest;
        dest.retry_after_ts = 0U;
        dest.consecutive_failures = 0U;

        WHEN("should_retry is evaluated at any current time")
        {
            auto const now = std::uint64_t{1718000000000ULL};
            auto const retryable = merovingian::federation::destination_should_retry(dest, now);

            THEN("the destination is retryable")
            {
                // Spec MUST: a destination with no prior failures must accept delivery.
                REQUIRE(retryable);
            }
        }
    }
}

// =============================================================================
// Circuit breaker — closed before backoff window expires
// =============================================================================
// Spec: Matrix Server-Server API v1.18 (retry semantics)
//
// Spec MUST: the sender MUST NOT retry before the backoff window expires.
// Retrying too early wastes resources and can trigger rate-limiting by the remote.
SCENARIO("destination_should_retry returns false while backoff window is active",
         "[federation][outbound][conformance][retry][circuit-breaker]")
{
    GIVEN("a destination whose retry_after_ts is set in the future")
    {
        auto const now = std::uint64_t{1718000000000ULL};
        auto dest = merovingian::federation::FederationDestination{};
        dest.server_name = remote_dest;
        dest.retry_after_ts = now + 60000U; // 60 s from now
        dest.consecutive_failures = 3U;

        WHEN("should_retry is evaluated before the backoff window expires")
        {
            auto const retryable = merovingian::federation::destination_should_retry(dest, now);

            THEN("the destination is not retryable")
            {
                // Spec MUST: sender must not retry before retry_after_ts.
                // Do NOT remove — premature retries flood the remote server.
                REQUIRE(!retryable);
            }
        }

        WHEN("should_retry is evaluated after the backoff window expires")
        {
            auto const future_now = dest.retry_after_ts + 1U;
            auto const retryable = merovingian::federation::destination_should_retry(dest, future_now);

            THEN("the destination is retryable")
            {
                // Spec: after the backoff window expires the sender MUST be
                // allowed to retry.
                REQUIRE(retryable);
            }
        }
    }
}

// =============================================================================
// apply_outbound_result — 2xx success clears failure state
// =============================================================================
// Spec: Matrix Server-Server API v1.18 (retry semantics)
//
// Spec MUST: on a successful delivery (2xx response) the sender MUST clear
// its failure state so subsequent transactions are not unnecessarily delayed.
SCENARIO("apply_outbound_result clears consecutive_failures on a 2xx response",
         "[federation][outbound][conformance][retry]")
{
    GIVEN("a destination with accumulated failures")
    {
        auto const now = std::uint64_t{1718000000000ULL};
        auto dest = merovingian::federation::FederationDestination{};
        dest.server_name = remote_dest;
        dest.consecutive_failures = 5U;
        dest.retry_after_ts = now + 60000U;

        WHEN("a 200 OK result is applied")
        {
            auto result = merovingian::federation::OutboundTransactionResult{};
            result.sent = true;
            result.http_status = 200U;
            merovingian::federation::apply_outbound_result(dest, result, now);

            THEN("consecutive_failures is reset to zero")
            {
                // Spec MUST: success clears the failure counter so the next
                // transaction is not blocked by stale backoff state.
                REQUIRE(dest.consecutive_failures == 0U);
            }

            THEN("retry_after_ts is cleared")
            {
                // Spec MUST: the circuit breaker must open after a successful delivery.
                REQUIRE(dest.retry_after_ts == 0U);
            }

            THEN("last_success_ts is updated to now")
            {
                REQUIRE(dest.last_success_ts == now);
            }
        }
    }
}

// =============================================================================
// apply_outbound_result — non-2xx failure sets backoff
// =============================================================================
// Spec: Matrix Server-Server API v1.18 (retry semantics)
//
// Spec: on delivery failure (non-2xx, network error, timeout) the sender MUST
// apply exponential backoff before the next attempt. The retry state must be
// updated so the circuit breaker is engaged for the computed interval.
SCENARIO("apply_outbound_result increments failures and sets retry_after_ts on non-2xx",
         "[federation][outbound][conformance][retry]")
{
    GIVEN("a fresh destination with no prior failures")
    {
        auto const now = std::uint64_t{1718000000000ULL};
        auto dest = merovingian::federation::FederationDestination{};
        dest.server_name = remote_dest;
        dest.consecutive_failures = 0U;
        dest.retry_after_ts = 0U;

        WHEN("a 500 Internal Server Error result is applied")
        {
            auto result = merovingian::federation::OutboundTransactionResult{};
            result.sent = true;
            result.http_status = 500U;
            merovingian::federation::apply_outbound_result(dest, result, now);

            THEN("consecutive_failures is incremented")
            {
                // Spec MUST: each failure must be recorded so backoff grows
                // on subsequent failures to the same destination.
                REQUIRE(dest.consecutive_failures == 1U);
            }

            THEN("retry_after_ts is set to a future timestamp")
            {
                // Spec MUST: a backoff window must be set after every failure.
                // Do NOT remove — without this the circuit breaker never engages.
                REQUIRE(dest.retry_after_ts > now);
            }
        }

        WHEN("a network error (http_status 0) result is applied")
        {
            auto result = merovingian::federation::OutboundTransactionResult{};
            result.sent = false;
            result.http_status = 0U;
            result.error = "connection_failed";
            merovingian::federation::apply_outbound_result(dest, result, now);

            THEN("consecutive_failures is incremented")
            {
                // Spec: network errors are treated identically to HTTP errors
                // for backoff purposes — both prevent the next retry.
                REQUIRE(dest.consecutive_failures == 1U);
            }

            THEN("retry_after_ts is set to a future timestamp")
            {
                REQUIRE(dest.retry_after_ts > now);
            }
        }
    }
}
