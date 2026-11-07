// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/crypto/Ed25519Provider.hpp"
#include "merovingian/database/EventTable.hpp"
#include "merovingian/events/EventSignature.hpp"
#include "merovingian/federation/AuthorisingSignatureKey.hpp"
#include "merovingian/federation/FederationAcceptedTransaction.hpp"
#include "merovingian/federation/FederationDecision.hpp"
#include "merovingian/federation/FederationKeyRecord.hpp"
#include "merovingian/federation/FederationPdu.hpp"
#include "merovingian/federation/FederationRemoteRuntime.hpp"
#include "merovingian/federation/FederationResponse.hpp"
#include "merovingian/federation/FederationRuntimeState.hpp"
#include "merovingian/federation/FederationSigningKey.hpp"
#include "merovingian/federation/InboundSignatureVerification.hpp"
#include "merovingian/federation/RoomReadResult.hpp"
#include "merovingian/federation/RuntimeFederationConfig.hpp"
#include "merovingian/federation/SignedFederationRequest.hpp"
#include "merovingian/federation/VerificationKeyResolution.hpp"
#include "merovingian/federation/XMatrixCredentials.hpp"
#include "merovingian/federation/inbound_request_providers.hpp"
#include "merovingian/media/LocalMediaDownloadResult.hpp"
#include "merovingian/observability/AuditLogEvent.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::federation
{

// True when `header_value` starts with the `X-Matrix` auth-scheme and a space. The scheme is compared
// ASCII-case-insensitively (RFC 9110 section 11.1: auth-schemes are case-insensitive); the credentials after it keep
// their case. One definition for every place that reads the scheme.
[[nodiscard]] auto has_x_matrix_scheme(std::string_view header_value) noexcept -> bool;

// Parses an Authorization header value that begins with "X-Matrix ". Returns
// std::nullopt for any malformed input or if the required fields (origin, key,
// sig) are absent.
[[nodiscard]] auto parse_x_matrix_authorization_header(std::string_view header_value)
    -> std::optional<XMatrixCredentials>;

[[nodiscard]] auto load_server_signing_key(std::string_view server_name, std::string_view key_id,
                                           std::string_view key_material) -> FederationSigningKey;
[[nodiscard]] auto signing_key_summary(FederationSigningKey const& key) -> std::string;
// Signs a federation request with this server's real Ed25519 secret key.
// The signed payload is the Matrix canonical JSON object
// {content?, destination, method, origin, uri} — content is omitted for a
// body-less request. `secret_key` is the raw 64-byte libsodium secret key,
// passed as a span so the caller never has to materialise an unpinned
// std::string copy of the key (the runtime keeps it in a SecretBuffer).
// Returns the Base64-encoded signature, or an empty string on any failure.
[[nodiscard]] auto make_federation_signature(std::string_view origin, std::string_view destination,
                                             std::string_view method, std::string_view target, std::string_view body,
                                             std::span<std::uint8_t const> secret_key) -> std::string;

// Inline adapter so legacy callers that still hold the raw secret as a
// std::string (notably the test keypair helpers) keep compiling without a
// span materialisation at every call site. The std::string_view argument
// lifetime covers this full expression, so the borrowed span is valid for
// the duration of the signing call only — callers must not retain it.
[[nodiscard]] inline auto make_federation_signature(std::string_view origin, std::string_view destination,
                                                    std::string_view method, std::string_view target,
                                                    std::string_view body, std::string_view secret_key) -> std::string
{
    return make_federation_signature(
        origin, destination, method, target, body,
        std::span<std::uint8_t const>{reinterpret_cast<std::uint8_t const*>(secret_key.data()), secret_key.size()});
}
// Verifies a federation request against the remote's published Ed25519 public
// key. Rebuilds the Matrix signed-request object and checks the detached
// signature; also rejects a request signed with a key past its validity.
[[nodiscard]] auto verify_signed_federation_request(SignedFederationRequest const& request,
                                                    FederationKeyRecord const& key) -> FederationDecision;
[[nodiscard]] auto make_federation_runtime_state(RuntimeFederationConfig config) -> FederationRuntimeState;
auto upsert_remote(FederationRuntimeState& runtime, FederationRemoteRuntime remote) -> void;
// Why the operator's policy refuses what `server_name` wrote, empty when it does not (ADR-0390): denied_servers,
// the default_policy=deny allow list and the admin's rules, whichever server carried the event here. This server
// is never refused its own events, and an empty name is left to the check that rejects a malformed sender. May take
// runtime.mutex through the provider, so never call it from a task whose parent holds that mutex and waits.
[[nodiscard]] auto operator_policy_refusal(FederationRuntimeState const& runtime, std::string_view server_name)
    -> std::string;
[[nodiscard]] auto authorize_federation_pdu(FederationPdu const& pdu, std::string_view expected_origin)
    -> FederationDecision;
[[nodiscard]] auto authorize_federation_pdu(FederationPdu const& pdu, std::string_view expected_origin,
                                            std::optional<FederationKeyRecord> const& key,
                                            RemoteKeyResolver const& remote_key_resolver,
                                            crypto::Ed25519Provider& provider) -> FederationDecision;

// Verifies the sender server's signature on `pdu` with `key`. From room
// version 5 the key must also be valid at the event's own origin_server_ts
// (`key.valid_until_ts >= origin_server_ts`, rooms/v5.md "Signing key validity
// period"); versions 1-4 ignore valid_until_ts. The current time plays no
// part: a key that has expired since the event was sent still verifies it
// (ADR-0075). How long a cached key is trusted is bounded where it is cached
// (cache_remote_server_keys, 7 days after the fetch).
[[nodiscard]] auto authorize_federation_pdu(FederationPdu const& pdu, std::string_view expected_origin,
                                            std::optional<FederationKeyRecord> const& key) -> FederationDecision;

// The signing-key validity rule on its own, for every path that verifies an
// event's signature: from room v5 `key.valid_until_ts` MUST be at least the
// event's origin_server_ts (rooms/v5.md, "Signing key validity period");
// versions 1-4 ignore valid_until_ts. Accepted, or a 400 (no integer
// origin_server_ts) or 403 (key expired before the event was sent). ADR-0075.
[[nodiscard]] auto check_signing_key_valid_for_event(FederationKeyRecord const& key, canonicaljson::Value const& event,
                                                     rooms::RoomVersionPolicy const& room_version)
    -> FederationDecision;
// Parses a raw PDU string (JSON or comma-delimited) into a FederationPdu.
// When version_resolver is provided it is called with the parsed room_id to
// determine the room version for event-ID computation; pdu.room_version is
// set to the resolved version. When the resolver is empty, falls back to "12".
[[nodiscard]] auto parse_federation_pdu(std::string_view encoded) -> FederationPdu;
[[nodiscard]] auto parse_federation_pdu(std::string_view encoded, RoomVersionResolver const& version_resolver)
    -> FederationPdu;
// Key-only verification at another trust boundary, including main's worker
// relay re-verification. Matching cached material needs no discovery or slot;
// misses share this runtime's source quota, slots and pair negative cache.
// Callers must still verify the signature and event-time key validity. A local
// denial is retryable overload, not evidence of a bad remote signature.

[[nodiscard]] auto resolve_verification_key(FederationRuntimeState& runtime, std::string_view source,
                                            std::string_view server_name, std::string_view key_id)
    -> VerificationKeyResolution;

// How many of the key IDs an event lists under one server's signatures are
// checked, for the sender's server (audit R05, ADR-0183) and a restricted
// join's authorising server (ADR-0171) alike. The signatures object is not
// itself signed, so a relaying server can add key IDs, and each candidate may
// cost a key fetch. A rotating server signs with one or two keys. An event
// listing more than this for its sender's server is refused, fail-closed.
inline constexpr std::size_t max_signature_keys_per_server{4U};
inline constexpr std::size_t max_authorising_signature_keys{max_signature_keys_per_server};

// The signing key identifiers `signatures` lists for `server_name`, in the
// event's own order, without repeats, keeping only the ed25519 algorithm this
// server understands and at most max_signature_keys_per_server of them.
// appendices.md "Checking for a Signature", step 2: "Removes any signing key
// identifiers from the entry with algorithms it doesn't understand."
[[nodiscard]] auto signature_key_ids_for_server(std::vector<events::EventSignature> const& signatures,
                                                std::string_view server_name) -> std::vector<std::string>;

// True when `signatures` lists more than max_signature_keys_per_server distinct
// ed25519 key IDs for `server_name`, so not every one of them would be checked.
[[nodiscard]] auto lists_too_many_signature_keys(std::vector<events::EventSignature> const& signatures,
                                                 std::string_view server_name) -> bool;

// The server and keys a restricted join's authorising-server signature may be
// checked with: the homeserver of content.join_authorised_via_users_server and
// the first max_authorising_signature_keys key IDs the event lists under it,
// in the event's own order (empty when it lists none). std::nullopt when the
// rule does not apply (not an m.room.member event, or no such field). A field
// whose value is not a user ID yields an empty server_name: it denotes no
// homeserver, so the event cannot be validly signed and the verifier refuses
// it (a 403), never treating it as absent. Callers
// that resolve keys ahead of verification (the send_join state path) use this
// so they fetch exactly the keys the verifier will ask for.
[[nodiscard]] auto join_authorising_signature_key(canonicaljson::Value const& event)
    -> std::optional<AuthorisingSignatureKey>;

// Resolves the authorising server's signing key for a restricted join through
// the caller's own admitted key path (resolve_verification_key, or an adapter
// over a RemoteKeyResolver).
using AuthorisingKeyResolver =
    std::function<VerificationKeyResolution(std::string_view server_name, std::string_view key_id)>;
// The same contract for any server's signature (the sender's, R05).
using SignatureKeyResolver = AuthorisingKeyResolver;

// Audit R05 (ADR-0183). Whether `event` passes the signature check for
// `server_name`, judged over every ed25519 key ID `signatures` lists for it.
// server-server-api.md "Validating hashes and signatures on received events":
// "If a signature is from an unknown or expired key, it is skipped", and "If
// all signatures from known unexpired keys from the originating server(s) are
// found to be valid, the expected content hash is calculated". So a key that
// does not resolve, or expired before the event's origin_server_ts, is
// skipped; a known, unexpired key whose signature does not verify refuses the
// event (403) whatever the others say; and at least one key must verify
// (403 otherwise). More than max_signature_keys_per_server listed IDs is a
// 403 before any lookup. A local admission denial on any candidate is a
// retryable 503 and running out of `deadline` a 504: neither is a verdict.
// `signatures` is the event's parsed signatures (FederationPdu::signatures or
// EventEnvelope::signatures).
[[nodiscard]] auto verify_server_signatures_on_event(
    canonicaljson::Value const& event, rooms::RoomVersionPolicy const& room_version, std::string_view server_name,
    std::vector<events::EventSignature> const& signatures, SignatureKeyResolver const& resolve_key,
    crypto::Ed25519Provider& provider,
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max())
    -> FederationDecision;

// Audit R05: the sender-signature check of a received PDU,
// verify_server_signatures_on_event for the server of its `sender`.
// `known_key` (the X-Matrix key of a direct request) is used without calling
// `resolve_key` when it is for the sender's server and one of the listed IDs;
// every other candidate goes through `resolve_key`, which must be an admitted
// path (FED-10). A PDU missing required fields or JSON, or that does not
// parse, is a 400; an unknown room version a 500.
[[nodiscard]] auto authorize_federation_pdu_sender(
    FederationPdu const& pdu, std::optional<FederationKeyRecord> const& known_key,
    SignatureKeyResolver const& resolve_key,
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max())
    -> FederationDecision;

// EVT-1 (rooms/v8.md and v10.md auth rule 4.2.1; v12.md rule 5.2.1): an
// m.room.member event whose content carries join_authorised_via_users_server
// MUST be validly signed by that user's homeserver, whatever the join rule.
// events::authorize_event_against_auth_events only checks that such a
// signature is present, so every path that admits a PDU
// into the event graph calls this after verifying the sender's signature: the
// /send and send_join path (through the resolver overload of
// authorize_federation_pdu), worker relay re-verification, backfill
// ingestion, and the send_join state this server stores when it joins
// (filter_verified_send_join_events). An event without the field is accepted unchanged. A local
// admission denial from `resolve_key` is a retryable 503, never a verdict on
// the signature; every other failure is a 403.
//
// Each candidate key may be a remote fetch, so a caller with a wall-clock
// budget passes `deadline`: no candidate lookup starts once it has passed
// (one already in progress runs to the resolver's own timeout). Stopping for
// the deadline with nothing verified is a 504, again never a verdict.
[[nodiscard]] auto verify_join_authorising_server_signature(
    canonicaljson::Value const& event, rooms::RoomVersionPolicy const& room_version,
    AuthorisingKeyResolver const& resolve_key, crypto::Ed25519Provider& provider,
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max())
    -> FederationDecision;
// As above, verifying with libsodium directly (no signing provider involved).
[[nodiscard]] auto verify_join_authorising_server_signature(
    canonicaljson::Value const& event, rooms::RoomVersionPolicy const& room_version,
    AuthorisingKeyResolver const& resolve_key,
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max())
    -> FederationDecision;

// FED-10, ADR-0155: the key of `server_name`/`key_id` for verifying the state of
// a room this server is joining. A network-free cached key is used when there
// is one. Otherwise the fetch takes one of this runtime's
// key_resolution_max_in_flight slots and honours the server/key failure cache,
// like every other network resolution, but it waits for a free slot (until
// `deadline`) instead of being refused, and is not charged to a per-source
// rate: a join needs one key per server in the room, and refusing would drop
// member events and leave the joined room's state incomplete.
//
// nullopt when the key cannot be resolved, the pair recently failed, or no
// slot came free before `deadline`. Must be called without
// FederationRuntimeState::mutex held (it waits on it).
[[nodiscard]] auto resolve_join_state_key(FederationRuntimeState& runtime, std::string_view server_name,
                                          std::string_view key_id, std::chrono::steady_clock::time_point deadline)
    -> std::optional<FederationKeyRecord>;

[[nodiscard]] auto handle_inbound_federation_request(FederationRuntimeState& runtime,
                                                     SignedFederationRequest const& request) -> FederationResponse;

// Verifies an inbound federation request's X-Matrix signature using the main
// process federation runtime (remote key resolution + Ed25519 verify + policy).
// Returns the verified peer identity on success, or the error response to
// return on failure. The main process calls this before forwarding only the
// verified identity to the federation worker over the authenticated IPC
// channel (#323), so the raw peer Authorization header (origin/key/sig) never
// crosses the IPC boundary and cannot be harvested by a compromised worker.
//
// Security (audit M-05, 2026-09): this function ALWAYS performs the Ed25519
// verification. It ignores SignedFederationRequest::signature_verified — that
// bypass belongs solely to handle_inbound_federation_request, the worker entry
// point. Do not reintroduce the flag check here: a plain bool on a
// caller-supplied struct must never stand in for cryptographic authentication.
[[nodiscard]] auto verify_inbound_federation_signature(FederationRuntimeState& runtime,
                                                       SignedFederationRequest const& request)
    -> InboundSignatureVerification;
[[nodiscard]] auto federation_runtime_summary(FederationRuntimeState const& runtime) -> std::string;
[[nodiscard]] auto federation_audit_is_safe(FederationRuntimeState const& runtime) -> bool;

// Completed-transaction dedupe (Matrix v1.19 server-server API, PUT
// /send/{txnId}: the sender retries one txnId until it gets 200). Main's
// accepted_transactions ring is the record for every transaction that reached
// main, whichever process ran it: the federation proxy records the ones the
// worker completes, so a retry that later reaches main, or the worker after a
// restart, is not processed again (ADR-0160).

// The txnId of a /_matrix/federation/v1/send/{txnId} target, or empty.
[[nodiscard]] auto federation_send_transaction_id(std::string_view target) -> std::string;
// The (edu_type, canonical content JSON) of every EDU in a /send body, in order, exactly as
// handle_inbound_federation_request hands them to the EDU sink: the same parse (`parse_lossless`, so a float,
// an out-of-range integer, a duplicate key or a depth or size overrun refuses the whole body), the same members
// skipped, the same canonical serialisation (keys sorted). Empty when the body is not a valid transaction.
// Main uses it to bind the EDUs a worker relays to the body it authenticated (F-74, ADR-0395).
[[nodiscard]] auto extract_transaction_edus(std::string_view body) -> std::vector<std::pair<std::string, std::string>>;
[[nodiscard]] auto federation_transaction_completed(FederationRuntimeState const& runtime, std::string_view origin,
                                                    std::string_view transaction_id) -> bool;
// The answer a completed transaction was first given: nullopt when the
// transaction is not in the ring, empty when its answer was not kept.
[[nodiscard]] auto completed_federation_transaction_answer(FederationRuntimeState const& runtime,
                                                           std::string_view origin, std::string_view transaction_id)
    -> std::optional<std::string>;
// Appends to the bounded ring, evicting the oldest entries at the configured
// entry cap and answer byte budget. Records nothing if the transaction is
// already there.
auto record_completed_federation_transaction(FederationRuntimeState& runtime, FederationAcceptedTransaction transaction)
    -> void;

} // namespace merovingian::federation
