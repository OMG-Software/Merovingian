// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/event.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/federation/security.hpp"
#include "merovingian/federation/transactions.hpp"
#include "merovingian/observability/observability.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

struct FederationSigningKey final
{
    std::string server_name{};
    std::string key_id{};
    std::string verify_token{};
    bool loaded{false};
};

struct FederationKeyRecord final
{
    std::string server_name{};
    std::string key_id{};
    std::uint64_t valid_until_ts{0U};
    // Raw 32-byte Ed25519 public key (not base64) used to verify signatures
    // produced by this server. Populated from the remote's published
    // /_matrix/key/v2/server response.
    std::string public_key_bytes{};
};

// Parsed fields from an Authorization: X-Matrix ... header.
struct XMatrixCredentials final
{
    std::string origin{};
    std::string destination{};
    std::string key_id{};
    std::string signature{};
};

struct SignedFederationRequest final
{
    std::string method{};
    std::string target{};
    std::string origin{};
    // Destination (receiving) server name. Part of the Matrix X-Matrix signed
    // request object: the verifier rebuilds the signed payload with it, so it
    // must equal this server's own name.
    std::string destination{};
    std::string key_id{};
    std::string signature{};
    // Current wall-clock time in milliseconds. Used only to reject a request
    // signed with a remote key whose published validity window has lapsed;
    // the Matrix request-signing scheme itself carries no timestamp.
    std::uint64_t now_ts{0U};
    bool canonical_json_verified{false};
    std::string body{};
    // Non-empty when the request arrived on a TLS connection. The inbound
    // handler compares this against the X-Matrix origin claim so a relay
    // cannot spoof origin through header injection.
    std::string tls_peer_server_name{};
};

struct FederationPdu final
{
    std::string event_id{};
    std::string room_id{};
    std::string event_type{};
    std::string sender{};
    std::vector<events::EventSignature> signatures{};
    std::string json{};
};

struct FederationAcceptedTransaction final
{
    std::string origin{};
    std::string transaction_id{};
    std::size_t pdu_count{0U};
    std::size_t edu_count{0U};
};

struct FederationRemoteRuntime final
{
    std::string server_name{};
    RemoteTrustState trust{};
    FederationKeyRecord signing_key{};
    RemoteServerRecord discovery{};
};

// On-demand resolver for remote federation peers. The resolver is responsible
// for any discovery, network fetch, self-signature verification, and caching
// — the federation core only consumes the returned record. The returned
// runtime carries both the verified signing key and the resolved discovery
// state so the inbound bootstrap path can pass the SSRF/TLS policy on the
// first request from a previously-unknown remote. Returning std::nullopt
// signals that resolution failed and the request must be rejected.
using RemoteKeyResolver =
    std::function<std::optional<FederationRemoteRuntime>(std::string_view server_name, std::string_view key_id)>;

// Result of a federation `query/profile` lookup. found=false means the user
// is unknown to this server and the handler responds 404 M_NOT_FOUND.
struct FederationProfile final
{
    bool found{false};
    std::string displayname{};
    std::string avatar_url{};
};

// Resolves a local user's published profile for an inbound federation
// `GET /_matrix/federation/v1/query/profile`. Optional: when unset the
// handler responds 501 Not Implemented.
using ProfileQueryProvider = std::function<FederationProfile(std::string_view user_id)>;

// Server-blind E2EE federation query hooks. The two POST hooks take the
// request body and return the canonical-JSON response body; the devices hook
// takes the path user_id. An empty return signals failure. Optional: an unset
// hook makes the corresponding route respond 501 Not Implemented.
using DeviceKeysQueryProvider = std::function<std::string(std::string_view request_body)>;
using OneTimeKeysClaimProvider = std::function<std::string(std::string_view request_body)>;
using UserDevicesProvider = std::function<std::string(std::string_view user_id)>;

// Inbound event-graph query hooks. Each takes the parsed path component (and
// for `get_missing_events`, the request body) and returns the canonical-JSON
// response body, or an empty string on failure. Optional: an unset hook makes
// the corresponding route respond 501 Not Implemented.
using EventQueryProvider = std::function<std::string(std::string_view event_id)>;
using StateQueryProvider = std::function<std::string(std::string_view room_id)>;
using StateIdsQueryProvider = std::function<std::string(std::string_view room_id)>;
using MissingEventsQueryProvider =
    std::function<std::string(std::string_view room_id, std::string_view request_body)>;

struct FederationRuntimeState final
{
    RuntimeFederationConfig config{};
    std::vector<FederationRemoteRuntime> remotes{};
    std::vector<FederationAcceptedTransaction> accepted_transactions{};
    std::vector<observability::AuditLogEvent> audit_events{};
    RemoteKeyResolver remote_key_resolver{};
    // Optional ingestion hooks. When set, accepted PDUs are appended to the
    // event graph via pdu_sink and accepted EDUs are routed to runtime
    // surfaces (typing tracker, receipt store, etc.) via edu_sink. Both
    // hooks are invoked from handle_inbound_federation_request.
    PduSink pdu_sink{};
    EduSink edu_sink{};
    // Optional state-resolution hook invoked when pdu_sink returns
    // rejected_state_conflict with populated state_conflict context. The
    // resolver is expected to run state-resolution v2 (via
    // `apply_state_resolution_v2`) and commit the merged state to the
    // persistent store. If the resolver merges successfully the PDU is
    // counted as accepted and audited as `federation.pdu_state_resolved`;
    // otherwise the original `federation.pdu_state_conflict` audit fires
    // and the PDU is dropped.
    StateConflictResolver state_conflict_resolver{};
    // Federation membership and history endpoints. Optional: when unset
    // the handler returns 501 Not Implemented for the corresponding route
    // so callers know to fall back to the legacy "log and accept" stub
    // behaviour rather than appearing to succeed.
    MembershipTemplateProvider membership_template_provider{};
    MembershipAcceptor membership_acceptor{};
    InviteHandler invite_handler{};
    BackfillProvider backfill_provider{};
    // Optional resolver for inbound `query/profile`. When unset the handler
    // responds 501 Not Implemented.
    ProfileQueryProvider profile_query_provider{};
    // Optional resolvers for inbound E2EE key federation routes. Each unset
    // hook makes its route respond 501 Not Implemented.
    DeviceKeysQueryProvider device_keys_query_provider{};
    OneTimeKeysClaimProvider one_time_keys_claim_provider{};
    UserDevicesProvider user_devices_provider{};
    // Optional resolvers for inbound event-graph queries. Each unset hook
    // makes its route respond 501 Not Implemented.
    EventQueryProvider event_query_provider{};
    StateQueryProvider state_query_provider{};
    StateIdsQueryProvider state_ids_query_provider{};
    MissingEventsQueryProvider missing_events_query_provider{};
};

struct FederationDecision final
{
    bool accepted{false};
    std::uint16_t status{500U};
    std::string reason{};
};

struct FederationResponse final
{
    std::uint16_t status{500U};
    std::string body{};
};

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
// body-less request. `secret_key` is the raw 64-byte libsodium secret key.
// Returns the Base64-encoded signature, or an empty string on any failure.
[[nodiscard]] auto make_federation_signature(std::string_view origin, std::string_view destination,
                                             std::string_view method, std::string_view target,
                                             std::string_view body, std::string_view secret_key) -> std::string;
// Verifies a federation request against the remote's published Ed25519 public
// key. Rebuilds the Matrix signed-request object and checks the detached
// signature; also rejects a request signed with a key past its validity.
[[nodiscard]] auto verify_signed_federation_request(SignedFederationRequest const& request,
                                                    FederationKeyRecord const& key) -> FederationDecision;
[[nodiscard]] auto make_federation_runtime_state(RuntimeFederationConfig config) -> FederationRuntimeState;
auto upsert_remote(FederationRuntimeState& runtime, FederationRemoteRuntime remote) -> void;
[[nodiscard]] auto federation_remote_is_known(FederationRuntimeState const& runtime,
                                              std::string_view server_name) noexcept -> bool;
[[nodiscard]] auto authorize_federation_pdu(FederationPdu const& pdu, std::string_view expected_origin)
    -> FederationDecision;
[[nodiscard]] auto authorize_federation_pdu(FederationPdu const& pdu, std::string_view expected_origin,
                                            std::optional<FederationKeyRecord> const& key) -> FederationDecision;
[[nodiscard]] auto parse_federation_pdu(std::string_view encoded) -> FederationPdu;
[[nodiscard]] auto handle_inbound_federation_request(FederationRuntimeState& runtime,
                                                     SignedFederationRequest const& request) -> FederationResponse;
[[nodiscard]] auto federation_runtime_summary(FederationRuntimeState const& runtime) -> std::string;
[[nodiscard]] auto federation_audit_is_safe(FederationRuntimeState const& runtime) noexcept -> bool;

} // namespace merovingian::federation
