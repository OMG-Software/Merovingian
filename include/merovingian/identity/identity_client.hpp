// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/federation/cached_server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::identity
{

// Outcome of an Identity Service API call. `ok` reflects *transport* success
// only (DNS/TLS/SSRF/connection/timeout) — callers fail closed on `ok == false`
// and use `error`/`error_detail` for audit logging. When `ok` is true, `status`
// holds the IS HTTP status and `body` the raw response body; the caller branches
// on `status` for IS-level outcomes (e.g. a 404 on lookup means "no binding",
// not a transport failure).
struct IdentityServerResult final
{
    bool ok{false};
    std::uint16_t status{0U};
    std::string body{};
    http::OutboundError error{http::OutboundError::network_error};
    std::string error_detail{};
};

// One entry in the `public_keys` array of a store-invite response: the IS's
// long-term public key and the ephemeral public key it generated for this
// invite, each with a key_validity_url where joining servers can check it.
struct StoreInvitePublicKey final
{
    std::string public_key{};
    std::string key_validity_url{};
};

// Parsed `POST /_matrix/identity/v2/store-invite` response (200). Per the v1.19
// spec the IS — not the homeserver — generates the invite `token`, the
// redacted `display_name`, and the `public_keys` (long-term + ephemeral). The
// homeserver embeds the ephemeral public_key/key_validity_url in the
// `m.room.third_party_invite` event so joining servers can verify the invite
// signature via the IS.
struct StoreInviteResponse final
{
    std::string token{};
    std::string display_name{};
    std::vector<StoreInvitePublicKey> public_keys{};
};

// Parsed `POST /_matrix/identity/v2/lookup` response (200): the MXID bound to
// the 3PID. Empty `mxid` means the IS has no binding for the 3PID.
struct LookupResponse final
{
    std::string mxid{};
};

// Parsed identity-server base URL. The IS is configured by absolute HTTPS URL
// (e.g. "https://is.example.org" or "https://is.example.org:8448/path"); the
// host and port drive SSRF-safe address resolution and the optional `path`
// prefixes every IS API path.
struct IdentityServerUrl final
{
    std::string host{};
    std::uint16_t port{443U};
    std::string path{};
};

// Pure validator + parser for an identity-server base URL. Returns nullopt for
// anything that is not an `https://` URL with a non-empty host. No network.
[[nodiscard]] auto parse_identity_server_url(std::string_view url) -> std::optional<IdentityServerUrl>;

// Pure request-body builders. Each returns the canonical JSON body for one IS
// endpoint. No network — unit-testable in isolation.
[[nodiscard]] auto build_store_invite_body(std::string_view medium, std::string_view address, std::string_view room_id,
                                           std::string_view sender) -> std::string;

[[nodiscard]] auto build_lookup_body(std::string_view medium, std::string_view address) -> std::string;

[[nodiscard]] auto build_bind_body(std::string_view client_secret, std::string_view sid, std::string_view mxid)
    -> std::string;

[[nodiscard]] auto build_unbind_body(std::string_view client_secret, std::string_view sid, std::string_view medium,
                                     std::string_view address) -> std::string;

[[nodiscard]] auto build_request_token_body(std::string_view client_secret, std::string_view email,
                                            std::string_view next_link) -> std::string;

// Pure response parsers. Return nullopt on a malformed body. No network.
[[nodiscard]] auto parse_store_invite_response(std::string_view body) -> std::optional<StoreInviteResponse>;
[[nodiscard]] auto parse_lookup_response(std::string_view body) -> std::optional<LookupResponse>;

// Outbound Identity Service API client. The homeserver is a *client* of one or
// more operator-configured identity servers (config.server().identity_server).
// Every call resolves the IS host to SSRF-safe pinned addresses via the
// runtime's CachedServerDiscovery (private/loopback ranges rejected upstream)
// and goes through http::OutboundClient with TLS verification on — no ad-hoc
// DNS, no cleartext. Authenticated endpoints carry the caller's bearer
// `id_access_token` (obtained by the client via /openid/request_token);
// unauthenticated endpoints pass an empty token.
//
// The client borrows its dependencies by reference: the OutboundClient and
// CachedServerDiscovery are owned by the HomeserverRuntime, and the
// IdentityServerConfig by the runtime's Config snapshot. Callers must keep
// them alive for the lifetime of the client.
class IdentityServerClient final
{
public:
    IdentityServerClient(http::OutboundClient& outbound, federation::CachedServerDiscovery& discovery,
                         config::IdentityServerConfig const& config) noexcept;

    // POST /_matrix/identity/v2/store-invite. `base_url` is the IS base URL
    // (must be in config.trusted_servers at the call site); `id_access_token`
    // authenticates the inviting user. Per the v1.19 spec the IS generates the
    // invite token and ephemeral key, so the HS sends only {medium, address,
    // room_id, sender}. On 200 the caller parses `body` with
    // parse_store_invite_response. Fails closed (ok==false) on any transport error.
    [[nodiscard]] auto store_invite(std::string_view base_url, std::string_view id_access_token,
                                    std::string_view medium, std::string_view address, std::string_view room_id,
                                    std::string_view sender) -> IdentityServerResult;

    // POST /_matrix/identity/v2/lookup. Resolves a (medium, address) to a bound
    // MXID. Unauthenticated (no id_access_token required by the IS).
    [[nodiscard]] auto lookup(std::string_view base_url, std::string_view medium, std::string_view address)
        -> IdentityServerResult;

    // POST /_matrix/identity/v2/3pid/bind. Binds a validated 3PID (client_secret
    // + sid from a prior requestToken flow) to `mxid` at the IS. Authenticated.
    [[nodiscard]] auto bind(std::string_view base_url, std::string_view id_access_token, std::string_view client_secret,
                            std::string_view sid, std::string_view mxid) -> IdentityServerResult;

    // POST /_matrix/identity/v2/3pid/unbind. Removes a 3PID binding. Authenticated.
    [[nodiscard]] auto unbind(std::string_view base_url, std::string_view id_access_token,
                              std::string_view client_secret, std::string_view sid, std::string_view medium,
                              std::string_view address) -> IdentityServerResult;

    // POST /_matrix/identity/v2/validate/email/requestToken. Starts an email
    // validation session; the IS mails a token and returns a `sid`. The caller
    // persists the (sid, client_secret) pair. Authenticated.
    [[nodiscard]] auto request_email_token(std::string_view base_url, std::string_view id_access_token,
                                           std::string_view client_secret, std::string_view email,
                                           std::string_view next_link) -> IdentityServerResult;

private:
    // Builds and performs one IS request: resolves base_url to SSRF-safe pinned
    // addresses, applies the configured timeouts, attaches the bearer token,
    // and returns the raw OutboundResult mapped to IdentityServerResult.
    [[nodiscard]] auto perform(std::string_view base_url, std::string_view method, std::string_view path,
                               std::string_view id_access_token, std::string_view body) -> IdentityServerResult;

    http::OutboundClient& outbound_;
    federation::CachedServerDiscovery& discovery_;
    config::IdentityServerConfig const& config_;
};

} // namespace merovingian::identity