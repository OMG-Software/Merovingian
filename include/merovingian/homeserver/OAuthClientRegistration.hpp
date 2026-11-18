// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/oauth/ClientMetadata.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

struct ClientServerRuntime;
struct HomeserverRuntime;

// The most idle clients one registration deletes to make room at the cap (ADR-0780). A registration needs one slot,
// so one deletion is the usual case; the bound keeps a request's work fixed even if the cap was lowered below the
// number held.
inline constexpr auto max_oauth_client_evictions_per_registration = std::size_t{8U};

// POST /_merovingian/oauth2/register (spec "Client registration", RFC 7591; plan P2, ADR-0779 to ADR-0781).
// `content_type` is the request's Content-Type header (empty when absent) and `body` its body; the dispatcher has
// matched the route and checked that `server.oauth.enabled` is true.
//
//  - A body over database::max_oauth_client_metadata_bytes, a Content-Type other than `application/json` (optionally
//    with `charset=utf-8`), or a body that is not JSON: 400 `invalid_client_metadata`.
//  - Metadata oauth::ClientMetadata::validate refuses: 400 with the refusal's code and fixed text.
//  - Otherwise the client ID is `oauth_client_id_of` the accepted metadata. A held client is touched
//    (database::touch_oauth_client, a write at most once a day); a new one is stored, after deleting idle clients
//    least recently used first when `runtime.limits.max_oauth_clients` are held. A client with a session, or one
//    `oauth_client_has_pending_authorisation` names, is never deleted. When nothing can go: 503
//    `temporarily_unavailable`, nothing stored.
//  - Success: 201 with `client_id`, `client_id_issued_at` (seconds, from the row's creation) and every member of
//    oauth::ClientMetadata::to_json.
//
// Every answer is oauth_json_response or oauth_error_response. Logs the client ID, the application type and the
// `client_uri` host, never the body. Requires runtime.homeserver.mutex held; makes no network call.
[[nodiscard]] auto register_oauth_client(ClientServerRuntime& runtime, std::string_view content_type,
                                         std::string_view body) -> LocalHttpResponse;

// The 400 `invalid_client_metadata` for a registration body over database::max_oauth_client_metadata_bytes, as
// register_oauth_client answers it. Reads no state, so the dispatcher's general body cap may answer it before taking
// runtime.homeserver.mutex (ADR-0781).
[[nodiscard]] auto oauth_client_metadata_too_large() -> LocalHttpResponse;

// The client ID this server gives `metadata` (plan P2, ADR-0779): crypto::oauth_client_id over
// `metadata.canonical_bytes()` under the key derived from the master key file. The same metadata always gives the same
// ID on this server. nullopt when no master key can be read or a primitive failed: no ID can be issued then.
[[nodiscard]] auto oauth_client_id_of(HomeserverRuntime const& runtime, oauth::ClientMetadata const& metadata)
    -> std::optional<std::string>;

// The registered metadata of client `client_id`, read back for an authorisation, token or revocation request
// (oauth/AGENTS.md rule 11): the row is found, its `metadata_json` parsed and validated again by
// oauth::ClientMetadata::validate. nullopt for an unknown client, and for a stored row that no longer validates,
// which is treated as unknown and logged at warning level with its client ID only, never its content. Requires
// runtime.mutex held; reads memory only.
[[nodiscard]] auto find_registered_oauth_client(HomeserverRuntime const& runtime, std::string_view client_id)
    -> std::optional<oauth::ClientMetadata>;

} // namespace merovingian::homeserver
