// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/media/thumbnailer.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// `upload_name` is the upload's `filename` query parameter (R17); one that
// fails media::media_filename_is_valid is refused with 400 M_INVALID_PARAM.
[[nodiscard]] auto upload_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                      std::string_view declared_mime_type, std::string_view sniffed_mime_type,
                                      bool scanner_clean, std::string_view bytes, std::string_view upload_name = {})
    -> OperationResult;
// ADR-0212: POST /_matrix/media/v1/create. On success `value` is
// "<content_uri>|<unused_expires_at>"; 429 (errcode M_LIMIT_EXCEEDED) when the
// user or the server holds too many pending uploads.
[[nodiscard]] auto create_pending_media_upload(HomeserverRuntime& runtime, std::string_view access_token)
    -> OperationResult;
// ADR-0212: PUT /_matrix/media/v3/upload/{serverName}/{mediaId} for a local
// `media_id`. Same MIME policy, quarantine, size limits and quotas as
// upload_local_media. Refusals carry the spec's errcode: 404 M_NOT_FOUND (not
// reserved, or expired), 403 M_FORBIDDEN (reserved by someone else), 409
// M_CANNOT_OVERWRITE_MEDIA (content already uploaded).
[[nodiscard]] auto upload_pending_media(HomeserverRuntime& runtime, std::string_view access_token,
                                        std::string_view media_id, std::string_view declared_mime_type,
                                        std::string_view sniffed_mime_type, bool scanner_clean, std::string_view bytes,
                                        std::string_view upload_name = {}) -> OperationResult;
// What a remote-media request carries beyond the media it names. Ignored for
// media hosted on this server.
struct RemoteMediaRequestContext final
{
    // The client the request is attributed to (rate_limit_client_key), which the
    // per-client cap of the client-outbound budget counts under (ADR-0079).
    // "unknown" is what a request with no peer address is keyed as.
    std::string client_key{"unknown"};
    // The authenticated user, empty when the request carries no valid token.
    // The per-requester thumbnail decode cap (MED-4) counts under it, or under
    // client_key when it is empty.
    std::string requester{};
    // The `allow_remote` query parameter (default true). False means the caller
    // does not want this server to go and fetch remote media (OUT-7).
    bool allow_remote{true};
    // ADR-0212: the `timeout_ms` query parameter (spec default 20000): how long
    // a download of a reserved but not yet uploaded local media ID may wait.
    // Capped by security.media.pending_upload_max_wait_ms.
    std::uint32_t timeout_ms{20000U};
};

// Download / thumbnail of `server_name`/`media_id`. For a remote `server_name`:
// 404 (nothing leaves the server) unless security.media.remote_fetch_enabled is
// set and `remote.allow_remote` is true; 429 when the client-outbound budget is
// exhausted; otherwise a live fetch under one 30 s deadline.
[[nodiscard]] auto download_local_media(HomeserverRuntime& runtime, std::string_view server_name,
                                        std::string_view media_id, bool legacy_endpoint = false,
                                        RemoteMediaRequestContext const& remote = {}) -> OperationResult;
[[nodiscard]] auto download_local_media_thumbnail(HomeserverRuntime& runtime, std::string_view server_name,
                                                  std::string_view media_id, std::uint32_t width, std::uint32_t height,
                                                  media::ThumbnailMethod method, bool legacy_endpoint = false,
                                                  RemoteMediaRequestContext const& remote = {}) -> OperationResult;
// GET /_matrix/federation/v1/media/download/{mediaId}: local media only. The
// federation core calls its providers without the runtime mutex, so this takes
// it for the repository lookups and releases it for the byte read (ADR-0119).
// Never call it with the mutex held by another frame of this thread.
[[nodiscard]] auto download_local_media_for_federation(HomeserverRuntime& runtime, std::string_view media_id)
    -> media::LocalMediaDownloadResult;
// GET /_matrix/federation/v1/media/thumbnail/{mediaId}: a thumbnail of local media, through the same
// path as the client thumbnail (cache, decode worker, per-requester cap). Takes the runtime mutex like
// the download above; a reserved ID with no content is 504 at once, and no remote media is fetched.
[[nodiscard]] auto download_local_media_thumbnail_for_federation(HomeserverRuntime& runtime,
                                                                 federation::FederationThumbnailQuery const& query)
    -> media::LocalMediaDownloadResult;
[[nodiscard]] auto admin_quarantine_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                                std::string_view media_id, std::string_view reason) -> OperationResult;
[[nodiscard]] auto admin_release_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                             std::string_view media_id) -> OperationResult;
[[nodiscard]] auto admin_remove_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                            std::string_view media_id, std::string_view reason) -> OperationResult;
[[nodiscard]] auto remote_media_fetch_disabled(HomeserverRuntime& runtime, std::string_view origin_server,
                                               std::string_view media_id) -> OperationResult;
// ADR-0213: stores bytes this server fetched on `owner_user_id`'s behalf (a
// URL preview's og:image) through the same pipeline as an upload: MIME
// sniffing, the scanner check, MIME policy, quarantine, the size limit and the
// owner's quotas. On success `value` is "<content_uri>|<size_bytes>|<content_type>";
// quarantined media is stored but refused (451) so it is never advertised.
[[nodiscard]] auto store_fetched_media_for_user(HomeserverRuntime& runtime, std::string_view owner_user_id,
                                                std::string_view declared_mime_type, std::string_view bytes)
    -> OperationResult;
// Builds the deprecated, unauthenticated federation media download URL:
// /_matrix/media/v3/download/{serverName}/{mediaId}
// (server-server-api.md#get_matrixmediav3downloadservernamemediaid). origin_server
// and media_id are percent-encoded so a reserved character in either cannot be
// misinterpreted as an extra path segment or a different route on the resolved
// host. Spec: servers MUST only use this endpoint as a fallback (with
// allow_remote=false) after the authenticated endpoint below returns 404.
// Exposed for unit testing.
[[nodiscard]] auto remote_media_download_url(std::string_view resolved_host, std::uint16_t resolved_port,
                                             std::string_view origin_server, std::string_view media_id) -> std::string;
// Builds the mandatory, authenticated federation media download URL:
// /_matrix/federation/v1/media/download/{mediaId}
// (server-server-api.md#get_matrixfederationv1mediadownloadmediaid, added in v1.11).
// Unlike the deprecated endpoint above, the server name is not part of the path —
// the destination server is implied by which host the request is sent to, and the
// request must carry an X-Matrix Authorization header since the caller is a server,
// not a user. media_id is percent-encoded so a reserved character cannot be
// misinterpreted as an extra path segment. Exposed for unit testing.
[[nodiscard]] auto remote_federation_media_download_url(std::string_view resolved_host, std::uint16_t resolved_port,
                                                        std::string_view media_id) -> std::string;

// Result of parsing a 200 response from the authenticated federation media
// download endpoint. Per spec the response is always `multipart/mixed` with
// exactly two parts: an (currently always empty) JSON metadata part, and
// either the media bytes or a `Location` redirect header. `ok` is false when
// the response could not be parsed as a well-formed two-part multipart body.
// `is_redirect` is true when the second part carries a `Location` header
// instead of inline bytes; `location` is only populated in that case.
struct FederationMediaPart final
{
    bool ok{false};
    bool is_redirect{false};
    std::string content_type{};
    std::string bytes{};
    std::string location{};
    // R17: the filename in the media part's Content-Disposition, if any.
    std::string filename{};
};

// Parses the multipart/mixed body of a /_matrix/federation/v1/media/download/{mediaId}
// 200 response. `content_type_header` is the outer response's Content-Type header
// value (used to extract the boundary parameter); `body` is the raw response body.
// Pure function; performs no I/O. Exposed for unit testing.
[[nodiscard]] auto parse_federation_media_multipart(std::string_view content_type_header, std::string_view body)
    -> FederationMediaPart;

// Result of resolving a `Location` redirect URL from the authenticated
// federation media download endpoint. `ok` is true when the URL uses HTTPS,
// has a resolvable host, and resolves only to non-private/non-loopback
// addresses. `discovery` carries the pinned addresses when resolution
// succeeds; `reason` explains the failure when it does not.
struct MediaRedirectResolutionResult final
{
    bool ok{false};
    std::string reason{};
    federation::ServerDiscoveryResult discovery{};
    std::string url{}; // Canonical URL from the transport's parser; use this for the fetch.
};

// Resolves a media redirect URL in an SSRF-safe way so the caller can fetch
// it with pinned addresses. `location_url` must be an absolute https:// URL;
// relative redirects are rejected. Exposed for unit testing.
[[nodiscard]] auto resolve_media_redirect_url(std::string_view location_url,
                                              federation::ServerDiscoveryNetwork& network)
    -> MediaRedirectResolutionResult;
[[nodiscard]] auto media_metrics_summary(HomeserverRuntime const& runtime) -> std::string;

} // namespace merovingian::homeserver
