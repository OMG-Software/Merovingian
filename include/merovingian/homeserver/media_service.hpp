// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/media/thumbnailer.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

[[nodiscard]] auto upload_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                      std::string_view declared_mime_type, std::string_view sniffed_mime_type,
                                      bool scanner_clean, std::string_view bytes) -> OperationResult;
[[nodiscard]] auto download_local_media(HomeserverRuntime& runtime, std::string_view server_name,
                                        std::string_view media_id) -> OperationResult;
[[nodiscard]] auto download_local_media_thumbnail(HomeserverRuntime& runtime, std::string_view server_name,
                                                  std::string_view media_id, std::uint32_t width, std::uint32_t height,
                                                  media::ThumbnailMethod method) -> OperationResult;
[[nodiscard]] auto admin_quarantine_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                                std::string_view media_id, std::string_view reason) -> OperationResult;
[[nodiscard]] auto admin_release_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                             std::string_view media_id) -> OperationResult;
[[nodiscard]] auto admin_remove_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                            std::string_view media_id, std::string_view reason) -> OperationResult;
[[nodiscard]] auto remote_media_fetch_disabled(HomeserverRuntime& runtime, std::string_view origin_server,
                                               std::string_view media_id) -> OperationResult;
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
};

// Resolves a media redirect URL in an SSRF-safe way so the caller can fetch
// it with pinned addresses. `location_url` must be an absolute https:// URL;
// relative redirects are rejected. Exposed for unit testing.
[[nodiscard]] auto resolve_media_redirect_url(std::string_view location_url,
                                              federation::ServerDiscoveryNetwork& network)
    -> MediaRedirectResolutionResult;
[[nodiscard]] auto media_metrics_summary(HomeserverRuntime const& runtime) -> std::string;

} // namespace merovingian::homeserver
