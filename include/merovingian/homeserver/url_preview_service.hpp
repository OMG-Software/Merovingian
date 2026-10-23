// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <string_view>

namespace merovingian::homeserver
{

// ADR-0213: GET /_matrix/client/v1/media/preview_url (and the deprecated
// /_matrix/media/v3/preview_url) for the authenticated `user_id`.
//
// This fetches a URL a client names, so every fetch goes through one gate:
// http or https only; the host resolved and every address checked against the
// private, loopback, link-local, CGNAT, multicast and reserved ranges and
// security.federation.deny_ip_ranges (IPv4 and IPv6), then pinned for the
// connection; the same check again for every redirect hop, at most
// security.media.url_preview_max_redirects of them; one deadline
// (url_preview_timeout_seconds) and byte caps (url_preview_max_page_size,
// url_preview_max_image_size) for the whole preview. Only HTML is parsed, by
// media::extract_open_graph. An og:image is fetched through the same gate and
// stored through the normal upload pipeline as `user_id`'s media.
//
// Runs with runtime.mutex held and published (RequestLockScope); every network
// call and DNS lookup releases it. On a main-pool thread it does no network
// work: it defers to the media fetch pool (ADR-0121) after the checks that need
// no network (enabled, parameters, cache). Results, failures included, are
// cached by URL. On success `value` is the JSON body; a refusal carries its
// status and errcode (404 M_UNRECOGNIZED when previews are disabled, 400 for a
// bad `url`, 502 M_UNKNOWN for any URL that cannot be previewed, without saying
// why, so the endpoint is not an oracle for internal addresses).
[[nodiscard]] auto preview_url(HomeserverRuntime& runtime, std::string_view user_id, std::string_view url,
                               RemoteMediaRequestContext const& remote) -> OperationResult;

} // namespace merovingian::homeserver
