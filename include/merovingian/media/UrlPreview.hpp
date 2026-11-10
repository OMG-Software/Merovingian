// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/OpenGraphData.hpp"

#include <cstddef>
#include <cstdint>
#include <list>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::media
{

// ADR-0213: the pure parts of URL previews (GET /_matrix/client/v1/media/preview_url).
// Nothing here performs I/O; the fetching, SSRF gating and storage live in
// homeserver/UrlPreviewService.cpp.

// Bounds on what one page may contribute to a preview. The page itself is
// already capped by security.media.url_preview_max_page_size.
inline constexpr std::size_t max_open_graph_properties = 32U;
inline constexpr std::size_t max_open_graph_key_bytes = 64U;
inline constexpr std::size_t max_open_graph_value_bytes = 1000U;
inline constexpr std::size_t max_open_graph_total_bytes = 8192U;
inline constexpr std::size_t max_preview_url_bytes = 2048U;

// Extracts OpenGraph `<meta property="og:..." content="...">` (or `name=`)
// tags and the first `<title>` from an HTML document in one forward pass. It
// is not an HTML parser and runs nothing: comments and the contents of
// <script> and <style> are skipped, every search moves forward, and the work is
// linear in the input. A tag that is not closed ends the scan.
[[nodiscard]] auto extract_open_graph(std::string_view html) -> OpenGraphData;

// True for the media types previews parse: text/html and application/xhtml+xml,
// with or without parameters, case-insensitively.
[[nodiscard]] auto content_type_is_html(std::string_view content_type) noexcept -> bool;

// Resolves `reference` (a redirect Location or an og:image value) against
// `base_url`, an absolute http(s) URL. An absolute http(s) URL is returned as
// is, a scheme-relative `//host/...` takes the base's scheme, and an
// absolute-path `/...` takes the base's scheme and authority. Anything else
// (a relative path, another scheme, an empty or over-long reference) yields
// an empty string, which the caller treats as a refusal.
[[nodiscard]] auto resolve_preview_reference(std::string_view base_url, std::string_view reference) -> std::string;

} // namespace merovingian::media
