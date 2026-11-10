// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/LibraryVersion.hpp"
#include "merovingian/media/ThumbnailRequest.hpp"
#include "merovingian/media/ThumbnailResult.hpp"
#include "merovingian/media/ThumbnailSourceFormat.hpp"
#include "merovingian/media/ThumbnailWorkerLibraries.hpp"
#include "merovingian/media/ThumbnailWorkerRequest.hpp"
#include "merovingian/media/ThumbnailWorkerResponse.hpp"
#include "merovingian/media/ThumbnailerConfig.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::media
{

// The largest thumbnail axis the sandboxed worker produces. A larger request
// is clamped to it, so every size past it yields the same bytes.
inline constexpr auto max_thumbnail_dimension = std::uint32_t{4096U};

// --- Wire protocol (shared by parent and worker; pure, no I/O) ---------------
// The framing is deliberately tiny and fixed so both ends agree byte-for-byte
// and it can be exercised by unit tests without spawning a process.

[[nodiscard]] auto map_content_type_to_source_format(std::string_view content_type)
    -> std::optional<ThumbnailSourceFormat>;

// Returns nullopt when source_bytes.size() exceeds UINT32_MAX (wire protocol limit).
[[nodiscard]] auto frame_thumbnail_request(ThumbnailWorkerRequest const& request) -> std::optional<std::string>;
[[nodiscard]] auto parse_thumbnail_request(std::string_view frame) -> std::optional<ThumbnailWorkerRequest>;
// Returns nullopt when png_bytes.size() exceeds UINT32_MAX (wire protocol limit).
[[nodiscard]] auto frame_thumbnail_response(ThumbnailWorkerResponse const& response) -> std::optional<std::string>;
[[nodiscard]] auto parse_thumbnail_response(std::string_view frame) -> std::optional<ThumbnailWorkerResponse>;

// --- Library report (0.12.45) ------------------------------------------------
// libpng and libjpeg-turbo are linked only into the worker, so the server asks it which versions
// it runs and how each is linked, for the startup log. The request is a frame of its own, never a
// thumbnail job; the worker answers it after its hardening, like any request. The report carries
// one line per library, fields separated by tabs; every byte outside printable ASCII is sent as
// '?', so nothing a library or the loader names can split a field or start a log line.

// More than the worker links; a longer report is refused.
inline constexpr std::size_t max_library_report_entries{8U};

[[nodiscard]] auto frame_library_report_request() -> std::string;
[[nodiscard]] auto is_library_report_request(std::string_view frame) noexcept -> bool;
[[nodiscard]] auto frame_library_report(std::span<core::LibraryVersion const> libraries) -> std::string;
// nullopt for anything the worker would not send: a wrong magic or length, a field that is not
// printable ASCII or is longer than the framing allows, an unknown linkage, too many entries.
[[nodiscard]] auto parse_library_report(std::string_view frame) -> std::optional<std::vector<core::LibraryVersion>>;

// --- Parent driver -----------------------------------------------------------

// Normalises and validates the requested geometry against the policy in
// `config`, returning the clamped (width, height) or nullopt when the request
// is unusable (zero or above the configured maximum dimension).
[[nodiscard]] auto normalise_thumbnail_dimensions(ThumbnailerConfig const& config, std::uint32_t width,
                                                  std::uint32_t height)
    -> std::optional<std::pair<std::uint32_t, std::uint32_t>>;

// Spawns the sandboxed worker, feeds it the source bytes, and returns the
// resampled PNG. On any spawn/deceode failure the result carries ok=false and a
// non-200 status; callers decide whether to fall back to the original bytes.
[[nodiscard]] auto generate_thumbnail(ThumbnailerConfig const& config, ThumbnailRequest const& request)
    -> ThumbnailResult;

// Spawns the worker as for a thumbnail and asks it for its library report. Without one, `error`
// says why: no worker configured, the worker could not run, or its answer was malformed.
[[nodiscard]] auto query_thumbnail_worker_libraries(ThumbnailerConfig const& config) -> ThumbnailWorkerLibraries;

} // namespace merovingian::media
