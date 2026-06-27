// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::media
{

// Resampling method requested by the client (Matrix CS API §thumbnails).
// `scale` fits the image within the box preserving aspect ratio; `crop`
// fills the box and trims the overflow, also preserving aspect ratio.
enum class ThumbnailMethod : std::uint8_t
{
    scale = 0U,
    crop = 1U,
};

// Source pixel format the worker should decode. Only the still-image formats
// the resampler supports are represented; animated/unsupported types never
// reach the worker.
enum class ThumbnailSourceFormat : std::uint8_t
{
    png = 0U,
    jpeg = 1U,
};

// Status the sandboxed worker reports back for a single request. Anything other
// than `ok` means no thumbnail bytes were produced.
enum class ThumbnailWorkerStatus : std::uint8_t
{
    ok = 0U,
    decode_failed = 1U,
    too_large = 2U,
    unsupported = 3U,
    internal_error = 4U,
};

// A decode+resample job handed to the worker over its stdin pipe.
struct ThumbnailWorkerRequest final
{
    ThumbnailSourceFormat format{ThumbnailSourceFormat::png};
    ThumbnailMethod method{ThumbnailMethod::scale};
    std::uint32_t target_width{0U};
    std::uint32_t target_height{0U};
    std::uint32_t max_pixels{0U}; // decode guard: reject images above this area
    std::string source_bytes{};
};

// The worker's reply, read from its stdout pipe.
struct ThumbnailWorkerResponse final
{
    ThumbnailWorkerStatus status{ThumbnailWorkerStatus::internal_error};
    std::uint32_t width{0U};
    std::uint32_t height{0U};
    std::string png_bytes{};
};

// Parent-facing request: the original media bytes plus the requested geometry.
struct ThumbnailRequest final
{
    std::string source_bytes{};
    std::string source_content_type{};
    std::uint32_t width{0U};
    std::uint32_t height{0U};
    ThumbnailMethod method{ThumbnailMethod::scale};
};

// Parent-facing result. `ok` thumbnails always carry `image/png` bytes.
struct ThumbnailResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string content_type{};
    std::string bytes{};
    std::uint32_t width{0U};
    std::uint32_t height{0U};
    std::string reason{};
};

// Configuration for spawning the out-of-process worker.
struct ThumbnailerConfig final
{
    std::string worker_path{};          // absolute path to the worker executable
    std::uint32_t timeout_seconds{10U}; // wall-clock cap on a single decode
    std::uint64_t max_input_bytes{0U};  // 0 = unbounded; reject larger sources
    std::uint64_t max_output_bytes{0U}; // 0 = unbounded; reject larger results
    std::uint32_t max_pixels{4096000U}; // decode-bomb guard handed to the worker
    std::uint32_t max_target_dimension{2048U};
};

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

} // namespace merovingian::media
