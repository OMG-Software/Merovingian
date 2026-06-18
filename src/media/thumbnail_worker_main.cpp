// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// merovingian-thumbnail-worker — out-of-process, sandboxed image resampler.
//
// The main homeserver NEVER decodes untrusted image bytes in-process. It spawns
// this short-lived worker, which:
//   1. clamps its own resources (address space, CPU, file size, descriptors)
//      and installs the seccomp-bpf syscall filter before reading any input,
//   2. reads a single framed request from stdin (see media/thumbnailer.hpp),
//   3. decodes PNG (libpng) or JPEG (libjpeg-turbo) into an RGBA8 buffer,
//      enforcing a pixel-count bomb guard,
//   4. resamples to the requested geometry (scale or crop), and
//   5. writes a framed PNG response to stdout.
//
// A decoder exploit is therefore contained: the worker holds no secrets, no
// sockets, and no filesystem access beyond the inherited stdio pipes.

#include "merovingian/media/thumbnailer.hpp"
#include "merovingian/platform/seccomp_hardening.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <tuple>
#include <vector>

#include <png.h>
#include <sys/resource.h>
#include <turbojpeg.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

namespace
{

// Sanitizer builds (ASan/TSan/MSan) reserve an enormous virtual address space
// for shadow memory, which a tight RLIMIT_AS would make un-mmap-able — the
// instrumented worker would die before decoding. Detect such builds so the
// address-space cap is skipped there (CI only); production builds keep it.
#if defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || __has_feature(memory_sanitizer)
constexpr bool sanitizer_build = true;
#else
constexpr bool sanitizer_build = false;
#endif
#elif defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
constexpr bool sanitizer_build = true;
#else
constexpr bool sanitizer_build = false;
#endif

using merovingian::media::ThumbnailMethod;
using merovingian::media::ThumbnailSourceFormat;
using merovingian::media::ThumbnailWorkerRequest;
using merovingian::media::ThumbnailWorkerResponse;
using merovingian::media::ThumbnailWorkerStatus;

// Hard ceilings the worker imposes on itself regardless of the request, so a
// malformed frame or hostile image cannot exhaust the host.
constexpr std::size_t max_input_bytes = 64U * 1024U * 1024U;      // 64 MiB source
constexpr std::uint64_t max_address_space = 768U * 1024U * 1024U; // 768 MiB RSS+heap
#if defined(NDEBUG)
constexpr std::uint64_t max_cpu_seconds = sanitizer_build ? 120U : 15U;
#else
constexpr std::uint64_t max_cpu_seconds = sanitizer_build ? 120U : 60U;
#endif
constexpr std::uint64_t max_file_size = 64U * 1024U * 1024U;
constexpr std::uint32_t absolute_max_dimension = 4096U;

struct Rgba final
{
    std::vector<unsigned char> pixels{}; // width*height*4, RGBA8
    std::uint32_t width{0U};
    std::uint32_t height{0U};
};

// Applies self-imposed resource limits and the syscall filter. Best-effort:
// a kernel without seccomp still runs, but the rlimits always apply.
auto harden() -> void
{
    auto const apply = [](int resource, std::uint64_t value) {
        auto limit = rlimit{static_cast<rlim_t>(value), static_cast<rlim_t>(value)};
        std::ignore = ::setrlimit(resource, &limit);
    };
    if (!sanitizer_build)
    {
        // Strict resource caps are dropped in sanitizer builds because
        // ASan/TSan/MSan reserve a large virtual address space and the
        // instrumented runtime is much slower; the same build is never
        // used in production.
        apply(RLIMIT_AS, max_address_space);
    }
    apply(RLIMIT_CPU, max_cpu_seconds);
    apply(RLIMIT_FSIZE, max_file_size);
    apply(RLIMIT_CORE, 0U);
    apply(RLIMIT_NOFILE, 16U);
#if defined(__linux__)
    std::ignore = ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    std::ignore = ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    // The seccomp-bpf allowlist is incompatible with sanitizer runtimes,
    // which need syscalls (e.g. for shadow memory, error reporting, and
    // /proc access) that the production worker does not require. Skip it
    // in sanitizer builds so the worker can run under ASan/UBSan/TSan.
    if (!sanitizer_build)
    {
        std::ignore = merovingian::platform::apply_seccomp_filter();
    }
#endif
}

[[nodiscard]] auto read_all_stdin() -> std::string
{
    auto input = std::string{};
    auto buffer = std::array<char, 65536U>{};
    while (true)
    {
        auto const n = ::read(STDIN_FILENO, buffer.data(), buffer.size());
        if (n <= 0)
        {
            break;
        }
        if (input.size() + static_cast<std::size_t>(n) > max_input_bytes)
        {
            return input; // truncated; framing check will reject
        }
        input.append(buffer.data(), static_cast<std::size_t>(n));
    }
    return input;
}

auto write_all_stdout(std::string const& bytes) -> void
{
    std::size_t written = 0U;
    while (written < bytes.size())
    {
        auto const n = ::write(STDOUT_FILENO, bytes.data() + written, bytes.size() - written);
        if (n <= 0)
        {
            return;
        }
        written += static_cast<std::size_t>(n);
    }
}

[[nodiscard]] auto pixels_within_guard(std::uint32_t width, std::uint32_t height, std::uint32_t max_pixels) -> bool
{
    if (width == 0U || height == 0U || width > absolute_max_dimension || height > absolute_max_dimension)
    {
        return false;
    }
    auto const area = static_cast<std::uint64_t>(width) * static_cast<std::uint64_t>(height);
    return max_pixels == 0U || area <= static_cast<std::uint64_t>(max_pixels);
}

// --- Decoders ----------------------------------------------------------------

[[nodiscard]] auto decode_png(std::string const& bytes, std::uint32_t max_pixels, Rgba& out) -> ThumbnailWorkerStatus
{
    auto image = png_image{};
    image.version = PNG_IMAGE_VERSION;
    if (png_image_begin_read_from_memory(&image, bytes.data(), bytes.size()) == 0)
    {
        return ThumbnailWorkerStatus::decode_failed;
    }
    image.format = PNG_FORMAT_RGBA;
    if (!pixels_within_guard(image.width, image.height, max_pixels))
    {
        png_image_free(&image);
        return ThumbnailWorkerStatus::too_large;
    }
    out.width = image.width;
    out.height = image.height;
    out.pixels.resize(static_cast<std::size_t>(PNG_IMAGE_SIZE(image)));
    if (png_image_finish_read(&image, nullptr, out.pixels.data(), 0, nullptr) == 0)
    {
        png_image_free(&image);
        return ThumbnailWorkerStatus::decode_failed;
    }
    png_image_free(&image);
    return ThumbnailWorkerStatus::ok;
}

[[nodiscard]] auto decode_jpeg(std::string const& bytes, std::uint32_t max_pixels, Rgba& out) -> ThumbnailWorkerStatus
{
    auto const handle = tjInitDecompress();
    if (handle == nullptr)
    {
        return ThumbnailWorkerStatus::internal_error;
    }
    auto width = 0;
    auto height = 0;
    auto subsamp = 0;
    auto colorspace = 0;
    auto const source = reinterpret_cast<unsigned char const*>(bytes.data());
    if (tjDecompressHeader3(handle, source, static_cast<unsigned long>(bytes.size()), &width, &height, &subsamp,
                            &colorspace) != 0 ||
        width <= 0 || height <= 0)
    {
        tjDestroy(handle);
        return ThumbnailWorkerStatus::decode_failed;
    }
    if (!pixels_within_guard(static_cast<std::uint32_t>(width), static_cast<std::uint32_t>(height), max_pixels))
    {
        tjDestroy(handle);
        return ThumbnailWorkerStatus::too_large;
    }
    out.width = static_cast<std::uint32_t>(width);
    out.height = static_cast<std::uint32_t>(height);
    out.pixels.resize(static_cast<std::size_t>(width) * static_cast<std::size_t>(height) * 4U);
    auto const rc = tjDecompress2(handle, source, static_cast<unsigned long>(bytes.size()), out.pixels.data(), width, 0,
                                  height, TJPF_RGBA, TJFLAG_FASTDCT);
    tjDestroy(handle);
    return rc == 0 ? ThumbnailWorkerStatus::ok : ThumbnailWorkerStatus::decode_failed;
}

// --- Resampling --------------------------------------------------------------

// Separable bilinear resample of an RGBA8 buffer. Adequate for thumbnail
// previews; favours simplicity and a tiny, auditable code path over filter
// quality.
[[nodiscard]] auto resample_bilinear(Rgba const& src, std::uint32_t dst_w, std::uint32_t dst_h) -> Rgba
{
    auto dst = Rgba{};
    dst.width = dst_w;
    dst.height = dst_h;
    dst.pixels.resize(static_cast<std::size_t>(dst_w) * static_cast<std::size_t>(dst_h) * 4U);
    if (src.width == 0U || src.height == 0U || dst_w == 0U || dst_h == 0U)
    {
        return dst;
    }
    auto const scale_x = static_cast<double>(src.width) / static_cast<double>(dst_w);
    auto const scale_y = static_cast<double>(src.height) / static_cast<double>(dst_h);
    for (std::uint32_t y = 0U; y < dst_h; ++y)
    {
        auto const src_y = (static_cast<double>(y) + 0.5) * scale_y - 0.5;
        auto const y0 = static_cast<std::int64_t>(src_y < 0.0 ? 0.0 : src_y);
        auto const y1 = std::min<std::int64_t>(y0 + 1, static_cast<std::int64_t>(src.height) - 1);
        auto const fy = src_y - static_cast<double>(y0) < 0.0 ? 0.0 : src_y - static_cast<double>(y0);
        for (std::uint32_t x = 0U; x < dst_w; ++x)
        {
            auto const src_x = (static_cast<double>(x) + 0.5) * scale_x - 0.5;
            auto const x0 = static_cast<std::int64_t>(src_x < 0.0 ? 0.0 : src_x);
            auto const x1 = std::min<std::int64_t>(x0 + 1, static_cast<std::int64_t>(src.width) - 1);
            auto const fx = src_x - static_cast<double>(x0) < 0.0 ? 0.0 : src_x - static_cast<double>(x0);
            auto const idx = [&src](std::int64_t px, std::int64_t py) {
                return (static_cast<std::size_t>(py) * src.width + static_cast<std::size_t>(px)) * 4U;
            };
            auto const i00 = idx(x0, y0);
            auto const i10 = idx(x1, y0);
            auto const i01 = idx(x0, y1);
            auto const i11 = idx(x1, y1);
            auto const out = (static_cast<std::size_t>(y) * dst_w + x) * 4U;
            for (std::size_t c = 0U; c < 4U; ++c)
            {
                auto const top = static_cast<double>(src.pixels[i00 + c]) * (1.0 - fx) +
                                 static_cast<double>(src.pixels[i10 + c]) * fx;
                auto const bottom = static_cast<double>(src.pixels[i01 + c]) * (1.0 - fx) +
                                    static_cast<double>(src.pixels[i11 + c]) * fx;
                auto const value = top * (1.0 - fy) + bottom * fy;
                dst.pixels[out + c] = static_cast<unsigned char>(value + 0.5);
            }
        }
    }
    return dst;
}

[[nodiscard]] auto crop_center(Rgba const& src, std::uint32_t crop_w, std::uint32_t crop_h) -> Rgba
{
    auto dst = Rgba{};
    dst.width = crop_w;
    dst.height = crop_h;
    dst.pixels.resize(static_cast<std::size_t>(crop_w) * static_cast<std::size_t>(crop_h) * 4U);
    auto const off_x = src.width > crop_w ? (src.width - crop_w) / 2U : 0U;
    auto const off_y = src.height > crop_h ? (src.height - crop_h) / 2U : 0U;
    for (std::uint32_t y = 0U; y < crop_h; ++y)
    {
        for (std::uint32_t x = 0U; x < crop_w; ++x)
        {
            auto const sx = std::min(off_x + x, src.width - 1U);
            auto const sy = std::min(off_y + y, src.height - 1U);
            auto const si = (static_cast<std::size_t>(sy) * src.width + sx) * 4U;
            auto const di = (static_cast<std::size_t>(y) * crop_w + x) * 4U;
            std::memcpy(dst.pixels.data() + di, src.pixels.data() + si, 4U);
        }
    }
    return dst;
}

// Produces the resampled image per the requested method. `scale` fits within
// the box preserving aspect ratio; `crop` fills the box then centre-crops.
[[nodiscard]] auto resample(Rgba const& src, std::uint32_t target_w, std::uint32_t target_h, ThumbnailMethod method)
    -> Rgba
{
    auto const sw = static_cast<double>(src.width);
    auto const sh = static_cast<double>(src.height);
    if (method == ThumbnailMethod::scale)
    {
        auto const ratio = std::min(static_cast<double>(target_w) / sw, static_cast<double>(target_h) / sh);
        auto const out_w = std::max<std::uint32_t>(1U, static_cast<std::uint32_t>(sw * ratio + 0.5));
        auto const out_h = std::max<std::uint32_t>(1U, static_cast<std::uint32_t>(sh * ratio + 0.5));
        return resample_bilinear(src, out_w, out_h);
    }
    auto const ratio = std::max(static_cast<double>(target_w) / sw, static_cast<double>(target_h) / sh);
    auto const fill_w = std::max<std::uint32_t>(target_w, static_cast<std::uint32_t>(sw * ratio + 0.5));
    auto const fill_h = std::max<std::uint32_t>(target_h, static_cast<std::uint32_t>(sh * ratio + 0.5));
    auto const filled = resample_bilinear(src, fill_w, fill_h);
    return crop_center(filled, target_w, target_h);
}

// --- PNG encode --------------------------------------------------------------

[[nodiscard]] auto encode_png(Rgba const& image, std::string& out) -> bool
{
    auto encoded = png_image{};
    encoded.version = PNG_IMAGE_VERSION;
    encoded.width = image.width;
    encoded.height = image.height;
    encoded.format = PNG_FORMAT_RGBA;
    auto size = png_alloc_size_t{0};
    // First call sizes the buffer; the second writes into it.
    if (png_image_write_to_memory(&encoded, nullptr, &size, 0, image.pixels.data(), 0, nullptr) == 0)
    {
        return false;
    }
    out.resize(static_cast<std::size_t>(size));
    if (png_image_write_to_memory(&encoded, out.data(), &size, 0, image.pixels.data(), 0, nullptr) == 0)
    {
        return false;
    }
    out.resize(static_cast<std::size_t>(size));
    return true;
}

[[nodiscard]] auto respond(ThumbnailWorkerStatus status, Rgba const& image, std::string png_bytes)
    -> ThumbnailWorkerResponse
{
    auto response = ThumbnailWorkerResponse{};
    response.status = status;
    if (status == ThumbnailWorkerStatus::ok)
    {
        response.width = image.width;
        response.height = image.height;
        response.png_bytes = std::move(png_bytes);
    }
    return response;
}

} // namespace

auto main() -> int
{
    harden();

    auto const input = read_all_stdin();
    auto const request = merovingian::media::parse_thumbnail_request(input);
    auto image = Rgba{};
    auto response = ThumbnailWorkerResponse{};

    if (!request.has_value())
    {
        response = respond(ThumbnailWorkerStatus::internal_error, image, {});
    }
    else
    {
        auto status = request->format == ThumbnailSourceFormat::png
                          ? decode_png(request->source_bytes, request->max_pixels, image)
                          : decode_jpeg(request->source_bytes, request->max_pixels, image);
        if (status != ThumbnailWorkerStatus::ok)
        {
            response = respond(status, image, {});
        }
        else
        {
            auto target_w = std::min(request->target_width, absolute_max_dimension);
            auto target_h = std::min(request->target_height, absolute_max_dimension);
            auto const resampled = resample(image, target_w, target_h, request->method);
            auto png_bytes = std::string{};
            if (!encode_png(resampled, png_bytes))
            {
                response = respond(ThumbnailWorkerStatus::internal_error, image, {});
            }
            else
            {
                response = respond(ThumbnailWorkerStatus::ok, resampled, std::move(png_bytes));
            }
        }
    }

    auto const frame_opt = merovingian::media::frame_thumbnail_response(response);
    // LCOV_EXCL_START — only reachable for >4 GiB PNG; impossible with any sane max_pixels limit
    if (!frame_opt.has_value())
    {
        return 1;
    }
    // LCOV_EXCL_STOP
    write_all_stdout(*frame_opt);
    return 0;
}
