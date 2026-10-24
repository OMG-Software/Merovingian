// SPDX-License-Identifier: GPL-3.0-or-later
//
// Integration coverage for the out-of-process image thumbnail worker. These
// scenarios spawn the real sandboxed worker binary and verify that an image is
// genuinely decoded, resampled, and re-encoded — not passed through unchanged.

#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/media/thumbnailer.hpp"
#include "support/temp_directory.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace
{

// An 8x8 RGBA PNG (red/blue checkerboard), generated offline. Embedded so the
// test does not depend on an encoder being available to the test process.
constexpr std::array<unsigned char, 81U> sample_png_8x8{
    137, 80,  78,  71,  13,  10, 26, 10,  0,   0,   0,   13,  73, 72,  68,  82,  0,  0,  0,  8,   0,
    0,   0,   8,   8,   6,   0,  0,  0,   196, 15,  190, 139, 0,  0,   0,   24,  73, 68, 65, 84,  120,
    156, 99,  248, 207, 192, 0,  66, 255, 113, 209, 12,  248, 36, 193, 244, 176, 48, 1,  0,  131, 23,
    127, 129, 6,   228, 109, 45, 0,  0,   0,   0,   73,  69,  78, 68,  174, 66,  96, 130};

[[nodiscard]] auto sample_png() -> std::string
{
    return std::string{reinterpret_cast<char const*>(sample_png_8x8.data()), sample_png_8x8.size()};
}

// An executable peer emits a chosen wire response using shell builtins only.
// The real parent fork/exec, pipe transport, and acceptance path are exercised.
class ResponseWorker final
{
public:
    explicit ResponseWorker(std::string_view frame, std::string_view checks = {})
        : path_{(merovingian::tests::temporary_directory() / "thumbnail-iso5-XXXXXX").string()}
        , descriptor_{::mkstemp(path_.data())}
    {
        REQUIRE(descriptor_.valid());
        REQUIRE(::fchmod(descriptor_.get(), S_IRUSR | S_IWUSR | S_IXUSR) == 0);
        auto script = std::string{"#!/bin/sh\nwhile IFS= read -r line; do :; done\n"};
        script.append(checks);
        script.append("printf '");
        for (auto const byte : frame)
        {
            auto const value = static_cast<unsigned char>(byte);
            script.push_back('\\');
            script.push_back(static_cast<char>('0' + ((value >> 6U) & 7U)));
            script.push_back(static_cast<char>('0' + ((value >> 3U) & 7U)));
            script.push_back(static_cast<char>('0' + (value & 7U)));
        }
        script.append("'\n");
        auto written = std::size_t{};
        while (written < script.size())
        {
            auto const count = ::write(descriptor_.get(), script.data() + written, script.size() - written);
            REQUIRE(count > 0);
            written += static_cast<std::size_t>(count);
        }
        descriptor_.reset();
    }

    ResponseWorker(ResponseWorker const&) = delete;
    auto operator=(ResponseWorker const&) -> ResponseWorker& = delete;

    ~ResponseWorker() noexcept
    {
        auto error = std::error_code{};
        std::ignore = std::filesystem::remove(path_, error);
    }

    [[nodiscard]] auto path() const -> std::string const&
    {
        return path_;
    }

private:
    std::string path_;
    merovingian::core::FileDescriptor descriptor_;
};

class ScopedEnvironmentVariable final
{
public:
    ScopedEnvironmentVariable(std::string name, std::string const& value)
        : name_{std::move(name)}
    {
        if (auto const* previous = ::getenv(name_.c_str()); previous != nullptr)
        {
            previous_ = previous;
        }
        REQUIRE(::setenv(name_.c_str(), value.c_str(), 1) == 0);
    }

    ScopedEnvironmentVariable(ScopedEnvironmentVariable const&) = delete;
    auto operator=(ScopedEnvironmentVariable const&) -> ScopedEnvironmentVariable& = delete;

    ~ScopedEnvironmentVariable() noexcept
    {
        if (previous_.has_value())
        {
            std::ignore = ::setenv(name_.c_str(), previous_->c_str(), 1);
        }
        else
        {
            std::ignore = ::unsetenv(name_.c_str());
        }
    }

private:
    std::string name_;
    std::optional<std::string> previous_;
};

class ScopedStderrRedirect final
{
public:
    explicit ScopedStderrRedirect(merovingian::core::FileDescriptor const& destination)
        : original_{::fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3)}
    {
        REQUIRE(original_.valid());
        REQUIRE(::dup2(destination.get(), STDERR_FILENO) == STDERR_FILENO);
    }

    ScopedStderrRedirect(ScopedStderrRedirect const&) = delete;
    auto operator=(ScopedStderrRedirect const&) -> ScopedStderrRedirect& = delete;

    ~ScopedStderrRedirect() noexcept
    {
        std::ignore = ::dup2(original_.get(), STDERR_FILENO);
    }

private:
    merovingian::core::FileDescriptor original_;
};

[[nodiscard]] auto request_from_worker(merovingian::media::ThumbnailWorkerResponse const& response,
                                       std::string_view checks = {}) -> merovingian::media::ThumbnailResult
{
    auto const frame = merovingian::media::frame_thumbnail_response(response);
    REQUIRE(frame.has_value());
    auto const worker = ResponseWorker{*frame, checks};
    auto config = merovingian::media::ThumbnailerConfig{};
    config.worker_path = worker.path();
    config.timeout_seconds = 5U;
    auto request = merovingian::media::ThumbnailRequest{};
    request.source_bytes = sample_png();
    request.source_content_type = "image/png";
    request.width = 4U;
    request.height = 4U;
    return merovingian::media::generate_thumbnail(config, request);
}

// Reads the width/height from a PNG's IHDR chunk (bytes 16..23, big-endian).
// [[maybe_unused]]: only referenced by the worker scenarios, which are compiled
// out when the image codecs (and thus the worker) are unavailable.
[[maybe_unused]] [[nodiscard]] auto png_dimensions(std::string const& png) -> std::pair<std::uint32_t, std::uint32_t>
{
    auto read_be = [&png](std::size_t offset) {
        return (static_cast<std::uint32_t>(static_cast<unsigned char>(png[offset])) << 24) |
               (static_cast<std::uint32_t>(static_cast<unsigned char>(png[offset + 1U])) << 16) |
               (static_cast<std::uint32_t>(static_cast<unsigned char>(png[offset + 2U])) << 8) |
               static_cast<std::uint32_t>(static_cast<unsigned char>(png[offset + 3U]));
    };
    return {read_be(16U), read_be(20U)};
}

[[maybe_unused]] [[nodiscard]] auto is_png(std::string const& bytes) -> bool
{
    return bytes.size() > 8U && static_cast<unsigned char>(bytes[0]) == 137U && bytes[1] == 'P' && bytes[2] == 'N' &&
           bytes[3] == 'G';
}

} // namespace

#ifdef MEROVINGIAN_TEST_THUMBNAIL_WORKER

// This scenario is also the platform-sandbox guard for the 0.12.5 audit,
// finding 9. harden() runs before the worker reads a byte of input, and it now
// enters seccomp-bpf on Linux, pledge("stdio") on OpenBSD and Capsicum
// capability mode on FreeBSD. A sandbox drawn too tight kills the worker
// mid-decode, which surfaces here as a failed round-trip -- so on each Tier 1
// platform's CI job this test is what proves that platform's sandbox admits
// exactly the work the worker still has to do. It cannot be asserted from the
// parent process any other way: the restrictions apply to the child, and a
// correctly sandboxed child is indistinguishable from an unsandboxed one except
// by what it can still accomplish.
SCENARIO("the sandboxed worker resamples a PNG to the requested size", "[media][thumbnail][integration]")
{
    GIVEN("an 8x8 PNG and the built thumbnail worker")
    {
        auto config = merovingian::media::ThumbnailerConfig{};
        config.worker_path = MEROVINGIAN_TEST_THUMBNAIL_WORKER;
        config.timeout_seconds = 60U;

        WHEN("a 4x4 scale thumbnail is requested")
        {
            auto request = merovingian::media::ThumbnailRequest{};
            request.source_bytes = sample_png();
            request.source_content_type = "image/png";
            request.width = 4U;
            request.height = 4U;
            request.method = merovingian::media::ThumbnailMethod::scale;
            auto const result = merovingian::media::generate_thumbnail(config, request);
            // Surface how the worker fared so a CI failure shows the worker's
            // exit/signal status (the reason suffix) instead of a bare 504.
            INFO("status=" << result.status << " reason=" << result.reason);

            THEN("a real, smaller PNG of the requested dimensions is produced")
            {
                REQUIRE(result.ok);
                REQUIRE(result.status == 200U);
                REQUIRE(result.content_type == "image/png");
                REQUIRE(is_png(result.bytes));
                // The output must differ from the original bytes — proving a
                // genuine decode/resample/encode, not a pass-through.
                REQUIRE(result.bytes != sample_png());
                auto const [w, h] = png_dimensions(result.bytes);
                REQUIRE(w == 4U);
                REQUIRE(h == 4U);
                REQUIRE(result.width == 4U);
                REQUIRE(result.height == 4U);
            }
        }

        WHEN("a 4x4 crop thumbnail is requested")
        {
            auto request = merovingian::media::ThumbnailRequest{};
            request.source_bytes = sample_png();
            request.source_content_type = "image/png";
            request.width = 4U;
            request.height = 4U;
            request.method = merovingian::media::ThumbnailMethod::crop;
            auto const result = merovingian::media::generate_thumbnail(config, request);
            INFO("status=" << result.status << " reason=" << result.reason);

            THEN("the crop result fills the requested box exactly")
            {
                REQUIRE(result.ok);
                auto const [w, h] = png_dimensions(result.bytes);
                REQUIRE(w == 4U);
                REQUIRE(h == 4U);
            }
        }

        WHEN("an unsupported content type is requested")
        {
            auto request = merovingian::media::ThumbnailRequest{};
            request.source_bytes = sample_png();
            request.source_content_type = "image/gif";
            request.width = 4U;
            request.height = 4U;
            auto const result = merovingian::media::generate_thumbnail(config, request);

            THEN("the worker is never spawned and an unsupported status is returned")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 415U);
            }
        }

        WHEN("garbage is supplied as PNG bytes")
        {
            auto request = merovingian::media::ThumbnailRequest{};
            request.source_bytes = "this is not a png";
            request.source_content_type = "image/png";
            request.width = 4U;
            request.height = 4U;
            auto const result = merovingian::media::generate_thumbnail(config, request);
            INFO("status=" << result.status << " reason=" << result.reason);

            THEN("the worker reports a decode failure rather than crashing the host")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 400U);
            }
        }
    }
}

// 0.12.45: the server logs the thumbnail worker's libraries at startup. libpng and libjpeg-turbo are
// linked only into the worker, so the server asks it, over the same sandboxed spawn as a thumbnail;
// the worker answers only after its hardening is in place, so this also proves the sandbox admits it.
SCENARIO("the sandboxed worker reports the image libraries it runs",
         "[media][thumbnail][integration][library-versions]")
{
    GIVEN("the built thumbnail worker")
    {
        auto config = merovingian::media::ThumbnailerConfig{};
        config.worker_path = MEROVINGIAN_TEST_THUMBNAIL_WORKER;
        config.timeout_seconds = 60U;

        WHEN("the server asks it for its library report")
        {
            auto const report = merovingian::media::query_thumbnail_worker_libraries(config);
            INFO(report.error.message());

            THEN("it names libpng and libjpeg-turbo, how each is linked, and what each was built against")
            {
                REQUIRE(report.libraries.has_value());
                auto names = std::vector<std::string>{};
                for (auto const& library : *report.libraries)
                {
                    CAPTURE(library.name, library.runtime_version, library.build_version, library.shared_object);
                    names.push_back(library.name);
                    REQUIRE_FALSE(library.build_version.empty());
                    REQUIRE(library.shared_object.empty() ==
                            (library.linkage == merovingian::core::Linkage::static_linked));
                }
                REQUIRE(names == std::vector<std::string>{"libpng", "libjpeg-turbo"});
                // libpng has a runtime version call; libjpeg-turbo's TurboJPEG API has none.
                REQUIRE_FALSE(report.libraries->front().runtime_version.empty());
            }
        }
    }
}

#endif // MEROVINGIAN_TEST_THUMBNAIL_WORKER

SCENARIO("a thumbnail worker that cannot run reports no libraries", "[media][thumbnail][integration][library-versions]")
{
    GIVEN("a thumbnailer whose worker is not configured, and one whose worker cannot be executed")
    {
        auto const unconfigured = merovingian::media::ThumbnailerConfig{};
        auto missing = merovingian::media::ThumbnailerConfig{};
        missing.worker_path = "/nonexistent/merovingian-thumbnail-worker";
        missing.timeout_seconds = 5U;

        WHEN("each is asked for its library report")
        {
            auto const not_configured = merovingian::media::query_thumbnail_worker_libraries(unconfigured);
            auto const not_run = merovingian::media::query_thumbnail_worker_libraries(missing);

            THEN("each fails with a reason instead of an empty report")
            {
                REQUIRE_FALSE(not_configured.libraries.has_value());
                REQUIRE(not_configured.error.message() == "thumbnail worker not configured");
                REQUIRE_FALSE(not_run.libraries.has_value());
                // A worker that never ran is not a malformed report: the reason says it did not
                // answer and names the path, which is what an operator checks.
                INFO(not_run.error.message());
                REQUIRE(not_run.error.message().starts_with(
                    "thumbnail worker /nonexistent/merovingian-thumbnail-worker did not answer"));
            }
        }
    }
}

SCENARIO("a failed worker surfaces how it died in the result reason", "[media][thumbnail][integration][diagnostics]")
{
    GIVEN("a thumbnailer configured with a worker path that cannot be executed")
    {
        auto config = merovingian::media::ThumbnailerConfig{};
        // No such file: execv fails in the child, which then _exit(127)s. This
        // exercises the failure path without depending on the image codecs.
        config.worker_path = "/nonexistent/merovingian-thumbnail-worker";
        config.timeout_seconds = 5U;

        WHEN("a thumbnail is requested")
        {
            auto request = merovingian::media::ThumbnailRequest{};
            request.source_bytes = sample_png();
            request.source_content_type = "image/png";
            request.width = 4U;
            request.height = 4U;
            request.method = merovingian::media::ThumbnailMethod::scale;
            auto const result = merovingian::media::generate_thumbnail(config, request);

            THEN("the request fails and the reason reports the worker's exit status")
            {
                REQUIRE_FALSE(result.ok);
                // The reason must describe the worker outcome (exit code/signal),
                // not just a bare timeout, so CI logs pinpoint the cause.
                REQUIRE(result.reason.find("worker") != std::string::npos);
                REQUIRE((result.reason.find("exited with code") != std::string::npos ||
                         result.reason.find("killed by signal") != std::string::npos ||
                         result.reason.find("still running") != std::string::npos));
            }
        }
    }
}

SCENARIO("the parent rejects successful decoder replies with invalid PNG headers",
         "[media][thumbnail][integration][security][iso-5][iso-5-png]")
{
    GIVEN("a decoder that can report success for arbitrary output bytes and dimensions")
    {
        struct ReplyCase final
        {
            std::string name;
            merovingian::media::ThumbnailWorkerResponse response;
        };
        auto const valid = merovingian::media::ThumbnailWorkerResponse{merovingian::media::ThumbnailWorkerStatus::ok,
                                                                       8U, 8U, sample_png()};
        auto cases = std::vector<ReplyCase>{};
        cases.push_back({
            "not a PNG", {merovingian::media::ThumbnailWorkerStatus::ok, 8U, 8U, "not a PNG"}
        });
        for (auto length = std::size_t{}; length < 33U; ++length)
        {
            auto response = valid;
            response.png_bytes.resize(length);
            cases.push_back({"truncated IHDR at " + std::to_string(length), std::move(response)});
        }
        for (auto offset = std::size_t{}; offset < 8U; ++offset)
        {
            auto response = valid;
            response.png_bytes[offset] ^= 1;
            cases.push_back({"signature byte " + std::to_string(offset), std::move(response)});
        }
        for (auto const length : {0U, 12U, 14U})
        {
            auto response = valid;
            response.png_bytes[11U] = static_cast<char>(length);
            cases.push_back({"wrong IHDR chunk length " + std::to_string(length), std::move(response)});
        }
        auto response = valid;
        response.png_bytes[12U] = 'X';
        cases.push_back({"not an initial IHDR chunk", std::move(response)});
        response = valid;
        response.width = 7U;
        cases.push_back({"reported width mismatch", std::move(response)});
        response = valid;
        response.height = 7U;
        cases.push_back({"reported height mismatch", std::move(response)});
        for (auto const offset : {16U, 20U})
        {
            response = valid;
            response.png_bytes.replace(offset, 4U, 4U, '\0');
            if (offset == 16U)
            {
                response.width = 0U;
            }
            else
            {
                response.height = 0U;
            }
            cases.push_back({"zero dimension at " + std::to_string(offset), std::move(response)});
            response = valid;
            response.png_bytes[offset] = '\x80';
            if (offset == 16U)
            {
                response.width = 0x80000008U;
            }
            else
            {
                response.height = 0x80000008U;
            }
            cases.push_back({"invalid PNG dimension at " + std::to_string(offset), std::move(response)});
        }

        WHEN("each framed successful reply arrives through the real subprocess pipes")
        {
            auto results = std::vector<merovingian::media::ThumbnailResult>{};
            for (auto const& item : cases)
            {
                results.push_back(request_from_worker(item.response));
            }

            THEN("every invalid header returns 502 without releasing bytes or dimensions")
            {
                REQUIRE(results.size() == cases.size());
                for (auto index = std::size_t{}; index < results.size(); ++index)
                {
                    INFO(cases[index].name);
                    auto const& result = results[index];
                    CHECK_FALSE(result.ok);
                    CHECK(result.status == 502U);
                    CHECK(result.bytes.empty());
                    CHECK(result.content_type.empty());
                    CHECK(result.width == 0U);
                    CHECK(result.height == 0U);
                }
            }
        }
    }
}

SCENARIO("the parent accepts a PNG matching the decoder's reported dimensions",
         "[media][thumbnail][integration][security][iso-5][iso-5-png]")
{
    GIVEN("a complete PNG whose IHDR agrees with the response frame")
    {
        auto const response = merovingian::media::ThumbnailWorkerResponse{merovingian::media::ThumbnailWorkerStatus::ok,
                                                                          8U, 8U, sample_png()};

        WHEN("the decoder returns it for a differently sized request")
        {
            // Validate the worker's report, not exact equality to requested geometry:
            // Matrix v1.19 thumbnails can differ from the requested dimensions.
            auto const result = request_from_worker(response);

            THEN("the parent preserves the PNG and its dimensions")
            {
                REQUIRE(result.ok);
                REQUIRE(result.status == 200U);
                REQUIRE(result.content_type == "image/png");
                REQUIRE(result.bytes == response.png_bytes);
                REQUIRE(result.width == 8U);
                REQUIRE(result.height == 8U);
            }
        }
    }
}

SCENARIO("the decoder starts with only a fixed minimal environment",
         "[media][thumbnail][integration][security][iso-5][iso-5-env]")
{
    GIVEN("parent-only environment entries and an untrusted parent search path")
    {
        auto const marker = ScopedEnvironmentVariable{"MEROVINGIAN_ISO5_PROBE", "present"};
        auto const path = ScopedEnvironmentVariable{"PATH", "/iso5-untrusted-path"};
        auto const preload = ScopedEnvironmentVariable{"LD_PRELOAD", ""};
        auto const response = merovingian::media::ThumbnailWorkerResponse{merovingian::media::ThumbnailWorkerStatus::ok,
                                                                          8U, 8U, sample_png()};

        WHEN("the executed peer refuses inherited entries or a non-minimal path")
        {
            auto const result = request_from_worker(
                response, "if [ \"${MEROVINGIAN_ISO5_PROBE+x}\" = x ] || [ \"${LD_LIBRARY_PATH+x}\" = x ] || "
                          "[ \"${LD_PRELOAD+x}\" = x ] || [ \"$PATH\" != \"/usr/bin:/bin\" ]; then exit 41; fi\n");

            THEN("the absolute executable runs successfully without the parent's environment")
            {
                REQUIRE(result.ok);
                REQUIRE(result.status == 200U);
                REQUIRE(result.bytes == response.png_bytes);
            }
        }
    }
}

SCENARIO("decoder stderr is a writable null sink rather than the parent's diagnostic stream",
         "[media][thumbnail][integration][security][iso-5][iso-5-stderr]")
{
    GIVEN("a parent diagnostic stream captured in a private temporary file")
    {
        auto path = (merovingian::tests::temporary_directory() / "thumbnail-stderr-XXXXXX").string();
        auto capture = merovingian::core::FileDescriptor{::mkstemp(path.data())};
        REQUIRE(capture.valid());
        REQUIRE(::unlink(path.c_str()) == 0);
        REQUIRE(capture.set_cloexec());
        auto const response = merovingian::media::ThumbnailWorkerResponse{merovingian::media::ThumbnailWorkerStatus::ok,
                                                                          8U, 8U, sample_png()};

        WHEN("the executed decoder writes a diagnostic and checks its stderr device")
        {
            auto result = merovingian::media::ThumbnailResult{};
            {
                auto const redirect = ScopedStderrRedirect{capture};
                // The write failing would mean stderr is closed; nothing reaching
                // the capture means it is not the parent's stream. On Linux,
                // /proc/self/fd/2 also names the open file, so its identity with
                // /dev/null is checked too. Elsewhere /dev/fd/2 may be a static
                // device node (NetBSD without fdescfs), which -ef cannot compare.
                result = request_from_worker(response, "printf 'iso5-stderr-probe' >&2 || exit 42\n"
#if defined(__linux__)
                                                       "if ! [ /proc/self/fd/2 -ef /dev/null ]; then exit 42; fi\n"
#endif
                );
            }
            REQUIRE(::lseek(capture.get(), 0, SEEK_SET) == 0);
            auto buffer = std::array<char, 64U>{};
            auto const diagnostic_bytes = ::read(capture.get(), buffer.data(), buffer.size());

            THEN("the worker succeeds but no diagnostic bytes reach the parent's stderr")
            {
                CHECK(result.ok);
                CHECK(result.status == 200U);
                CHECK(diagnostic_bytes == 0);
            }
        }
    }
}

SCENARIO("thumbnail generation degrades safely when no worker is configured", "[media][thumbnail][integration]")
{
    GIVEN("a thumbnailer config with an empty worker path")
    {
        auto config = merovingian::media::ThumbnailerConfig{};

        WHEN("a thumbnail is requested")
        {
            auto request = merovingian::media::ThumbnailRequest{};
            request.source_bytes = sample_png();
            request.source_content_type = "image/png";
            request.width = 4U;
            request.height = 4U;
            auto const result = merovingian::media::generate_thumbnail(config, request);

            THEN("it reports the worker is unavailable instead of failing hard")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 503U);
            }
        }
    }
}

#ifdef MEROVINGIAN_TEST_THUMBNAIL_WORKER

namespace
{

// Complete RGBA PNGs generated offline with Python stdlib zlib, struct, and CRC.
// Each IDAT contains all scanlines for the stated geometry; no codec is linked
// into the test process. Successful real-worker scale controls verify decoding.
constexpr std::array<unsigned char, 99U> sample_png_4096x1{
    137, 80,  78,  71,  13,  10,  26,  10,  0,   0,   0,   13,  73,  72,  68,  82,  0,   0,   16, 0,
    0,   0,   0,   1,   8,   6,   0,   0,   0,   94,  33,  107, 124, 0,   0,   0,   42,  73,  68, 65,
    84,  120, 218, 237, 195, 65,  13,  0,   0,   12,  3,   161, 243, 111, 186, 147, 177, 15,  36, 180,
    154, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 250, 251, 0,  248,
    102, 225, 210, 12,  185, 221, 33,  0,   0,   0,   0,   73,  69,  78,  68,  174, 66,  96,  130};

constexpr std::array<unsigned char, 113U> sample_png_1x4096{
    137, 80, 78,  71,  13,  10,  26,  10,  0,   0,   0,   13, 73,  72,  68,  82,  0,  0,   0,   1,   0,   0,   16,
    0,   8,  6,   0,   0,   0,   179, 151, 139, 226, 0,   0,  0,   56,  73,  68,  65, 84,  120, 218, 237, 196, 49,
    1,   0,  0,   12,  195, 160, 248, 55,  221, 169, 216, 7,  7,   173, 150, 36,  73, 146, 36,  73,  146, 36,  73,
    146, 36, 73,  146, 36,  73,  146, 36,  73,  146, 36,  73, 146, 36,  73,  146, 36, 73,  146, 36,  73,  250, 236,
    0,   9,  101, 225, 210, 55,  105, 124, 102, 0,   0,   0,  0,   73,  69,  78,  68, 174, 66,  96,  130};

struct ThinPngCase final
{
    std::string source_bytes;
    std::uint32_t source_width;
    std::uint32_t source_height;
    std::uint32_t target_width;
    std::uint32_t target_height;
};

[[nodiscard]] auto thin_png_cases(std::uint32_t target_long_dimension) -> std::array<ThinPngCase, 2U>
{
    return {
        ThinPngCase{std::string{sample_png_4096x1.begin(), sample_png_4096x1.end()}, 4096U, 1U,    1U,
                    target_long_dimension},
        ThinPngCase{std::string{sample_png_1x4096.begin(), sample_png_1x4096.end()}, 1U,    4096U, target_long_dimension,
                    1U                   }
    };
}

} // namespace

SCENARIO("the real thumbnail worker applies the request pixel budget to crop fill",
         "[integration][media][thumbnail][med-8][med-8-budget]")
{
    GIVEN("valid thin PNGs containing exactly the configured 4096 source pixels")
    {
        auto config = merovingian::media::ThumbnailerConfig{};
        config.worker_path = MEROVINGIAN_TEST_THUMBNAIL_WORKER;
        config.timeout_seconds = 60U;
        config.max_pixels = 4096U;

        WHEN("scale and crop requests use the same admitted source and target geometry")
        {
            THEN("ordinary crop succeeds but both 16384-pixel crop fills return a framed size rejection")
            {
                auto ordinary_request = merovingian::media::ThumbnailRequest{};
                ordinary_request.source_bytes = sample_png();
                ordinary_request.source_content_type = "image/png";
                ordinary_request.width = 4U;
                ordinary_request.height = 4U;
                ordinary_request.method = merovingian::media::ThumbnailMethod::crop;
                auto const ordinary = merovingian::media::generate_thumbnail(config, ordinary_request);
                INFO("ordinary crop status=" << ordinary.status << " reason=" << ordinary.reason);
                REQUIRE(ordinary.ok);
                REQUIRE(ordinary.status == 200U);
                REQUIRE(ordinary.content_type == "image/png");
                REQUIRE(is_png(ordinary.bytes));
                REQUIRE(ordinary.bytes.size() >= 24U);
                auto const [ordinary_width, ordinary_height] = png_dimensions(ordinary.bytes);
                REQUIRE(ordinary_width == 4U);
                REQUIRE(ordinary_height == 4U);
                REQUIRE(ordinary.width == 4U);
                REQUIRE(ordinary.height == 4U);

                for (auto const& item : thin_png_cases(2U))
                {
                    INFO("source=" << item.source_width << 'x' << item.source_height << " target=" << item.target_width
                                   << 'x' << item.target_height);
                    REQUIRE(is_png(item.source_bytes));
                    REQUIRE(item.source_bytes.size() >= 24U);
                    auto const [source_width, source_height] = png_dimensions(item.source_bytes);
                    REQUIRE(source_width == item.source_width);
                    REQUIRE(source_height == item.source_height);
                    REQUIRE(static_cast<std::uint64_t>(source_width) * source_height == config.max_pixels);

                    auto request = merovingian::media::ThumbnailRequest{};
                    request.source_bytes = item.source_bytes;
                    request.source_content_type = "image/png";
                    request.width = item.target_width;
                    request.height = item.target_height;
                    request.method = merovingian::media::ThumbnailMethod::scale;
                    auto const scale = merovingian::media::generate_thumbnail(config, request);
                    INFO("scale status=" << scale.status << " reason=" << scale.reason);
                    REQUIRE(scale.ok);
                    REQUIRE(scale.status == 200U);
                    REQUIRE(scale.content_type == "image/png");
                    REQUIRE(is_png(scale.bytes));
                    REQUIRE(scale.bytes.size() >= 24U);
                    auto const [scale_width, scale_height] = png_dimensions(scale.bytes);
                    REQUIRE(scale_width == 1U);
                    REQUIRE(scale_height == 1U);
                    REQUIRE(scale.width == 1U);
                    REQUIRE(scale.height == 1U);

                    // The old fill is 8192x2 (or 2x8192): only 64 KiB,
                    // safely exposing admission above this request's budget.
                    request.method = merovingian::media::ThumbnailMethod::crop;
                    auto const crop = merovingian::media::generate_thumbnail(config, request);
                    INFO("crop status=" << crop.status << " reason=" << crop.reason);
                    CHECK_FALSE(crop.ok);
                    CHECK(crop.status == 413U);
                    CHECK(crop.bytes.empty());
                    CHECK(crop.content_type.empty());
                    CHECK(crop.width == 0U);
                    CHECK(crop.height == 0U);
                }
            }
        }
    }
}

SCENARIO("the real thumbnail worker keeps its existing hard ceiling for crop fill",
         "[integration][media][thumbnail][med-8][med-8-budget]")
{
    GIVEN("valid thin PNGs and zero, ceiling-sized, or UINT32_MAX request budgets")
    {
        auto config = merovingian::media::ThumbnailerConfig{};
        config.worker_path = MEROVINGIAN_TEST_THUMBNAIL_WORKER;
        config.timeout_seconds = 60U;

        WHEN("both orientations request a 32-pixel-long target box")
        {
            THEN("scale succeeds but all six 4194304-pixel crop fills exceed the existing ceiling")
            {
                for (auto const max_pixels : std::array<std::uint32_t, 3U>{0U, 4096000U, 4294967295U})
                {
                    config.max_pixels = max_pixels;
                    for (auto const& item : thin_png_cases(32U))
                    {
                        INFO("max_pixels=" << max_pixels << " source=" << item.source_width << 'x' << item.source_height
                                           << " target=" << item.target_width << 'x' << item.target_height);
                        REQUIRE(is_png(item.source_bytes));
                        REQUIRE(item.source_bytes.size() >= 24U);
                        auto const [source_width, source_height] = png_dimensions(item.source_bytes);
                        REQUIRE(source_width == item.source_width);
                        REQUIRE(source_height == item.source_height);

                        auto request = merovingian::media::ThumbnailRequest{};
                        request.source_bytes = item.source_bytes;
                        request.source_content_type = "image/png";
                        request.width = item.target_width;
                        request.height = item.target_height;
                        request.method = merovingian::media::ThumbnailMethod::scale;
                        auto const scale = merovingian::media::generate_thumbnail(config, request);
                        INFO("scale status=" << scale.status << " reason=" << scale.reason);
                        REQUIRE(scale.ok);
                        REQUIRE(scale.status == 200U);
                        REQUIRE(scale.content_type == "image/png");
                        REQUIRE(is_png(scale.bytes));
                        REQUIRE(scale.bytes.size() >= 24U);
                        auto const [scale_width, scale_height] = png_dimensions(scale.bytes);
                        REQUIRE(scale_width == 1U);
                        REQUIRE(scale_height == 1U);
                        REQUIRE(scale.width == 1U);
                        REQUIRE(scale.height == 1U);

                        // The old fill is 131072x32 (or 32x131072): 16 MiB,
                        // above the existing 4096000-pixel hard ceiling.
                        request.method = merovingian::media::ThumbnailMethod::crop;
                        auto const crop = merovingian::media::generate_thumbnail(config, request);
                        INFO("crop status=" << crop.status << " reason=" << crop.reason);
                        CHECK_FALSE(crop.ok);
                        CHECK(crop.status == 413U);
                        CHECK(crop.bytes.empty());
                        CHECK(crop.content_type.empty());
                        CHECK(crop.width == 0U);
                        CHECK(crop.height == 0U);
                    }
                }
            }
        }
    }
}

// First-GREEN audit coverage only: do not run before the crop-fill repair.
// The original path attempts a 64 GiB RGBA fill, and ASan skips the memory cap.
// These admission regressions do not cover every worker exception branch.
SCENARIO("the real thumbnail worker rejects the original MED-8 crop magnitude",
         "[integration][media][thumbnail][med-8][med-8-audit]")
{
    GIVEN("valid thin PNGs and the default pixel budget")
    {
        auto config = merovingian::media::ThumbnailerConfig{};
        config.worker_path = MEROVINGIAN_TEST_THUMBNAIL_WORKER;
        config.timeout_seconds = 60U;

        WHEN("both orientations request a 2048-pixel-long target box")
        {
            THEN("scale succeeds but the audit-sized crop fills return framed size rejections")
            {
                for (auto const& item : thin_png_cases(2048U))
                {
                    INFO("source=" << item.source_width << 'x' << item.source_height << " target=" << item.target_width
                                   << 'x' << item.target_height);
                    REQUIRE(is_png(item.source_bytes));
                    REQUIRE(item.source_bytes.size() >= 24U);
                    auto const [source_width, source_height] = png_dimensions(item.source_bytes);
                    REQUIRE(source_width == item.source_width);
                    REQUIRE(source_height == item.source_height);

                    auto request = merovingian::media::ThumbnailRequest{};
                    request.source_bytes = item.source_bytes;
                    request.source_content_type = "image/png";
                    request.width = item.target_width;
                    request.height = item.target_height;
                    request.method = merovingian::media::ThumbnailMethod::scale;
                    auto const scale = merovingian::media::generate_thumbnail(config, request);
                    INFO("scale status=" << scale.status << " reason=" << scale.reason);
                    REQUIRE(scale.ok);
                    REQUIRE(scale.status == 200U);
                    REQUIRE(scale.content_type == "image/png");
                    REQUIRE(is_png(scale.bytes));
                    REQUIRE(scale.bytes.size() >= 24U);
                    auto const [scale_width, scale_height] = png_dimensions(scale.bytes);
                    REQUIRE(scale_width == 1U);
                    REQUIRE(scale_height == 1U);
                    REQUIRE(scale.width == 1U);
                    REQUIRE(scale.height == 1U);

                    request.method = merovingian::media::ThumbnailMethod::crop;
                    auto const crop = merovingian::media::generate_thumbnail(config, request);
                    INFO("crop status=" << crop.status << " reason=" << crop.reason);
                    CHECK_FALSE(crop.ok);
                    CHECK(crop.status == 413U);
                    CHECK(crop.bytes.empty());
                    CHECK(crop.content_type.empty());
                    CHECK(crop.width == 0U);
                    CHECK(crop.height == 0U);
                }
            }
        }
    }
}

#endif // MEROVINGIAN_TEST_THUMBNAIL_WORKER
