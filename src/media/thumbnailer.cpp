// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/thumbnailer.hpp"

#include "merovingian/core/file_descriptor.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
#include <sys/wait.h>
#include <unistd.h>

namespace merovingian::media
{
namespace
{

    constexpr std::string_view request_magic{"MTH1"};
    constexpr std::string_view response_magic{"MTR1"};

    auto append_u32(std::string& out, std::uint32_t value) -> void
    {
        out.push_back(static_cast<char>((value >> 24) & 0xFFU));
        out.push_back(static_cast<char>((value >> 16) & 0xFFU));
        out.push_back(static_cast<char>((value >> 8) & 0xFFU));
        out.push_back(static_cast<char>(value & 0xFFU));
    }

    [[nodiscard]] auto read_u32(std::string_view frame, std::size_t offset) -> std::uint32_t
    {
        return (static_cast<std::uint32_t>(static_cast<unsigned char>(frame[offset])) << 24) |
               (static_cast<std::uint32_t>(static_cast<unsigned char>(frame[offset + 1U])) << 16) |
               (static_cast<std::uint32_t>(static_cast<unsigned char>(frame[offset + 2U])) << 8) |
               static_cast<std::uint32_t>(static_cast<unsigned char>(frame[offset + 3U]));
    }

    [[nodiscard]] auto monotonic_ms() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    // Writes `payload` to `fd` honouring `deadline_ms`, never blocking longer
    // than the remaining budget. Returns false on error or timeout.
    [[nodiscard]] auto write_all_deadline(int fd, std::string_view payload, std::int64_t deadline_ms) -> bool
    {
        std::size_t written = 0U;
        while (written < payload.size())
        {
            auto const remaining = deadline_ms - monotonic_ms();
            if (remaining <= 0)
            {
                return false;
            }
            auto pfd = pollfd{fd, POLLOUT, 0};
            auto const ready = ::poll(&pfd, 1U, static_cast<int>(remaining));
            if (ready <= 0 || (pfd.revents & (POLLERR | POLLNVAL)) != 0)
            {
                return false;
            }
            auto const n = ::write(fd, payload.data() + written, payload.size() - written);
            if (n < 0)
            {
                if (errno == EINTR || errno == EAGAIN)
                {
                    continue;
                }
                return false;
            }
            written += static_cast<std::size_t>(n);
        }
        return true;
    }

    // Reads `fd` to EOF honouring `deadline_ms` and `max_bytes`. Returns the
    // bytes read; sets `ok` false on error, timeout, or overflow.
    [[nodiscard]] auto read_all_deadline(int fd, std::int64_t deadline_ms, std::size_t max_bytes, bool& ok)
        -> std::string
    {
        ok = false;
        auto output = std::string{};
        auto buffer = std::array<char, 65536U>{};
        while (true)
        {
            auto const remaining = deadline_ms - monotonic_ms();
            if (remaining <= 0)
            {
                return output;
            }
            auto pfd = pollfd{fd, POLLIN, 0};
            auto const ready = ::poll(&pfd, 1U, static_cast<int>(remaining));
            if (ready < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                return output;
            }
            if (ready == 0)
            {
                return output; // timed out
            }
            auto const n = ::read(fd, buffer.data(), buffer.size());
            if (n < 0)
            {
                if (errno == EINTR || errno == EAGAIN)
                {
                    continue;
                }
                return output;
            }
            if (n == 0)
            {
                ok = true; // clean EOF
                return output;
            }
            if (max_bytes != 0U && output.size() + static_cast<std::size_t>(n) > max_bytes)
            {
                return output; // worker produced more than allowed
            }
            output.append(buffer.data(), static_cast<std::size_t>(n));
        }
    }

    // Renders a reaped worker's wait(2) status into a short, human-readable
    // suffix so a failed thumbnail surfaces *how* the worker died (signalled,
    // exited non-zero, or still running at the deadline) rather than a generic
    // timeout. Diagnostics only — the status never changes the HTTP result.
    [[nodiscard]] auto describe_worker_status(bool reaped, int status) -> std::string
    {
        if (!reaped)
        {
            return " (worker still running at deadline)";
        }
        if (WIFSIGNALED(status))
        {
            return " (worker killed by signal " + std::to_string(WTERMSIG(status)) + ")";
        }
        if (WIFEXITED(status))
        {
            return " (worker exited with code " + std::to_string(WEXITSTATUS(status)) + ")";
        }
        return " (worker ended abnormally)";
    }

    auto set_nonblocking(int fd) -> void
    {
        auto const flags = ::fcntl(fd, F_GETFL, 0);
        if (flags >= 0)
        {
            std::ignore = ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
    }

    // Create a pipe whose ends carry FD_CLOEXEC. On Linux and FreeBSD pipe2() is
    // atomic; elsewhere we fall back to pipe() + fcntl(F_SETFD). Returns false on
    // error and leaves both ends set to -1.
    [[nodiscard]] auto create_cloexec_pipe(std::array<int, 2>& fds) noexcept -> bool
    {
        fds = {-1, -1};
#if defined(__linux__) || defined(__FreeBSD__)
        if (::pipe2(fds.data(), O_CLOEXEC) == 0)
        {
            return true;
        }
        // Fall back on kernels/libc that lack pipe2 even on these platforms.
#endif
        if (::pipe(fds.data()) != 0)
        {
            return false;
        }
        auto read_ok = core::FileDescriptor{fds[0]}.set_cloexec();
        auto write_ok = core::FileDescriptor{fds[1]}.set_cloexec();
        if (!read_ok || !write_ok)
        {
            ::close(fds[0]);
            ::close(fds[1]);
            fds = {-1, -1};
            return false;
        }
        return true;
    }

} // namespace

auto map_content_type_to_source_format(std::string_view content_type) -> std::optional<ThumbnailSourceFormat>
{
    if (content_type == "image/png")
    {
        return ThumbnailSourceFormat::png;
    }
    if (content_type == "image/jpeg")
    {
        return ThumbnailSourceFormat::jpeg;
    }
    return std::nullopt;
}

auto frame_thumbnail_request(ThumbnailWorkerRequest const& request) -> std::optional<std::string>
{
    // LCOV_EXCL_START — requires a >4 GiB source_bytes; max_upload_bytes enforces this upstream
    if (request.source_bytes.size() > std::numeric_limits<std::uint32_t>::max())
    {
        return std::nullopt;
    }
    // LCOV_EXCL_STOP
    auto frame = std::string{request_magic};
    frame.push_back(static_cast<char>(request.format));
    frame.push_back(static_cast<char>(request.method));
    append_u32(frame, request.target_width);
    append_u32(frame, request.target_height);
    append_u32(frame, request.max_pixels);
    append_u32(frame, static_cast<std::uint32_t>(request.source_bytes.size()));
    frame.append(request.source_bytes);
    return frame;
}

auto parse_thumbnail_request(std::string_view frame) -> std::optional<ThumbnailWorkerRequest>
{
    constexpr std::size_t header_size = 4U + 1U + 1U + 4U + 4U + 4U + 4U;
    if (frame.size() < header_size || frame.substr(0U, 4U) != request_magic)
    {
        return std::nullopt;
    }
    auto request = ThumbnailWorkerRequest{};
    auto const format = static_cast<unsigned char>(frame[4U]);
    auto const method = static_cast<unsigned char>(frame[5U]);
    if (format > static_cast<unsigned char>(ThumbnailSourceFormat::jpeg) ||
        method > static_cast<unsigned char>(ThumbnailMethod::crop))
    {
        return std::nullopt;
    }
    request.format = static_cast<ThumbnailSourceFormat>(format);
    request.method = static_cast<ThumbnailMethod>(method);
    request.target_width = read_u32(frame, 6U);
    request.target_height = read_u32(frame, 10U);
    request.max_pixels = read_u32(frame, 14U);
    auto const input_len = read_u32(frame, 18U);
    if (frame.size() - header_size != input_len)
    {
        return std::nullopt;
    }
    request.source_bytes.assign(frame.substr(header_size));
    return request;
}

auto frame_thumbnail_response(ThumbnailWorkerResponse const& response) -> std::optional<std::string>
{
    // LCOV_EXCL_START — requires a >4 GiB PNG; physically impossible with any sane max_pixels limit
    if (response.png_bytes.size() > std::numeric_limits<std::uint32_t>::max())
    {
        return std::nullopt;
    }
    // LCOV_EXCL_STOP
    auto frame = std::string{response_magic};
    frame.push_back(static_cast<char>(response.status));
    append_u32(frame, response.width);
    append_u32(frame, response.height);
    append_u32(frame, static_cast<std::uint32_t>(response.png_bytes.size()));
    frame.append(response.png_bytes);
    return frame;
}

auto parse_thumbnail_response(std::string_view frame) -> std::optional<ThumbnailWorkerResponse>
{
    constexpr std::size_t header_size = 4U + 1U + 4U + 4U + 4U;
    if (frame.size() < header_size || frame.substr(0U, 4U) != response_magic)
    {
        return std::nullopt;
    }
    auto response = ThumbnailWorkerResponse{};
    auto const status = static_cast<unsigned char>(frame[4U]);
    if (status > static_cast<unsigned char>(ThumbnailWorkerStatus::internal_error))
    {
        return std::nullopt;
    }
    response.status = static_cast<ThumbnailWorkerStatus>(status);
    response.width = read_u32(frame, 5U);
    response.height = read_u32(frame, 9U);
    auto const output_len = read_u32(frame, 13U);
    if (frame.size() - header_size != output_len)
    {
        return std::nullopt;
    }
    response.png_bytes.assign(frame.substr(header_size));
    return response;
}

auto normalise_thumbnail_dimensions(ThumbnailerConfig const& config, std::uint32_t width, std::uint32_t height)
    -> std::optional<std::pair<std::uint32_t, std::uint32_t>>
{
    if (width == 0U || height == 0U)
    {
        return std::nullopt;
    }
    auto const cap = config.max_target_dimension == 0U ? width : config.max_target_dimension;
    if (width > cap || height > cap)
    {
        return std::nullopt;
    }
    return std::pair{width, height};
}

auto generate_thumbnail(ThumbnailerConfig const& config, ThumbnailRequest const& request) -> ThumbnailResult
{
    if (config.worker_path.empty())
    {
        return {false, 503U, {}, {}, 0U, 0U, "thumbnail worker not configured"};
    }
    if (request.source_bytes.empty())
    {
        return {false, 400U, {}, {}, 0U, 0U, "empty source media"};
    }
    if (config.max_input_bytes != 0U && request.source_bytes.size() > config.max_input_bytes)
    {
        return {false, 413U, {}, {}, 0U, 0U, "source media exceeds decode input limit"};
    }
    auto const format = map_content_type_to_source_format(request.source_content_type);
    if (!format.has_value())
    {
        return {false, 415U, {}, {}, 0U, 0U, "unsupported source content type"};
    }
    auto const dimensions = normalise_thumbnail_dimensions(config, request.width, request.height);
    if (!dimensions.has_value())
    {
        return {false, 400U, {}, {}, 0U, 0U, "invalid thumbnail dimensions"};
    }

    auto worker_request = ThumbnailWorkerRequest{};
    worker_request.format = *format;
    worker_request.method = request.method;
    worker_request.target_width = dimensions->first;
    worker_request.target_height = dimensions->second;
    worker_request.max_pixels = config.max_pixels;
    worker_request.source_bytes = request.source_bytes;
    auto const frame_opt = frame_thumbnail_request(worker_request);
    // LCOV_EXCL_START — only reachable when source_bytes > 4 GiB; prevented by max_upload_bytes
    if (!frame_opt.has_value())
    {
        return {false, 413U, {}, {}, 0U, 0U, "source image too large for thumbnail wire protocol"};
    }
    // LCOV_EXCL_STOP
    auto const& frame = *frame_opt;

    // stdin: parent writes -> child reads; stdout: child writes -> parent reads.
    auto to_child = std::array<int, 2>{-1, -1};
    auto from_child = std::array<int, 2>{-1, -1};
    if (!create_cloexec_pipe(to_child))
    {
        return {false, 500U, {}, {}, 0U, 0U, "failed to create worker input pipe"};
    }
    auto child_stdin_read = core::FileDescriptor{to_child[0]};
    auto child_stdin_write = core::FileDescriptor{to_child[1]};
    if (!create_cloexec_pipe(from_child))
    {
        return {false, 500U, {}, {}, 0U, 0U, "failed to create worker output pipe"};
    }
    auto child_stdout_read = core::FileDescriptor{from_child[0]};
    auto child_stdout_write = core::FileDescriptor{from_child[1]};

    auto const pid = ::fork();
    if (pid < 0)
    {
        return {false, 500U, {}, {}, 0U, 0U, "failed to fork worker"};
    }
    if (pid == 0)
    {
        // Child: wire pipes to stdio, drop every other descriptor, then exec.
        ::dup2(child_stdin_read.get(), STDIN_FILENO);
        ::dup2(child_stdout_write.get(), STDOUT_FILENO);

        // The parent write-end and child read-end are not needed after dup2.
        // Close them explicitly before the sweep so the sweep does not need to
        // know about them and we avoid double-close on the FileDescriptor reset.
        child_stdin_write.reset();
        child_stdout_read.reset();

        // Close everything except stdio and the pipe ends that are now stdio.
        // Use the allocation-free span overload: between fork() and exec() the
        // child must not touch the heap because another thread in the parent may
        // hold a malloc lock, which would deadlock and leave the parent waiting
        // until the worker timeout fires.
        auto const keep_open =
            std::array<int, 4>{STDIN_FILENO, STDOUT_FILENO, child_stdin_read.get(), child_stdout_write.get()};
        core::close_all_file_descriptors_except(std::span<int const>{keep_open});

        // Prevent privilege escalation through setuid/setcap helpers before exec.
        // PR_SET_NO_NEW_PRIVS is Linux-specific; other platforms rely on the
        // fork/exec model and the worker's own hardening.
#if defined(__linux__)
        std::ignore = ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
#endif

        child_stdin_read.reset();
        child_stdout_write.reset();
        char* const argv[] = {const_cast<char*>(config.worker_path.c_str()), nullptr};
        ::execv(config.worker_path.c_str(), argv);
        ::_exit(127); // exec failed
    }

    // Parent: close the child's ends so EOF propagates correctly.
    child_stdin_read.reset();
    child_stdout_write.reset();
    // A worker that dies mid-write must not raise SIGPIPE in the parent.
    ::signal(SIGPIPE, SIG_IGN);
    set_nonblocking(child_stdin_write.get());
    set_nonblocking(child_stdout_read.get());

    auto const timeout_ms =
        static_cast<std::int64_t>(config.timeout_seconds == 0U ? 10U : config.timeout_seconds) * 1000;
    auto const deadline_ms = monotonic_ms() + timeout_ms;

    auto const wrote = write_all_deadline(child_stdin_write.get(), frame, deadline_ms);
    child_stdin_write.reset(); // signal EOF to the worker
    auto read_ok = false;
    auto const response_bytes =
        wrote
            ? read_all_deadline(
                  child_stdout_read.get(), deadline_ms,
                  config.max_output_bytes == 0U ? 0U : static_cast<std::size_t>(config.max_output_bytes) + 32U, read_ok)
            : std::string{};

    // Reap the worker; kill it if it is still alive (timeout or protocol error).
    // `alive_at_deadline` distinguishes a hung worker (we had to SIGKILL it) from
    // one that exited or was signalled on its own, which the diagnostics surface.
    auto status = 0;
    auto const alive_at_deadline = ::waitpid(pid, &status, WNOHANG) == 0;
    if (alive_at_deadline)
    {
        ::kill(pid, SIGKILL);
        std::ignore = ::waitpid(pid, &status, 0);
    }
    auto const worker_status = describe_worker_status(!alive_at_deadline, status);

    if (!wrote)
    {
        return {false, 504U, {}, {}, 0U, 0U, "timed out sending media to worker" + worker_status};
    }
    if (!read_ok)
    {
        return {false, 504U, {}, {}, 0U, 0U, "worker timed out or output too large" + worker_status};
    }
    auto const response = parse_thumbnail_response(response_bytes);
    if (!response.has_value())
    {
        return {false, 502U, {}, {}, 0U, 0U, "malformed worker response" + worker_status};
    }
    switch (response->status)
    {
    case ThumbnailWorkerStatus::ok:
        if (config.max_output_bytes != 0U && response->png_bytes.size() > config.max_output_bytes)
        {
            return {false, 502U, {}, {}, 0U, 0U, "thumbnail exceeds output limit"};
        }
        return {true, 200U, "image/png", response->png_bytes, response->width, response->height, {}};
    case ThumbnailWorkerStatus::decode_failed:
        return {false, 400U, {}, {}, 0U, 0U, "worker could not decode source image"};
    case ThumbnailWorkerStatus::too_large:
        return {false, 413U, {}, {}, 0U, 0U, "source image exceeds decode limits"};
    case ThumbnailWorkerStatus::unsupported:
        return {false, 415U, {}, {}, 0U, 0U, "worker does not support this image"};
    case ThumbnailWorkerStatus::internal_error:
        break;
    }
    return {false, 502U, {}, {}, 0U, 0U, "worker internal error"};
}

} // namespace merovingian::media
