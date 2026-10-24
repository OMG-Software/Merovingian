// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/thumbnailer.hpp"

#include "merovingian/core/error.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/core/library_version.hpp"

#include <algorithm>
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
    constexpr std::string_view library_request_magic{"MLQ1"};
    constexpr std::string_view library_report_magic{"MLR1"};

    // Library report fields: printable ASCII only, at most this long (a shared-object path is the
    // longest), five per line.
    constexpr std::size_t max_library_field_bytes{512U};
    constexpr std::size_t library_report_fields{5U};
    constexpr std::size_t max_library_report_bytes{max_library_report_entries * library_report_fields *
                                                   (max_library_field_bytes + 1U)};

    [[nodiscard]] constexpr auto is_report_byte(char byte) noexcept -> bool
    {
        return byte >= 0x20 && byte <= 0x7E;
    }

    // A field as the report carries it: anything outside printable ASCII (tabs and newlines
    // included) becomes '?', and an over-long field is cut.
    [[nodiscard]] auto report_field(std::string_view value) -> std::string
    {
        auto field = std::string{value.substr(0U, max_library_field_bytes)};
        for (auto& byte : field)
        {
            if (!is_report_byte(byte))
            {
                byte = '?';
            }
        }
        return field;
    }

    [[nodiscard]] auto linkage_name(core::Linkage linkage) -> std::string_view
    {
        return linkage == core::Linkage::dynamic ? "dynamic" : "static";
    }

    [[nodiscard]] auto parse_linkage(std::string_view name) -> std::optional<core::Linkage>
    {
        if (name == "dynamic")
        {
            return core::Linkage::dynamic;
        }
        if (name == "static")
        {
            return core::Linkage::static_linked;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto open_worker_stderr_sink() noexcept -> core::FileDescriptor
    {
        auto sink = core::FileDescriptor{::open("/dev/null", O_WRONLY | O_CLOEXEC)};
        if (sink.valid() && sink.get() <= STDERR_FILENO)
        {
            // A service may start with stdio closed and redirect it later. Keep
            // our owned sink outside that mutable range, preserving closed stdio.
            return core::FileDescriptor{::fcntl(sink.get(), F_DUPFD_CLOEXEC, 3)};
        }
        return sink;
    }

    // Pre-open before main can enter Capsicum or another filesystem sandbox.
    // Immutable RAII ownership keeps concurrent thumbnail requests independent;
    // CLOEXEC prevents the original descriptor surviving the worker exec.
    auto const worker_stderr_sink = open_worker_stderr_sink();

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

    [[nodiscard]] auto png_matches_reported_dimensions(ThumbnailWorkerResponse const& response) noexcept -> bool
    {
        // Inspect only the fixed PNG header: no image decoder belongs in the parent.
        constexpr auto png_signature = std::string_view{"\x89PNG\r\n\x1a\n", 8U};
        constexpr auto ihdr_size = std::size_t{33U}; // signature + length/type + 13-byte IHDR + CRC
        auto const png = std::string_view{response.png_bytes};
        if (png.size() < ihdr_size || png.substr(0U, 8U) != png_signature || read_u32(png, 8U) != 13U ||
            png.substr(12U, 4U) != "IHDR")
        {
            return false;
        }
        auto const width = read_u32(png, 16U);
        auto const height = read_u32(png, 20U);
        constexpr auto max_png_dimension = std::uint32_t{0x7FFFFFFFU};
        return width != 0U && height != 0U && width <= max_png_dimension && height <= max_png_dimension &&
               width == response.width && height == response.height;
    }

    [[nodiscard]] auto monotonic_ms() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    // Writes `payload` to `fd` honouring `deadline_ms`, never blocking longer
    // than the remaining budget. Returns false on error or timeout. On failure
    // `detail` is set to a short cause string (poll/revents/errno, bytes sent)
    // so the caller can surface why the worker write stalled.
    [[nodiscard]] auto write_all_deadline(int fd, std::string_view payload, std::int64_t deadline_ms,
                                          std::string& detail) -> bool
    {
        std::size_t written = 0U;
        while (written < payload.size())
        {
            auto const remaining = deadline_ms - monotonic_ms();
            if (remaining <= 0)
            {
                detail = "poll deadline elapsed after " + std::to_string(written) + "/" +
                         std::to_string(payload.size()) + " bytes";
                return false;
            }
            auto pfd = pollfd{fd, POLLOUT, 0};
            auto const ready = ::poll(&pfd, 1U, static_cast<int>(remaining));
            if (ready <= 0 || (pfd.revents & (POLLERR | POLLNVAL)) != 0)
            {
                detail = "poll ready=" + std::to_string(ready) + " revents=" + std::to_string(pfd.revents) +
                         " errno=" + std::to_string(ready < 0 ? errno : 0) + " sent=" + std::to_string(written);
                return false;
            }
            auto const n = ::write(fd, payload.data() + written, payload.size() - written);
            if (n < 0)
            {
                if (errno == EINTR || errno == EAGAIN)
                {
                    continue;
                }
                detail = "write errno=" + std::to_string(errno) + " sent=" + std::to_string(written);
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
        // Set FD_CLOEXEC on each end with a raw fcntl. Do NOT wrap the fds in a
        // temporary core::FileDescriptor here: that temporary owns the fd and
        // closes it when it is destroyed at the end of the full expression,
        // which left the caller holding two already-closed pipe ends. On NetBSD
        // (and any platform taking this non-pipe2 path) the parent then polled
        // the closed worker-stdin write end and got POLLNVAL, so the request was
        // never sent and the worker stalled on empty stdin (HTTP 504).
        auto const set_cloexec = [](int fd) noexcept -> bool {
            auto const flags = ::fcntl(fd, F_GETFD, 0);
            return flags >= 0 && ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
        };
        if (!set_cloexec(fds[0]) || !set_cloexec(fds[1]))
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

auto frame_library_report_request() -> std::string
{
    return std::string{library_request_magic};
}

auto is_library_report_request(std::string_view frame) noexcept -> bool
{
    return frame == library_request_magic;
}

auto frame_library_report(std::span<core::LibraryVersion const> libraries) -> std::string
{
    auto text = std::string{};
    for (auto const& library : libraries)
    {
        text += report_field(library.name) + '\t' + std::string{linkage_name(library.linkage)} + '\t' +
                report_field(library.runtime_version) + '\t' + report_field(library.build_version) + '\t' +
                report_field(library.shared_object) + '\n';
    }
    auto frame = std::string{library_report_magic};
    append_u32(frame, static_cast<std::uint32_t>(text.size()));
    return frame + text;
}

auto parse_library_report(std::string_view frame) -> std::optional<std::vector<core::LibraryVersion>>
{
    constexpr auto header_bytes = library_report_magic.size() + 4U;
    if (frame.size() < header_bytes || frame.substr(0U, library_report_magic.size()) != library_report_magic)
    {
        return std::nullopt;
    }
    auto const length = read_u32(frame, library_report_magic.size());
    auto text = frame.substr(header_bytes);
    if (length > max_library_report_bytes || text.size() != length || (!text.empty() && text.back() != '\n'))
    {
        return std::nullopt;
    }
    auto libraries = std::vector<core::LibraryVersion>{};
    while (!text.empty())
    {
        if (libraries.size() == max_library_report_entries)
        {
            return std::nullopt;
        }
        auto const line_end = text.find('\n');
        auto line = text.substr(0U, line_end);
        text.remove_prefix(line_end + 1U);

        auto fields = std::vector<std::string_view>{};
        while (fields.size() < library_report_fields)
        {
            auto const tab = line.find('\t');
            fields.push_back(line.substr(0U, tab));
            if (tab == std::string_view::npos)
            {
                line = {};
                break;
            }
            line.remove_prefix(tab + 1U);
        }
        if (fields.size() != library_report_fields || !line.empty())
        {
            return std::nullopt;
        }
        for (auto const field : fields)
        {
            if (field.size() > max_library_field_bytes || !std::ranges::all_of(field, [](char byte) {
                    return is_report_byte(byte);
                }))
            {
                return std::nullopt;
            }
        }
        auto const linkage = parse_linkage(fields[1]);
        if (!linkage.has_value())
        {
            return std::nullopt;
        }
        libraries.push_back(core::LibraryVersion{std::string{fields[0]}, *linkage, std::string{fields[2]},
                                                 std::string{fields[3]}, std::string{fields[4]}});
    }
    return libraries;
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

namespace
{

    // One round trip with a freshly spawned worker: `frame` in, its whole stdout back. Every
    // request takes this path, so a library report runs under the same environment, descriptor
    // sweep, NO_NEW_PRIVS and deadline as a thumbnail.
    struct WorkerExchange final
    {
        // Non-empty when the worker never ran (no pipe, no fork, no stderr sink).
        std::string setup_failure{};
        bool wrote{false};
        bool read_ok{false};
        std::string response_bytes{};
        std::string write_detail{};
        std::string worker_status{};
    };

    [[nodiscard]] auto exchange_with_worker(ThumbnailerConfig const& config, std::string const& frame,
                                            std::size_t max_response_bytes) -> WorkerExchange
    {
        auto exchange = WorkerExchange{};
        if (!worker_stderr_sink.valid())
        {
            exchange.setup_failure = "thumbnail worker stderr sink unavailable";
            return exchange;
        }

        // stdin: parent writes -> child reads; stdout: child writes -> parent reads.
        auto to_child = std::array<int, 2>{-1, -1};
        auto from_child = std::array<int, 2>{-1, -1};
        if (!create_cloexec_pipe(to_child))
        {
            exchange.setup_failure = "failed to create worker input pipe";
            return exchange;
        }
        auto child_stdin_read = core::FileDescriptor{to_child[0]};
        auto child_stdin_write = core::FileDescriptor{to_child[1]};
        if (!create_cloexec_pipe(from_child))
        {
            exchange.setup_failure = "failed to create worker output pipe";
            return exchange;
        }
        auto child_stdout_read = core::FileDescriptor{from_child[0]};
        auto child_stdout_write = core::FileDescriptor{from_child[1]};

        // Construct the exec environment before fork; never inherit parent-only or
        // dynamic-loader entries, and do not allocate in the fork-to-exec window.
        char minimal_path[] = "PATH=/usr/bin:/bin";
        char* const exec_env[] = {minimal_path, nullptr};
        auto const pid = ::fork();
        if (pid < 0)
        {
            exchange.setup_failure = "failed to fork worker";
            return exchange;
        }
        if (pid == 0)
        {
            // Child: wire pipes to stdio, drop every other descriptor, then exec.
            ::dup2(child_stdin_read.get(), STDIN_FILENO);
            ::dup2(child_stdout_write.get(), STDOUT_FILENO);
            if (::dup2(worker_stderr_sink.get(), STDERR_FILENO) < 0)
            {
                ::_exit(127); // Never execute a worker with inherited diagnostic access.
            }

            // The parent write-end and child read-end are not needed after dup2.
            // Close them explicitly before the sweep so the sweep does not need to
            // know about them and we avoid double-close on the FileDescriptor reset.
            child_stdin_write.reset();
            child_stdout_read.reset();

            char* const exec_argv[] = {const_cast<char*>(config.worker_path.c_str()), nullptr};

#ifdef __FreeBSD__
            // In FreeBSD Capsicum capability mode the process cannot open files by path;
            // use a pre-opened binary fd with fexecve(3) instead of execv(3).
            if (config.worker_binary_fd >= 0)
            {
                // Include the pre-opened binary fd in the keep-open set so the fd
                // sweep does not close it before the fexecve call.
                auto const keep_open_caps = std::array<int, 5>{STDIN_FILENO, STDOUT_FILENO, child_stdin_read.get(),
                                                               child_stdout_write.get(), config.worker_binary_fd};
                core::close_all_file_descriptors_except(std::span<int const>{keep_open_caps});
                child_stdin_read.reset();
                child_stdout_write.reset();
                ::fexecve(config.worker_binary_fd, exec_argv, exec_env);
                ::_exit(127); // fexecve failed
            }
#endif // __FreeBSD__

            // Standard path: close everything except stdio and the pipe ends, then exec.
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
            ::execve(config.worker_path.c_str(), exec_argv, exec_env);
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

        exchange.wrote = write_all_deadline(child_stdin_write.get(), frame, deadline_ms, exchange.write_detail);
        child_stdin_write.reset(); // signal EOF to the worker
        if (exchange.wrote)
        {
            exchange.response_bytes =
                read_all_deadline(child_stdout_read.get(), deadline_ms, max_response_bytes, exchange.read_ok);
        }

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
        exchange.worker_status = describe_worker_status(!alive_at_deadline, status);
        return exchange;
    }

} // namespace

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

    auto const exchange = exchange_with_worker(
        config, frame, config.max_output_bytes == 0U ? 0U : static_cast<std::size_t>(config.max_output_bytes) + 32U);
    if (!exchange.setup_failure.empty())
    {
        return {false, 500U, {}, {}, 0U, 0U, exchange.setup_failure};
    }
    auto const& worker_status = exchange.worker_status;
    if (!exchange.wrote)
    {
        return {false,
                504U,
                {},
                {},
                0U,
                0U,
                "timed out sending media to worker" + worker_status + " [" + exchange.write_detail + "]"};
    }
    if (!exchange.read_ok)
    {
        return {false, 504U, {}, {}, 0U, 0U, "worker timed out or output too large" + worker_status};
    }
    auto const response = parse_thumbnail_response(exchange.response_bytes);
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
        if (!png_matches_reported_dimensions(*response))
        {
            return {false, 502U, {}, {}, 0U, 0U, "invalid worker PNG header or dimensions"};
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

auto query_thumbnail_worker_libraries(ThumbnailerConfig const& config) -> ThumbnailWorkerLibraries
{
    if (config.worker_path.empty())
    {
        return {
            {},
            core::Error{core::ErrorCode::invalid_argument, "thumbnail worker not configured"}
        };
    }
    auto const exchange = exchange_with_worker(config, frame_library_report_request(),
                                               library_report_magic.size() + 4U + max_library_report_bytes);
    if (!exchange.setup_failure.empty())
    {
        return {
            {},
            core::Error{core::ErrorCode::io_failure, exchange.setup_failure}
        };
    }
    // A worker that could not exec exits 127 with nothing written, which reads as an empty answer,
    // not a malformed one.
    if (!exchange.wrote || !exchange.read_ok || exchange.response_bytes.empty())
    {
        return {
            {},
            core::Error{core::ErrorCode::io_failure,
             "thumbnail worker " + config.worker_path + " did not answer" + exchange.worker_status}
        };
    }
    auto report = parse_library_report(exchange.response_bytes);
    if (!report.has_value())
    {
        return {
            {},
            core::Error{core::ErrorCode::parse_failure,
             "malformed thumbnail worker library report" + exchange.worker_status}
        };
    }
    return {std::move(report), {}};
}

} // namespace merovingian::media
