// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Integration test: spawn the real merovingian-server binary, let it run under
// full platform hardening (seccomp, capability drop, no-new-privs) for 10 s,
// then verify it shuts down cleanly via SIGTERM.
//
// This test catches seccomp filter gaps that are invisible to in-process unit
// tests — specifically syscalls made by glibc thread initialisation AFTER the
// filter is installed (rseq, membarrier, getcpu, futex_waitv). A filter gap
// produces SIGSYS (SECCOMP_RET_KILL_PROCESS) and the server dies with "Bad
// system call" immediately after the listeners become active.
//
// Because the project now refuses to start unless every hardening control is
// `enabled`, the test is skipped when the current build or runtime environment
// cannot satisfy that requirement. The skip is detected from the server log
// rather than by duplicating the readiness logic in the test runner.

#include "../support/temp_directory.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MEROVINGIAN_TEST_SERVER_BINARY
#define MEROVINGIAN_TEST_SERVER_BINARY ""
#endif
#ifndef MEROVINGIAN_TEST_FEDERATION_WORKER
#define MEROVINGIAN_TEST_FEDERATION_WORKER ""
#endif

// environ is a POSIX global; declare it for posix_spawn envp building.
extern char** environ; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

namespace
{

[[nodiscard]] auto server_binary() -> std::string_view
{
    return MEROVINGIAN_TEST_SERVER_BINARY;
}

[[nodiscard]] auto federation_worker_binary() -> std::string_view
{
    return MEROVINGIAN_TEST_FEDERATION_WORKER;
}

// RAII temp directory removed on destruction.
struct TempDir final
{
    std::filesystem::path path;

    explicit TempDir()
    {
        auto rng = std::mt19937{std::random_device{}()};
        auto dist = std::uniform_int_distribution<std::uint64_t>{};
        auto const base = merovingian::tests::temporary_directory();
        while (true)
        {
            auto candidate = base / ("merv-startup-" + std::to_string(dist(rng)));
            if (!std::filesystem::exists(candidate))
            {
                std::filesystem::create_directories(candidate);
                path = std::move(candidate);
                return;
            }
        }
    }

    ~TempDir() noexcept
    {
        try
        {
            std::filesystem::remove_all(path);
        }
        catch (...)
        {
        }
    }

    TempDir(TempDir const&) = delete;
    auto operator=(TempDir const&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
};

// Bind to loopback:0 to let the kernel assign a free port, then close the
// socket. There is a small TOCTOU window, which is acceptable for test use.
[[nodiscard]] auto probe_free_port() -> std::uint16_t
{
    auto const fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return 0;
    }
    auto const reuse = int{1};
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    auto addr = sockaddr_in{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        ::close(fd);
        return 0;
    }
    auto len = socklen_t{sizeof(addr)};
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
    ::close(fd);
    return ntohs(addr.sin_port);
}

// Write a minimal no-TLS SQLite config that the server can start with.
// SQLite auto-migrates on first open so no separate db-migrate step is needed.
// The signing key is stored in the database (plaintext fallback when no
// security.secrets.master_key_file is configured); no separate key file is needed.
auto write_minimal_config(std::filesystem::path const& config_path, std::filesystem::path const& db_path,
                          std::string_view worker_binary, std::uint16_t client_port, std::uint16_t fed_port) -> void
{
    {
        auto f = std::ofstream{config_path};
        f << "server.name=localhost.test\n"
          << "server.public_baseurl=https://localhost.test\n"
          << "listeners.client.bind=127.0.0.1:" << client_port << "\n"
          << "listeners.client.tls=false\n"
          << "listeners.federation.bind=127.0.0.1:" << fed_port << "\n"
          << "listeners.federation.tls=false\n"
          << "database.backend=sqlite\n"
          << "database.sqlite_path=" << db_path.string() << "\n"
          << "federation.worker.binary=" << worker_binary << "\n";
    }
    // The server rejects config files with group/other write permission.
    ::chmod(config_path.c_str(), 0644); // NOLINT(google-runtime-int)
}

// Build a child environment that strips MEROVINGIAN_TEST_DISABLE_HARDENING so
// the spawned server runs with full platform hardening even when the Catch2
// test runner has that variable set to skip in-process hardening.
[[nodiscard]] auto build_child_env() -> std::vector<std::string>
{
    auto result = std::vector<std::string>{};
    for (auto** p = environ; *p != nullptr; ++p)
    {
        auto const entry = std::string_view{*p};
        if (entry.starts_with("MEROVINGIAN_TEST_DISABLE_HARDENING="))
        {
            continue;
        }
        result.emplace_back(entry);
    }
    return result;
}

// RAII guard that kills and reaps the child process on destruction.
struct ServerGuard final
{
    pid_t pid{-1};
    int log_pipe_read{-1};
    int exit_status{-1};
    bool reaped{false};

    ServerGuard() = default;

    ~ServerGuard() noexcept
    {
        if (log_pipe_read >= 0)
        {
            ::close(log_pipe_read);
            log_pipe_read = -1;
        }
        if (pid > 0)
        {
            ::kill(pid, SIGKILL);
            ::waitpid(pid, nullptr, 0);
            pid = -1;
        }
    }

    ServerGuard(ServerGuard const&) = delete;
    auto operator=(ServerGuard const&) -> ServerGuard& = delete;
    ServerGuard(ServerGuard&&) = delete;
    auto operator=(ServerGuard&&) -> ServerGuard& = delete;

    // True if the child is still running. Uses waitpid(WNOHANG) so that a
    // process which has already exited (and would otherwise exist only as a
    // zombie) is reported as not alive. When the child has exited, its status
    // is stored and the pid is cleared to prevent the destructor from sending
    // SIGKILL to a stale pid.
    [[nodiscard]] auto alive() noexcept -> bool
    {
        if (pid <= 0)
        {
            return false;
        }

        auto const rc = ::waitpid(pid, &exit_status, WNOHANG);
        if (rc > 0)
        {
            reaped = true;
            pid = -1;
            return false;
        }
        if (rc == 0)
        {
            return true;
        }

        // rc < 0: unexpected error — treat the process as gone.
        pid = -1;
        return false;
    }
};

// Launch the server, redirecting stdout and stderr to a pipe so we can detect
// the "Listeners active" log line. The child runs without
// MEROVINGIAN_TEST_DISABLE_HARDENING so seccomp and capability drop apply.
[[nodiscard]] auto launch_server(std::string const& binary, std::filesystem::path const& config_path,
                                 std::vector<std::string> const& child_env, ServerGuard& out) -> bool
{
    auto pipe_fds = std::array<int, 2>{-1, -1};
    if (::pipe(pipe_fds.data()) != 0)
    {
        return false;
    }
    // Read end: non-blocking so wait_for_log_line can use select() correctly.
    ::fcntl(pipe_fds[0], F_SETFL, ::fcntl(pipe_fds[0], F_GETFL) | O_NONBLOCK);
    // Read end: close-on-exec so the child does not inherit it.
    ::fcntl(pipe_fds[0], F_SETFD, FD_CLOEXEC);
    // Write end has no CLOEXEC; child inherits it and we dup2 it to std{out,err}.

    auto actions = posix_spawn_file_actions_t{};
    ::posix_spawn_file_actions_init(&actions);
    ::posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDOUT_FILENO);
    ::posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDERR_FILENO);
    // Close the original write-end fd in the child after dup2.
    ::posix_spawn_file_actions_addclose(&actions, pipe_fds[1]);

    auto config_str = config_path.string();
    // argv must be char* (not const char*) per POSIX — cast is safe: spawn
    // treats argv as read-only.
    char* argv[] = {const_cast<char*>(binary.c_str()), const_cast<char*>("--config"),
                    const_cast<char*>(config_str.c_str()), nullptr};

    auto env_ptrs = std::vector<char*>{};
    env_ptrs.reserve(child_env.size() + 1U);
    for (auto const& s : child_env)
    {
        env_ptrs.push_back(const_cast<char*>(s.c_str()));
    }
    env_ptrs.push_back(nullptr);

    auto child_pid = pid_t{};
    auto const rc = ::posix_spawn(&child_pid, binary.c_str(), &actions, nullptr, argv, env_ptrs.data());
    ::posix_spawn_file_actions_destroy(&actions);
    ::close(pipe_fds[1]); // parent closes write end; read end stays open

    if (rc != 0)
    {
        ::close(pipe_fds[0]);
        return false;
    }

    out.log_pipe_read = pipe_fds[0];
    out.pid = child_pid;
    return true;
}

// Read from read_fd until target is found in the accumulated output or timeout
// expires. Uses select() to avoid busy-waiting. Returns true when target is found.
// All data read from the pipe is appended to out_accumulated so callers can
// inspect log lines that arrived in the same read() as the target.
[[nodiscard]] auto wait_for_log_line(int read_fd, std::string_view target, std::chrono::seconds timeout,
                                     std::string& out_accumulated) -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + timeout;
    auto chunk = std::array<char, 4096>{};

    while (std::chrono::steady_clock::now() < deadline)
    {
        auto const remaining_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining_ms <= 0)
        {
            break;
        }

        // Cap the select() wait at 1 s so we don't overshoot the deadline too badly.
        auto tv = timeval{};
        tv.tv_sec = static_cast<long>(std::min<long long>(remaining_ms / 1000LL, 1LL));
        tv.tv_usec = static_cast<long>((remaining_ms % 1000LL) * 1000LL);

        auto rfds = fd_set{};
        FD_ZERO(&rfds);
        FD_SET(read_fd, &rfds);

        if (::select(read_fd + 1, &rfds, nullptr, nullptr, &tv) <= 0)
        {
            continue; // timeout slice or EINTR — loop and check deadline
        }

        auto const n = ::read(read_fd, chunk.data(), chunk.size() - 1U);
        if (n <= 0)
        {
            return false; // EOF: process exited before printing the target line
        }
        out_accumulated.append(chunk.data(), static_cast<std::size_t>(n));
        if (out_accumulated.find(target) != std::string::npos)
        {
            return true;
        }
    }
    return false;
}

// Poll for the child to exit, with a deadline. Returns true when the child has
// exited; fills out_status with the raw waitpid() status on success.
[[nodiscard]] auto wait_for_exit(pid_t pid, std::chrono::seconds timeout, int& out_status) -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
        auto const rc = ::waitpid(pid, &out_status, WNOHANG);
        if (rc > 0)
        {
            return true;
        }
        if (rc < 0)
        {
            return false; // unexpected error
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    return false;
}

// Read everything currently available from read_fd. Non-blocking; returns what
// has already been emitted by the child process.
[[nodiscard]] auto drain_pipe(int read_fd) -> std::string
{
    auto result = std::string{};
    auto chunk = std::array<char, 4096>{};
    while (true)
    {
        auto const n = ::read(read_fd, chunk.data(), chunk.size() - 1U);
        if (n <= 0)
        {
            break;
        }
        result.append(chunk.data(), static_cast<std::size_t>(n));
    }
    return result;
}

} // namespace

SCENARIO("merovingian-server either starts under full platform hardening or refuses to start when hardening cannot be "
         "enabled",
         "[platform][hardening][integration][startup][binary]")
{
    GIVEN("the server binary and federation worker binary are available")
    {
        if (server_binary().empty())
        {
            WARN("MEROVINGIAN_TEST_SERVER_BINARY not set — skipping live binary startup test");
            return;
        }
        if (federation_worker_binary().empty())
        {
            WARN("MEROVINGIAN_TEST_FEDERATION_WORKER not set — skipping live binary startup test");
            return;
        }

        auto const tmp = TempDir{};
        auto const db_path = tmp.path / "test.db";
        auto const config_path = tmp.path / "test.conf";

        auto const client_port = probe_free_port();
        auto const fed_port = probe_free_port();
        REQUIRE(client_port != 0);
        REQUIRE(fed_port != 0);

        write_minimal_config(config_path, db_path, federation_worker_binary(), client_port, fed_port);

        // Strip MEROVINGIAN_TEST_DISABLE_HARDENING from the child environment so
        // the server runs with full seccomp + capability drop + no-new-privs even
        // though the Catch2 test runner suppresses those controls in-process.
        auto const child_env = build_child_env();

        WHEN("the server binary is started with a minimal SQLite config")
        {
            auto guard = ServerGuard{};
            auto const binary = std::string{server_binary()};
            REQUIRE(launch_server(binary, config_path, child_env, guard));

            // "Listeners active; awaiting traffic..." is the INFO log line emitted
            // once all TCP sockets are bound and the seccomp filter, capability drop,
            // and no-new-privs are fully applied. Capture every byte read so that
            // log lines arriving in the same read() as the target are preserved.
            auto startup_log = std::string{};
            auto const ready =
                wait_for_log_line(guard.log_pipe_read, "Listeners active", std::chrono::seconds{20}, startup_log);

            THEN("the server reaches the listening state without crashing")
            {
                REQUIRE(ready);

                // The final hardening self-check runs immediately after "Listeners
                // active". If the build/runtime cannot satisfy every control, skip
                // this test rather than failing CI in unsupported environments.
                if (startup_log.find("Startup refused: hardening self-check") != std::string::npos)
                {
                    WARN("build/runtime environment cannot satisfy full hardening; binary startup test skipped\n" +
                         startup_log);
                    return;
                }

                // The server performs the final hardening self-check immediately
                // after logging "Listeners active". Poll the log for either a clean
                // startup or a refusal; if the runtime cannot satisfy every control,
                // skip this test rather than failing CI in unsupported environments.
                auto hardening_decided = false;
                for (auto i = 0; i < 50; ++i)
                {
                    auto const drain = drain_pipe(guard.log_pipe_read);
                    if (drain.find("Startup refused: hardening self-check") != std::string::npos)
                    {
                        WARN("build/runtime environment cannot satisfy full hardening; binary startup test skipped\n" +
                             drain);
                        return;
                    }
                    if (!guard.alive())
                    {
                        hardening_decided = true;
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds{100});
                }

                if (hardening_decided)
                {
                    auto const drain = drain_pipe(guard.log_pipe_read);
                    if (drain.find("Startup refused: hardening self-check") != std::string::npos)
                    {
                        WARN("build/runtime environment cannot satisfy full hardening; binary startup test skipped\n" +
                             drain);
                        return;
                    }
                    FAIL("server died before the 10 s idle window; likely seccomp gap or crash:\n" +
                         std::string{"--- startup log ---\n"} + startup_log + "\n--- post-listeners drain ---\n" +
                         drain);
                }

                // Confirm it survives 10 s of idle operation under full hardening.
                // A seccomp gap (SIGSYS / SECCOMP_RET_KILL_PROCESS) would kill the
                // process during this window, causing alive() to return false.
                std::this_thread::sleep_for(std::chrono::seconds{10});
                if (!guard.alive())
                {
                    auto const drain = drain_pipe(guard.log_pipe_read);
                    FAIL("server died during 10 s idle window under full hardening; likely seccomp gap:\n" + drain);
                }

                // Request graceful shutdown.
                ::kill(guard.pid, SIGTERM);

                // Wait up to 10 s for clean exit; the destructor SIGKILLs if needed.
                auto exit_status = int{};
                auto const exited = wait_for_exit(guard.pid, std::chrono::seconds{10}, exit_status);

                // Drain any remaining log output for debugging shutdown failures.
                if (!exited || !((WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 0) ||
                                 (WIFSIGNALED(exit_status) && WTERMSIG(exit_status) == SIGTERM)))
                {
                    auto const drain = drain_pipe(guard.log_pipe_read);
                    WARN("server log:\n" + drain);
                    WARN("exit_status raw=" + std::to_string(exit_status) +
                         " exited=" + std::string{exited ? "true" : "false"} +
                         " signaled=" + std::string{WIFSIGNALED(exit_status) ? "true" : "false"} +
                         " signal=" + std::to_string(WIFSIGNALED(exit_status) ? WTERMSIG(exit_status) : 0) +
                         " exitcode=" + std::to_string(WIFEXITED(exit_status) ? WEXITSTATUS(exit_status) : -1));
                }

                guard.pid = -1; // already reaped; prevent double-kill in destructor

                REQUIRE(exited);
                // Accept graceful exit (status 0) or termination by the signal we sent.
                auto const clean_exit = (WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 0) ||
                                        (WIFSIGNALED(exit_status) && WTERMSIG(exit_status) == SIGTERM);
                REQUIRE(clean_exit);
            }
        }
    }
}
