// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/homeserver/worker_env.hpp"
#include "merovingian/homeserver/worker_supervisor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace
{

using merovingian::homeserver::WorkerSupervisor;

// RAII guard that sets an env var for the scope of a test and restores the
// prior value (or unsets it) on destruction, so tests do not leak env state.
class EnvGuard
{
public:
    EnvGuard(std::string name, std::string value)
        : name_{std::move(name)}
    {
        if (auto const* prev = ::getenv(name_.c_str()); prev != nullptr)
        {
            prev_ = std::string{prev};
            had_prev_ = true;
        }
        ::setenv(name_.c_str(), value.c_str(), 1);
    }
    ~EnvGuard()
    {
        if (had_prev_)
        {
            ::setenv(name_.c_str(), prev_.c_str(), 1);
        }
        else
        {
            ::unsetenv(name_.c_str());
        }
    }
    EnvGuard(EnvGuard const&) = delete;
    auto operator=(EnvGuard const&) -> EnvGuard& = delete;
    EnvGuard(EnvGuard&&) = delete;
    auto operator=(EnvGuard&&) -> EnvGuard& = delete;

private:
    std::string name_{};
    std::string prev_{};
    bool had_prev_{false};
};

} // namespace

SCENARIO("WorkerSupervisor construction captures shard index and timeout", "[federation][worker-supervisor]")
{
    GIVEN("a supervisor configured for shard 7")
    {
        WHEN("it is constructed without starting")
        {
            auto supervisor = WorkerSupervisor{"/nonexistent/worker", "/nonexistent/config", 30U, 7U};

            THEN("the shard index and timeout are preserved")
            {
                REQUIRE(supervisor.shard_index() == 7U);
                REQUIRE(supervisor.request_timeout() == 30U);
            }
        }
    }
}

SCENARIO("WorkerSupervisor defaults to shard 0 when omitted", "[federation][worker-supervisor]")
{
    GIVEN("a supervisor constructed without a shard argument")
    {
        WHEN("it is constructed")
        {
            auto supervisor = WorkerSupervisor{"/nonexistent/worker", "/nonexistent/config", 30U};

            THEN("shard index defaults to 0")
            {
                REQUIRE(supervisor.shard_index() == 0U);
            }
        }
    }
}

SCENARIO("WorkerSupervisor reports healthy before start", "[federation][worker-supervisor]")
{
    GIVEN("a freshly constructed supervisor")
    {
        WHEN("its health is queried before start()")
        {
            auto supervisor = WorkerSupervisor{"/nonexistent/worker", "/nonexistent/config", 30U, 2U};

            THEN("it reports healthy")
            {
                REQUIRE(supervisor.healthy());
            }
        }
    }
}

SCENARIO("WorkerSupervisor stop is idempotent before start", "[federation][worker-supervisor][lifecycle]")
{
    GIVEN("a freshly constructed supervisor")
    {
        WHEN("stop is called before start and again after")
        {
            auto supervisor = WorkerSupervisor{"/nonexistent/worker", "/nonexistent/config", 30U, 2U};
            supervisor.stop();
            supervisor.stop();

            THEN("the supervisor remains healthy and does not crash")
            {
                REQUIRE(supervisor.healthy());
            }
        }
    }
}

SCENARIO("WorkerSupervisor exposes timeout and shard getters", "[federation][worker-supervisor]")
{
    GIVEN("a supervisor configured with a 45-second timeout and shard 9")
    {
        WHEN("the getters are queried")
        {
            auto supervisor = WorkerSupervisor{"/nonexistent/worker", "/nonexistent/config", 45U, 9U};

            THEN("the original values are returned")
            {
                REQUIRE(supervisor.request_timeout() == 45U);
                REQUIRE(supervisor.shard_index() == 9U);
            }
        }
    }
}

SCENARIO("WorkerSupervisor reports no worker pid before start", "[federation][worker-supervisor][lifecycle]")
{
    GIVEN("a freshly constructed supervisor")
    {
        WHEN("the worker pid is queried before start()")
        {
            auto supervisor = WorkerSupervisor{"/nonexistent/worker", "/nonexistent/config", 30U, 2U};

            THEN("it reports -1 because no child has been spawned")
            {
                REQUIRE(supervisor.worker_pid() == -1);
            }
        }
    }
}

SCENARIO("The worker child environment is allowlisted to PATH only", "[federation][worker-supervisor][security]")
{
    GIVEN("a parent environment containing a secret sentinel and a custom PATH")
    {
        auto const secret = EnvGuard{"MEROVINGIAN_TEST_LEAK_SENTINEL", "super-secret-value"};
        auto const path = EnvGuard{"PATH", "/custom/test/bin"};
        std::ignore = secret;
        std::ignore = path;

        WHEN("the minimal worker env is built")
        {
            auto const env = merovingian::homeserver::build_minimal_worker_env();

            THEN("exactly one PATH entry is present and no other keys")
            {
                REQUIRE(env.entries.size() == 1U);
                REQUIRE(env.entries[0U] == "PATH=/custom/test/bin");
            }
            AND_THEN("the sentinel secret is not present in any entry")
            {
                for (auto const& entry : env.entries)
                {
                    REQUIRE(entry.find("super-secret-value") == std::string::npos);
                    REQUIRE(entry.find("MEROVINGIAN_TEST_LEAK_SENTINEL") == std::string::npos);
                }
            }
            AND_THEN("the argv array is null-terminated for posix_spawn")
            {
                REQUIRE(env.argv.size() == 2U); // one entry + null sentinel
                REQUIRE(env.argv[0U] != nullptr);
                REQUIRE(std::string_view{env.argv[0U]} == "PATH=/custom/test/bin");
                REQUIRE(env.argv[1U] == nullptr);
            }
        }
    }
}

SCENARIO("The worker child environment provides a default PATH when the parent has none",
         "[federation][worker-supervisor][security]")
{
    GIVEN("a parent environment with PATH unset")
    {
        auto const path = EnvGuard{"PATH", ""};
        ::unsetenv("PATH");
        std::ignore = path;

        WHEN("the minimal worker env is built")
        {
            auto const env = merovingian::homeserver::build_minimal_worker_env();

            THEN("a fallback PATH is provided so the child can resolve helpers")
            {
                REQUIRE(env.entries.size() == 1U);
                REQUIRE(env.entries[0U].rfind("PATH=", 0U) == 0U);
                REQUIRE(env.entries[0U].size() > std::string{"PATH="}.size());
                REQUIRE(env.argv.back() == nullptr);
            }
        }
    }
}

// Finding N1 follow-up: the worker key pipe must never be inheritable in the
// parent. main is multithreaded; any posix_spawn elsewhere (another shard's
// restart, the thumbnail decoder) that ran while the read end had FD_CLOEXEC
// cleared would inherit the pipe carrying the IPC auth key. The fd is made
// inheritable only in the child, by posix_spawn_file_actions_adddup2 onto
// kWorkerIpcKeyFd.
SCENARIO("The worker key pipe stays close-on-exec in the parent",
         "[federation][worker-supervisor][security][worker_key_fd]")
{
    GIVEN("32 bytes of IPC auth key material")
    {
        auto key = std::vector<std::uint8_t>(32U);
        for (auto i = std::size_t{0U}; i < key.size(); ++i)
        {
            key[i] = static_cast<std::uint8_t>(i + 1U);
        }

        WHEN("the supervisor prepares the key pipe for a worker spawn")
        {
            auto const read_end = merovingian::homeserver::make_worker_key_pipe(key);

            THEN("the read end is still close-on-exec in the parent")
            {
                auto const flags = ::fcntl(read_end.get(), F_GETFD);
                REQUIRE(flags >= 0);
                REQUIRE((flags & FD_CLOEXEC) != 0);
            }

            THEN("the read end never occupies a fixed child fd number")
            {
                REQUIRE(read_end.get() != merovingian::homeserver::kWorkerIpcFd);
                REQUIRE(read_end.get() != merovingian::homeserver::kWorkerIpcKeyFd);
            }

            THEN("the pipe yields exactly the key bytes followed by end-of-file")
            {
                auto buffer = std::array<std::uint8_t, 64U>{};
                auto const count = ::read(read_end.get(), buffer.data(), buffer.size());
                REQUIRE(count == static_cast<ssize_t>(key.size()));
                REQUIRE(std::vector<std::uint8_t>(buffer.begin(), buffer.begin() + count) == key);
                REQUIRE(::read(read_end.get(), buffer.data(), buffer.size()) == 0);
            }
        }
    }
}

// 0.12.13 audit item 8. With main's stdin closed, socketpair() returns fds 0
// and 3, so the child's end would already be kWorkerIpcFd and the adddup2
// placing it there becomes a same-fd dup2 — which some libcs treat as a no-op
// that leaves FD_CLOEXEC set, starting the worker without its IPC socket. Real
// kernel descriptors, in a forked child so the test binary's own fd table and
// stdin are untouched; the child reports through its exit code.
SCENARIO("The worker IPC socket pair keeps the child's end off the fixed fd numbers even with stdin closed",
         "[federation][worker-supervisor][security][worker_ipc_fd]")
{
    GIVEN("a process whose stdin and every descriptor above stderr are closed")
    {
        WHEN("the supervisor creates the worker's IPC socket pair there")
        {
            auto const pid = ::fork();
            REQUIRE(pid >= 0);
            if (pid == 0)
            {
                merovingian::core::close_all_file_descriptors_except(std::set<int>{});
                std::ignore = ::close(STDIN_FILENO);
                auto code = 0;
                try
                {
                    auto const [server, client] = merovingian::homeserver::make_worker_ipc_socketpair();
                    auto const fixed = std::array<int, 3>{merovingian::homeserver::kWorkerIpcFd,
                                                          merovingian::homeserver::kWorkerIpcKeyFd,
                                                          merovingian::homeserver::kWorkerDbUriFd};
                    if (std::ranges::find(fixed, client.get()) != fixed.end())
                    {
                        code = 10; // the child's end is on a fixed fd number
                    }
                    else if ((::fcntl(client.get(), F_GETFD) & FD_CLOEXEC) == 0 ||
                             (::fcntl(server.get(), F_GETFD) & FD_CLOEXEC) == 0)
                    {
                        code = 11; // an end lost close-on-exec in the parent
                    }
                    else
                    {
                        auto const byte = char{'x'};
                        auto received = char{0};
                        if (::write(server.get(), &byte, 1U) != 1 || ::read(client.get(), &received, 1U) != 1 ||
                            received != 'x')
                        {
                            code = 12; // the ends are not a connected pair
                        }
                    }
                }
                catch (...)
                {
                    code = 13;
                }
                ::_exit(code);
            }

            THEN("the child's end is not on a fixed fd number and both ends are connected and close-on-exec")
            {
                auto status = 0;
                REQUIRE(::waitpid(pid, &status, 0) == pid);
                REQUIRE(WIFEXITED(status));
                // 10: on a fixed fd; 11: lost FD_CLOEXEC; 12: not connected; 13: threw.
                REQUIRE(WEXITSTATUS(status) == 0);
            }
        }
    }
}

SCENARIO("The worker key fd is distinct from the IPC fd and the standard streams",
         "[federation][worker-supervisor][security][worker_key_fd]")
{
    GIVEN("the fixed child fd numbers")
    {
        THEN("the key fd collides with neither stdio nor the IPC socket")
        {
            REQUIRE(merovingian::homeserver::kWorkerIpcKeyFd > 2);
            REQUIRE(merovingian::homeserver::kWorkerIpcKeyFd != merovingian::homeserver::kWorkerIpcFd);
        }
    }
}

SCENARIO("The worker key pipe refuses empty key material", "[federation][worker-supervisor][security][worker_key_fd]")
{
    GIVEN("no key material")
    {
        auto const key = std::vector<std::uint8_t>{};

        WHEN("the supervisor prepares the key pipe")
        {
            THEN("it fails closed instead of handing the worker an empty pipe")
            {
                REQUIRE_THROWS(merovingian::homeserver::make_worker_key_pipe(key));
            }
        }
    }
}
