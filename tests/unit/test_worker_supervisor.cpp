// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/worker_env.hpp"
#include "merovingian/homeserver/worker_supervisor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <string>
#include <string_view>

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
