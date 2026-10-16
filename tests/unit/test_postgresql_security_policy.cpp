// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/database/postgresql_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace
{
[[nodiscard]] auto environment_value(std::string const& name) -> std::optional<std::string>
{
    if (auto const* value = std::getenv(name.c_str()); value != nullptr)
    {
        return std::string{value};
    }
    return std::nullopt;
}

class ScopedEnvironmentVariable final
{
public:
    ScopedEnvironmentVariable(std::string name, std::optional<std::string> const& value)
        : name_{std::move(name)}
        , previous_{environment_value(name_)}
    {
        applied_ = value.has_value() ? ::setenv(name_.c_str(), value->c_str(), 1) == 0 : ::unsetenv(name_.c_str()) == 0;
    }
    ScopedEnvironmentVariable(ScopedEnvironmentVariable const&) = delete;
    auto operator=(ScopedEnvironmentVariable const&) -> ScopedEnvironmentVariable& = delete;
    ScopedEnvironmentVariable(ScopedEnvironmentVariable&&) = delete;
    auto operator=(ScopedEnvironmentVariable&&) -> ScopedEnvironmentVariable& = delete;

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

    [[nodiscard]] auto applied() const noexcept -> bool
    {
        return applied_;
    }

private:
    std::string name_;
    std::optional<std::string> previous_;
    bool applied_{false};
};
} // namespace

SCENARIO("Remote PostgreSQL TLS admission requires an explicit mode even with secure inherited defaults",
         "[database][db8][db8-explicit-mode]")
{
    GIVEN("a securely configured parent environment that is not inherited by the minimal worker")
    {
        WHEN("connection options are admitted before any network access")
        {
            THEN("both formats require the explicit mode and preserve local exemptions and environment state")
            {
                auto const names = std::array<std::string, 4>{"PGHOST", "PGHOSTADDR", "PGSERVICE", "PGSSLMODE"};
                auto const before = std::array{environment_value(names[0]), environment_value(names[1]),
                                               environment_value(names[2]), environment_value(names[3])};
                {
                    auto const host = ScopedEnvironmentVariable{names[0], std::nullopt};
                    auto const address = ScopedEnvironmentVariable{names[1], std::nullopt};
                    auto const service = ScopedEnvironmentVariable{names[2], std::nullopt};
                    auto const inherited_mode = ScopedEnvironmentVariable{names[3], std::string{"verify-full"}};
                    REQUIRE(host.applied());
                    REQUIRE(address.applied());
                    REQUIRE(service.applied());
                    REQUIRE(inherited_mode.applied());

                    auto const destination = std::string{"db.remote.invalid"};
                    auto const bases = std::array{std::string{"postgresql"} + "://" + destination + "/",
                                                  std::string{"host"} + "=" + destination};
                    auto const separators = std::array<std::string, 2>{"?", " "};
                    for (auto i = std::size_t{0}; i < bases.size(); ++i)
                    {
                        INFO("connection format index: " << i);
                        auto const mode_prefix = bases[i] + separators[i] + "sslmode" + "=";
                        auto const control =
                            merovingian::database::validate_postgresql_conninfo(mode_prefix + "verify-full").allowed;
                        REQUIRE(control);
                        auto const missing = merovingian::database::validate_postgresql_conninfo(bases[i]).allowed;
                        CHECK_FALSE(missing);
                        auto const empty = merovingian::database::validate_postgresql_conninfo(mode_prefix).allowed;
                        CHECK_FALSE(empty);
                        for (auto const weaker :
                             std::array<std::string_view, 5>{"disable", "allow", "prefer", "require", "verify-ca"})
                        {
                            auto const allowed =
                                merovingian::database::validate_postgresql_conninfo(mode_prefix + std::string{weaker})
                                    .allowed;
                            CHECK_FALSE(allowed);
                        }
                    }
                    for (auto const destination_local :
                         std::array<std::string_view, 4>{"localhost", "127.0.0.1", "::1", "/run/postgresql"})
                    {
                        auto const local = merovingian::database::validate_postgresql_conninfo(
                                               std::string{"host"} + "=" + std::string{destination_local})
                                               .allowed;
                        CHECK(local);
                    }
                }
                for (auto i = std::size_t{0}; i < names.size(); ++i)
                {
                    auto const restored = environment_value(names[i]) == before[i];
                    CHECK(restored);
                }
            }
        }
    }
}

SCENARIO("Remote PostgreSQL requires authenticated TLS across every destination", "[database][db8]")
{
    GIVEN("libpq URI and key value connection options")
    {
        WHEN("the policy validates every host and address")
        {
            THEN("missing weaker and bypassed TLS are rejected")
            {
                for (auto const conninfo : std::array{
                    "host=db.example.org dbname=matrix", "host=db.example.org sslmode=prefer", "host=db.example.org sslmode=require",
                    "host=localhost,db.example.org", "host=localhost hostaddr=203.0.113.5", "hostaddr=127.0.0.1,203.0.113.5",
                    "postgresql://localhost,db.example.org/matrix", "postgresql://localhost/matrix?hostaddr=203.0.113.5",
                    "postgresql:///matrix?host=db.example.org", "host=db.example.org sslmode=verify-full sslmode=disable",
                    "host=localhost service=external", "host=localhost unknown_option=x", "host='unterminated"})
                {
                    auto const allowed = merovingian::database::validate_postgresql_conninfo(conninfo).allowed;
                    REQUIRE_FALSE(allowed);
                }
                for (auto const conninfo : std::array{
                    "host=db.example.org sslmode=verify-full", "host=127.0.0.1 sslmode=disable", "host=::1 sslmode=disable",
                    "host=/var/run/postgresql sslmode=disable", "host=localhost,127.0.0.2 sslmode=disable",
                    "postgresql://db.example.org/matrix?sslmode=verify-full", "host=localhost hostaddr=127.0.0.1"})
                {
                    auto const allowed = merovingian::database::validate_postgresql_conninfo(conninfo).allowed;
                    REQUIRE(allowed);
                }
            }
        }
    }
}
SCENARIO("PostgreSQL diagnostics never include connection options", "[database][db9]")
{
    GIVEN("spaced quoted escaped and URI credential forms")
    {
        // Construct markers at runtime; assertions only print booleans, never credentials.
        auto const marker = std::string(17, 'q') + " " + std::string(19, 'z');
        auto const samples = std::array<std::string, 4>{
            "host=localhost password = '" + marker + "'", "host=localhost password='" + marker + "'",
            "postgresql://user:" + std::string(17, 'q') + "%20" + std::string(19, 'z') + "@localhost/db",
            "host=localhost options='" + marker + "' password='unfinished"};
        WHEN("diagnostic identities and rejected-open errors are produced")
        {
            THEN("none reproduces either marker or the original connection options")
            {
                for (auto const& conninfo : samples)
                {
                    auto const identity = merovingian::database::redact_postgresql_conninfo(conninfo);
                    auto const safe = identity.find(std::string(17, 'q')) == std::string::npos && identity.find(std::string(19, 'z')) == std::string::npos && identity.find("host=") == std::string::npos;
                    REQUIRE(safe);
                }
                auto const opened = merovingian::database::open_postgresql_connection("host=localhost options='" + marker + "' password='unfinished");
                REQUIRE_FALSE(opened.ok);
                auto const safe = opened.reason.find(std::string(17, 'q')) == std::string::npos && opened.reason.find(std::string(19, 'z')) == std::string::npos;
                REQUIRE(safe);
            }
        }
    }
}
