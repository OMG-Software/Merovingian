// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Integration test: secret-file metadata checks at startup.
//
// `validate_existing_secret_files` in src/main.cpp inspects every configured
// secret file for owner-only non-executable regular-file permissions before the
// server opens it. This test spawns the real merovingian-server binary with
// --check-config against temp files with known permissions, so it exercises the
// real kernel metadata path (TOCTOU-safe `lstat`) rather than a mock.

#include "../support/temp_directory.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MEROVINGIAN_TEST_SERVER_BINARY
#define MEROVINGIAN_TEST_SERVER_BINARY ""
#endif

// environ is a POSIX global; declare it for posix_spawn envp building.
extern char** environ; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

namespace
{

[[nodiscard]] auto server_binary() -> std::string_view
{
    return MEROVINGIAN_TEST_SERVER_BINARY;
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
            auto candidate = base / ("merv-secret-files-" + std::to_string(dist(rng)));
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

auto write_master_key_file(std::filesystem::path const& path) -> void
{
    auto output = std::ofstream{path, std::ios::binary};
    auto constexpr key_bytes = std::size_t{32U};
    auto key = std::array<std::uint8_t, key_bytes>{};
    for (auto i = std::size_t{0U}; i < key_bytes; ++i)
    {
        key[i] = static_cast<std::uint8_t>(i);
    }
    output.write(reinterpret_cast<char const*>(key.data()), static_cast<std::streamsize>(key.size()));
}

auto write_minimal_config(std::filesystem::path const& config_path, std::filesystem::path const& db_path,
                          std::string_view master_key_path) -> void
{
    auto f = std::ofstream{config_path};
    f << "server.name=localhost.test\n"
      << "server.public_baseurl=https://localhost.test\n"
      << "listeners.client.bind=127.0.0.1:8008\n"
      << "listeners.client.tls=false\n"
      << "listeners.federation.bind=127.0.0.1:8009\n"
      << "listeners.federation.tls=false\n"
      << "database.backend=sqlite\n"
      << "database.sqlite_path=" << db_path.string() << "\n"
      << "security.secrets.master_key_file=" << master_key_path << "\n";
    // The config file itself must pass is_secure_config_file (no group/other write).
    ::chmod(config_path.c_str(), 0644); // NOLINT(google-runtime-int)
}

// Spawn the server binary with --check-config and return its exit status, or
// -1 if the process could not be spawned or did not exit cleanly.
[[nodiscard]] auto run_check_config(std::string_view binary, std::filesystem::path const& config_path) -> int
{
    auto config_str = config_path.string();
    // argv must be char* (not const char*) per POSIX — spawn treats argv as read-only.
    char* argv[] = {const_cast<char*>(binary.data()), const_cast<char*>("--check-config"),
                    const_cast<char*>(config_str.c_str()), nullptr};

    auto env_ptrs = std::vector<char*>{};
    for (auto** p = environ; *p != nullptr; ++p)
    {
        env_ptrs.push_back(*p);
    }
    env_ptrs.push_back(nullptr);

    auto pid = pid_t{};
    auto const rc = ::posix_spawn(&pid, binary.data(), nullptr, nullptr, argv, env_ptrs.data());
    if (rc != 0)
    {
        return -1;
    }

    auto status = int{};
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    while (std::chrono::steady_clock::now() < deadline)
    {
        auto const wr = ::waitpid(pid, &status, WNOHANG);
        if (wr > 0)
        {
            if (WIFEXITED(status))
            {
                return WEXITSTATUS(status);
            }
            return -1;
        }
        if (wr < 0)
        {
            return -1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }

    ::kill(pid, SIGKILL);                     // NOLINT(cppcoreguidelines-pro-type-vararg)
    std::ignore = ::waitpid(pid, &status, 0); // reap the killed child
    return -1;
}

} // namespace

SCENARIO("Master key file with group-readable permissions is rejected", "[secret_files][security][integration]")
{
    GIVEN("a master key file readable by group and a minimal configuration")
    {
        auto const tmp = TempDir{};
        auto const master_key_path = tmp.path / "group-readable.key";
        auto const config_path = tmp.path / "group-readable.conf";
        auto const db_path = tmp.path / "group-readable.sqlite3";
        write_master_key_file(master_key_path);
        ::chmod(master_key_path.c_str(), 0640); // NOLINT(google-runtime-int)
        write_minimal_config(config_path, db_path, master_key_path.string());

        WHEN("the server checks the configuration")
        {
            auto const exit_code = run_check_config(server_binary(), config_path);

            THEN("config validation fails because the secret file is not owner-only")
            {
                REQUIRE(exit_code == 79);
            }
        }
    }
}

SCENARIO("Master key file with other-readable permissions is rejected", "[secret_files][security][integration]")
{
    GIVEN("a master key file readable by others and a minimal configuration")
    {
        auto const tmp = TempDir{};
        auto const master_key_path = tmp.path / "other-readable.key";
        auto const config_path = tmp.path / "other-readable.conf";
        auto const db_path = tmp.path / "other-readable.sqlite3";
        write_master_key_file(master_key_path);
        ::chmod(master_key_path.c_str(), 0644); // NOLINT(google-runtime-int)
        write_minimal_config(config_path, db_path, master_key_path.string());

        WHEN("the server checks the configuration")
        {
            auto const exit_code = run_check_config(server_binary(), config_path);

            THEN("config validation fails because the secret file is not owner-only")
            {
                REQUIRE(exit_code == 79);
            }
        }
    }
}

SCENARIO("Master key file writable by owner is rejected", "[secret_files][security][integration]")
{
    GIVEN("a master key file that is owner-readable and owner-writable")
    {
        auto const tmp = TempDir{};
        auto const master_key_path = tmp.path / "owner-writable.key";
        auto const config_path = tmp.path / "owner-writable.conf";
        auto const db_path = tmp.path / "owner-writable.sqlite3";
        write_master_key_file(master_key_path);
        ::chmod(master_key_path.c_str(), 0600); // NOLINT(google-runtime-int)
        write_minimal_config(config_path, db_path, master_key_path.string());

        WHEN("the server checks the configuration")
        {
            auto const exit_code = run_check_config(server_binary(), config_path);

            THEN("config validation fails because the secret file must be read-only")
            {
                REQUIRE(exit_code == 79);
            }
        }
    }
}

SCENARIO("Symlinked master key file is rejected", "[secret_files][security][integration]")
{
    GIVEN("a master key file reached through a symlink")
    {
        auto const tmp = TempDir{};
        auto const real_key_path = tmp.path / "real.key";
        auto const symlink_key_path = tmp.path / "symlink.key";
        auto const config_path = tmp.path / "symlink.conf";
        auto const db_path = tmp.path / "symlink.sqlite3";
        write_master_key_file(real_key_path);
        ::chmod(real_key_path.c_str(), 0400); // NOLINT(google-runtime-int)
        std::filesystem::create_symlink(real_key_path.filename(), symlink_key_path);
        write_minimal_config(config_path, db_path, symlink_key_path.string());

        WHEN("the server checks the configuration")
        {
            auto const exit_code = run_check_config(server_binary(), config_path);

            THEN("config validation fails because secret files must be regular files")
            {
                REQUIRE(exit_code == 79);
            }
        }
    }
}

SCENARIO("Owner-only read-only master key file is accepted", "[secret_files][security][integration]")
{
    GIVEN("a master key file with owner-read-only permissions and a minimal configuration")
    {
        auto const tmp = TempDir{};
        auto const master_key_path = tmp.path / "secure.key";
        auto const config_path = tmp.path / "secure.conf";
        auto const db_path = tmp.path / "secure.sqlite3";
        write_master_key_file(master_key_path);
        ::chmod(master_key_path.c_str(), 0400); // NOLINT(google-runtime-int)
        write_minimal_config(config_path, db_path, master_key_path.string());

        WHEN("the server checks the configuration")
        {
            auto const exit_code = run_check_config(server_binary(), config_path);

            THEN("config validation passes")
            {
                REQUIRE(exit_code == 0);
            }
        }
    }
}
