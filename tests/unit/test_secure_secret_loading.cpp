// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/platform/file_metadata.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>

#include <sys/stat.h>
#include <unistd.h>

namespace
{
class SecretScratch final
{
public:
    SecretScratch()
    {
        auto pattern = (std::filesystem::temp_directory_path() / "merov-secret-boundary-XXXXXX").string();
        auto const* created = ::mkdtemp(pattern.data());
        if (created == nullptr)
        {
            throw std::runtime_error{"temporary directory unavailable"};
        }
        path = created;
    }
    ~SecretScratch() noexcept
    {
        auto error = std::error_code{};
        std::filesystem::remove_all(path, error);
    }
    std::filesystem::path path;
};

auto write_fixture(std::filesystem::path const& path, std::string_view bytes) -> void
{
    auto stream = std::ofstream{path, std::ios::binary};
    stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    stream.close();
    REQUIRE(::chmod(path.c_str(), 0400) == 0);
}

[[nodiscard]] auto source(std::string_view relative) -> std::string
{
    auto stream = std::ifstream{std::filesystem::path{MEROVINGIAN_TEST_SOURCE_ROOT} / relative};
    REQUIRE(stream.good());
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}
} // namespace

SCENARIO("PostgreSQL bootstrap refuses unchecked secret paths before parsing", "[platform][iso7-loaders]")
{
    GIVEN("a URI file whose contents are deliberately not connection options")
    {
        auto scratch = SecretScratch{};
        auto const file = scratch.path / "connection.uri";
        write_fixture(file, "not-connection-options\n");
        auto const link = scratch.path / "alias.uri";
        std::filesystem::create_symlink(file, link);
        WHEN("bootstrap receives a symlink or unsafe file permissions")
        {
            THEN("each is rejected at the file boundary before the database parser")
            {
                for (auto const mode : std::array<mode_t, 3>{0400, 0600, 0440})
                {
                    REQUIRE(::chmod(file.c_str(), mode) == 0);
                    auto database = merovingian::config::DatabaseConfig{};
                    database.uri_file = (mode == 0400 ? link : file).string();
                    auto const config = merovingian::config::Config{merovingian::config::ServerConfig{},
                                                                    merovingian::config::ListenersConfig{},
                                                                    database,
                                                                    merovingian::config::SecurityConfig{},
                                                                    merovingian::config::ClientRateLimitsConfig{},
                                                                    merovingian::config::LogModulesConfig{}};
                    auto const opened = merovingian::homeserver::bootstrap_local_database(config, {});
                    CHECK_FALSE(opened.opened);
                    CHECK_FALSE(opened.schema_validated);
                }
            }
        }
    }
}

SCENARIO("Secret reads remain bound to the validated descriptor after path replacement", "[platform][iso7-descriptor]")
{
    GIVEN("a secure open descriptor and a replacement at the same pathname")
    {
        auto scratch = SecretScratch{};
        auto const file = scratch.path / "secret";
        write_fixture(file, std::string(32, 'a'));
        auto descriptor = merovingian::platform::open_secure_secret_file(file.string());
        REQUIRE(descriptor.has_value());
        std::filesystem::rename(file, scratch.path / "original");
        write_fixture(file, std::string(32, 'b'));
        WHEN("the validated descriptor is read")
        {
            auto const loaded = merovingian::platform::read_secure_secret_file(*descriptor, 32);
            THEN("the original object is read rather than the replaceable pathname")
            {
                REQUIRE(loaded.has_value());
                auto const original = loaded->bytes().size() == 32 && loaded->bytes().front() == 'a';
                REQUIRE(original);
                REQUIRE(loaded->is_locked());
            }
        }
    }
}

SCENARIO("Secret reads reject special files oversized inputs and embedded NUL paths", "[platform][iso7-descriptor]")
{
    GIVEN("nonregular oversized empty and malformed inputs")
    {
        auto scratch = SecretScratch{};
        auto const file = scratch.path / "secret";
        auto const fifo = scratch.path / "pipe";
        REQUIRE(::mkfifo(fifo.c_str(), 0400) == 0);
        WHEN("the bounded descriptor reader opens them")
        {
            THEN("every invalid input fails without blocking or truncation")
            {
                CHECK_FALSE(merovingian::platform::read_secure_secret_file(fifo.string(), 32).has_value());
                CHECK_FALSE(merovingian::platform::read_secure_secret_file(scratch.path.string(), 32).has_value());
                write_fixture(file, std::string(33, 'a'));
                CHECK_FALSE(merovingian::platform::read_secure_secret_file(file.string(), 32).has_value());
                CHECK_FALSE(
                    merovingian::platform::read_secure_secret_file(file.string() + std::string{"\0suffix", 7}, 32)
                        .has_value());
                std::filesystem::remove(file);
                write_fixture(file, "");
                CHECK_FALSE(merovingian::platform::read_secure_secret_file(file.string(), 32).has_value());
            }
        }
    }
}

SCENARIO("All text secret loaders use the descriptor-bound locked reader", "[platform][iso7-loaders][ops6]")
{
    GIVEN("main and worker startup secret loaders")
    {
        WHEN("the production loader bodies are inspected")
        {
            THEN("they share the bounded validated reader without file stream plaintext buffers")
            {
                for (auto const& entry : std::array{
                         std::pair{"src/homeserver/runtime.cpp",     "auto read_database_uri_file("       },
                         std::pair{"src/homeserver/worker_pool.cpp", "auto read_worker_database_uri_file("},
                         std::pair{"src/main.cpp",                   "auto read_bootstrap_admin_password("}
                })
                {
                    auto const text = source(entry.first);
                    auto const start = text.find(entry.second);
                    REQUIRE(start != std::string::npos);
                    auto const end = text.find("\n}", start);
                    auto const body = text.substr(start, end - start);
                    CHECK(body.find("read_secure_secret_line(") != std::string::npos);
                    CHECK(body.find("std::ifstream") == std::string::npos);
                }
                auto const main = source("src/main.cpp");
                CHECK(
                    main.find(
                        "auto read_bootstrap_admin_password(std::string const& path) -> std::optional<std::string>") ==
                    std::string::npos);
            }
        }
    }
}
