// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/temp_directory.hpp"
#include "merovingian/observability/log_file_sink.hpp"
#include "merovingian/observability/logger.hpp"

#include <catch2/catch_test_macros.hpp>

#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <system_error>
#include <tuple>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace
{
// A private scratch directory removed at scope exit.
class ScratchDirectory final
{
public:
    explicit ScratchDirectory(std::string const& name)
        : m_path{merovingian::tests::temporary_directory() /
                 (name + "-" + std::to_string(::getpid()) + "-" + std::to_string(::time(nullptr)))}
    {
        std::filesystem::remove_all(m_path);
        std::filesystem::create_directories(m_path);
    }
    ~ScratchDirectory()
    {
        auto error = std::error_code{};
        std::ignore = std::filesystem::remove_all(m_path, error);
    }
    ScratchDirectory(ScratchDirectory const&) = delete;
    auto operator=(ScratchDirectory const&) -> ScratchDirectory& = delete;
    ScratchDirectory(ScratchDirectory&&) = delete;
    auto operator=(ScratchDirectory&&) -> ScratchDirectory& = delete;

    [[nodiscard]] auto path() const -> std::filesystem::path const&
    {
        return m_path;
    }

private:
    std::filesystem::path m_path;
};

// Restores the process umask on scope exit.
class UmaskScope final
{
public:
    explicit UmaskScope(mode_t mask) noexcept
        : m_previous{::umask(mask)}
    {
    }
    ~UmaskScope()
    {
        std::ignore = ::umask(m_previous);
    }
    UmaskScope(UmaskScope const&) = delete;
    auto operator=(UmaskScope const&) -> UmaskScope& = delete;
    UmaskScope(UmaskScope&&) = delete;
    auto operator=(UmaskScope&&) -> UmaskScope& = delete;

private:
    mode_t m_previous;
};

[[nodiscard]] auto read_text(std::filesystem::path const& path) -> std::string
{
    auto stream = std::ifstream{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}

auto write_text(std::filesystem::path const& path, std::string const& text) -> void
{
    auto stream = std::ofstream{path, std::ios::binary | std::ios::trunc};
    stream << text;
}

[[nodiscard]] auto permissions_of(std::filesystem::path const& path) -> mode_t
{
    struct stat metadata{};
    REQUIRE(::lstat(path.c_str(), &metadata) == 0);
    return metadata.st_mode & 07777;
}

// Finds this process's descriptor for `path` and reports whether it is
// close-on-exec. Linux exposes descriptors under /proc/self/fd.
[[nodiscard]] auto descriptor_for_is_cloexec(std::filesystem::path const& path) -> std::optional<bool>
{
#ifdef __linux__
    auto const wanted = std::filesystem::canonical(path);
    for (auto const& entry : std::filesystem::directory_iterator{"/proc/self/fd"})
    {
        auto error = std::error_code{};
        auto const target = std::filesystem::read_symlink(entry.path(), error);
        if (!error && target == wanted)
        {
            auto const fd = std::stoi(entry.path().filename().string());
            auto const flags = ::fcntl(fd, F_GETFD);
            return flags >= 0 && (flags & FD_CLOEXEC) != 0;
        }
    }
    return std::nullopt;
#else
    std::ignore = path;
    return true;
#endif
}
} // namespace

SCENARIO("The log file is created owner-only and close-on-exec under a permissive umask", "[observability][iso6]")
{
    GIVEN("a fresh log path and a process umask that would make it world-readable")
    {
        auto const scratch = ScratchDirectory{"merovingian-log-sink-create"};
        auto const path = scratch.path() / "debug.log";
        auto const mask = UmaskScope{0000};

        WHEN("the sink opens it and a line is flushed")
        {
            auto sink = merovingian::observability::LogFileSink{};
            auto const opened = sink.open(path.string());
            sink.write("first line\n");
            sink.flush();

            THEN("the file holds the line, is mode 0600 and its descriptor does not survive exec")
            {
                REQUIRE(opened);
                REQUIRE(sink.is_open());
                REQUIRE(read_text(path) == "first line\n");
                REQUIRE(permissions_of(path) == 0600);
                auto const cloexec = descriptor_for_is_cloexec(path);
                REQUIRE(cloexec.has_value());
                REQUIRE(*cloexec);
            }
        }
    }
}

SCENARIO("An existing log file is tightened and restarted", "[observability][iso6]")
{
    GIVEN("a regular log file this process owns, left world-readable with old content")
    {
        auto const scratch = ScratchDirectory{"merovingian-log-sink-existing"};
        auto const path = scratch.path() / "debug.log";
        write_text(path, "previous run\n");
        REQUIRE(::chmod(path.c_str(), 0644) == 0);

        WHEN("the sink opens it")
        {
            auto sink = merovingian::observability::LogFileSink{};
            auto const opened = sink.open(path.string());
            sink.write("new run\n");
            sink.flush();

            THEN("it is mode 0600 and holds only this run's output, as before")
            {
                REQUIRE(opened);
                REQUIRE(permissions_of(path) == 0600);
                REQUIRE(read_text(path) == "new run\n");
            }
        }
    }
}

SCENARIO("A symlinked log path is refused without touching its target", "[observability][iso6]")
{
    GIVEN("a log path that is a symbolic link to another file")
    {
        auto const scratch = ScratchDirectory{"merovingian-log-sink-symlink"};
        auto const target = scratch.path() / "victim";
        auto const link = scratch.path() / "debug.log";
        write_text(target, "do not truncate\n");
        REQUIRE(::chmod(target.c_str(), 0644) == 0);
        std::filesystem::create_symlink(target, link);

        WHEN("the sink is asked to open the link, and the logger is pointed at it")
        {
            auto sink = merovingian::observability::LogFileSink{};
            auto const opened = sink.open(link.string());
            sink.write("attacker-directed\n");
            sink.flush();

            THEN("nothing is opened and the target keeps its content and mode")
            {
                REQUIRE_FALSE(opened);
                REQUIRE_FALSE(sink.is_open());
                REQUIRE(read_text(target) == "do not truncate\n");
                REQUIRE(permissions_of(target) == 0644);
            }
        }
    }
}

SCENARIO("A log path that is not a regular file is refused without blocking", "[observability][iso6]")
{
    GIVEN("a FIFO with no reader and a directory at the log path")
    {
        auto const scratch = ScratchDirectory{"merovingian-log-sink-special"};
        auto const fifo = scratch.path() / "fifo.log";
        auto const directory = scratch.path() / "dir.log";
        REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);
        std::filesystem::create_directory(directory);

        WHEN("the sink opens each")
        {
            auto fifo_sink = merovingian::observability::LogFileSink{};
            auto directory_sink = merovingian::observability::LogFileSink{};
            auto const fifo_opened = fifo_sink.open(fifo.string());
            auto const directory_opened = directory_sink.open(directory.string());

            THEN("both are refused promptly")
            {
                REQUIRE_FALSE(fifo_opened);
                REQUIRE_FALSE(fifo_sink.is_open());
                REQUIRE_FALSE(directory_opened);
                REQUIRE_FALSE(directory_sink.is_open());
            }
        }
    }
}

SCENARIO("The logger writes nothing through a refused log path", "[observability][iso6]")
{
    GIVEN("a logger whose log file path is a symbolic link")
    {
        auto const scratch = ScratchDirectory{"merovingian-log-sink-logger"};
        auto const target = scratch.path() / "victim";
        auto const link = scratch.path() / "debug.log";
        write_text(target, "original\n");
        std::filesystem::create_symlink(target, link);

        WHEN("the path is set and an error is logged")
        {
            auto logger = merovingian::observability::SingleLog{};
            auto const accepted = logger.set_log_file_path(link.string());
            logger.error("iso6", "must not reach the symlink target");

            THEN("the logger reports the path refused, so the caller can say so, and the target is unchanged")
            {
                CHECK_FALSE(accepted);
                REQUIRE(read_text(target) == "original\n");
            }
        }
    }
}
