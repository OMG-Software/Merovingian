// SPDX-License-Identifier: GPL-3.0-or-later

// ISO-1 (security-audit-report-2026-09-29.md): the logger used to start its two
// writer threads in its constructor, so the federation worker's first log line
// created threads before Landlock and the worker seccomp filter were
// installed, and those threads escaped both. The logger now creates no thread
// until start_writers() is called; until then it writes synchronously, so a
// message logged before that point is neither lost nor able to deadlock.
//
// A local SingleLog is used rather than SingleLog::instance(), so each scenario
// observes a logger that has genuinely never started.

#include "../support/process_tasks.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/observability/logger.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <sstream>
#include <streambuf>
#include <string>
#include <system_error>

namespace
{

using merovingian::observability::LogLevel;
using merovingian::observability::SingleLog;

// Redirects std::cout into a string for the lifetime of the object.
class CoutCapture final
{
public:
    CoutCapture()
        : m_previous{std::cout.rdbuf(m_buffer.rdbuf())}
    {
    }
    ~CoutCapture()
    {
        std::cout.rdbuf(m_previous);
    }
    CoutCapture(CoutCapture const&) = delete;
    auto operator=(CoutCapture const&) -> CoutCapture& = delete;
    CoutCapture(CoutCapture&&) = delete;
    auto operator=(CoutCapture&&) -> CoutCapture& = delete;

    [[nodiscard]] auto text() const -> std::string
    {
        return m_buffer.str();
    }

private:
    std::ostringstream m_buffer{};
    std::streambuf* m_previous{nullptr};
};

[[nodiscard]] auto count_occurrences(std::string const& haystack, std::string const& needle) -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto pos = haystack.find(needle); pos != std::string::npos; pos = haystack.find(needle, pos + needle.size()))
    {
        ++count;
    }
    return count;
}

[[nodiscard]] auto read_file(std::filesystem::path const& path) -> std::string
{
    auto in = std::ifstream{path};
    return std::string{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

} // namespace

SCENARIO("The logger starts no thread until its writers are explicitly started", "[observability][logger][iso1]")
{
    GIVEN("a logger that has never been started")
    {
        auto logger = SingleLog{};
        logger.set_console_log_level(LogLevel::off);
        logger.set_file_log_level(LogLevel::off);
        auto const tasks_before = merovingian::tests::count_process_tasks();
        if (tasks_before == 0U)
        {
            SKIP("this platform has no /proc/self/task to count threads with");
        }

        WHEN("it is constructed and used")
        {
            logger.info("iso1", "a message logged before the writers exist");
            logger.critical("iso1", "and a critical one");

            THEN("no thread was created and the logger reports its writers as not started")
            {
                REQUIRE_FALSE(logger.writers_started());
                REQUIRE(merovingian::tests::count_process_tasks() == tasks_before);
            }
        }

        WHEN("its writers are started")
        {
            REQUIRE(logger.start_writers());

            THEN("exactly two writer threads appear, and starting again adds none")
            {
                REQUIRE(logger.writers_started());
                REQUIRE(merovingian::tests::count_process_tasks() == tasks_before + 2U);
                REQUIRE(logger.start_writers());
                REQUIRE(merovingian::tests::count_process_tasks() == tasks_before + 2U);
            }
        }
    }
}

SCENARIO("A message logged before the writers start is not lost", "[observability][logger][iso1]")
{
    GIVEN("a logger with console and file sinks and no writers yet")
    {
        auto const directory = merovingian::tests::temporary_directory() / "merovingian-logger-writers-test";
        std::filesystem::create_directories(directory);
        auto const log_path = directory / "before-start.log";

        auto capture = CoutCapture{};
        auto logger = std::optional<SingleLog>{};
        logger.emplace();
        logger->set_console_log_level(LogLevel::trace);
        logger->set_file_log_level(LogLevel::trace);
        logger->set_default_log_level(LogLevel::trace);
        logger->set_log_file_path(log_path.string());

        WHEN("messages are logged before start_writers, more after it, and the logger is then destroyed")
        {
            for (auto i = 0; i < 20; ++i)
            {
                logger->info("iso1", "early-" + std::to_string(i));
            }
            auto const console_before_start = capture.text();
            REQUIRE(logger->start_writers());
            for (auto i = 0; i < 20; ++i)
            {
                logger->info("iso1", "late-" + std::to_string(i));
            }
            // The destructor stops the writers after they drain their queues.
            logger.reset();
            auto const console = capture.text();
            auto const file = read_file(log_path);
            std::error_code ec;
            std::filesystem::remove_all(directory, ec);

            THEN("the early messages were already on the console before any writer existed")
            {
                REQUIRE(count_occurrences(console_before_start, "early-") == 20U);
            }

            THEN("every early and late message reached both sinks exactly once")
            {
                for (auto i = 0; i < 20; ++i)
                {
                    auto const early = "early-" + std::to_string(i) + "\n";
                    auto const late = "late-" + std::to_string(i) + "\n";
                    REQUIRE(count_occurrences(console, early) == 1U);
                    REQUIRE(count_occurrences(file, early) == 1U);
                    REQUIRE(count_occurrences(console, late) == 1U);
                    REQUIRE(count_occurrences(file, late) == 1U);
                }
            }
        }
    }
}

SCENARIO("A logger that never starts its writers still delivers every message", "[observability][logger][iso1]")
{
    GIVEN("a logger used by a short-lived tool that never calls start_writers")
    {
        auto capture = CoutCapture{};
        {
            auto logger = SingleLog{};
            logger.set_console_log_level(LogLevel::trace);
            logger.set_file_log_level(LogLevel::off);

            WHEN("it logs more messages than the bounded writer queue could hold")
            {
                for (auto i = 0U; i < merovingian::observability::max_log_queue_size + 100U; ++i)
                {
                    logger.info("iso1", "sync-" + std::to_string(i));
                }

                THEN("none was dropped, because nothing is queued")
                {
                    REQUIRE(logger.console_dropped_message_count() == 0U);
                    REQUIRE(count_occurrences(capture.text(), "sync-") ==
                            merovingian::observability::max_log_queue_size + 100U);
                }
            }
        }
    }
}
