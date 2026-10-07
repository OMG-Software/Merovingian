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

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <optional>
#include <sstream>
#include <streambuf>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>

#include <sys/wait.h>
#include <unistd.h>

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

// Runs `body` in a forked child, which has only the forking thread, and returns
// what it wrote to its report pipe. The child _exit()s; nothing in it may use
// Catch2, whose assertions belong to the parent.
[[nodiscard]] auto counts_in_single_threaded_child(std::function<void(int)> const& body) -> std::string
{
    int fds[2] = {-1, -1}; // NOLINT(*-avoid-c-arrays)
    REQUIRE(::pipe(fds) == 0);
    auto const pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0)
    {
        ::close(fds[0]);
        body(fds[1]);
        ::close(fds[1]);
        ::_exit(0);
    }
    ::close(fds[1]);
    auto report = std::string{};
    char buffer[256]; // NOLINT(*-avoid-c-arrays)
    for (auto n = ::read(fds[0], buffer, sizeof(buffer)); n > 0; n = ::read(fds[0], buffer, sizeof(buffer)))
    {
        report.append(buffer, static_cast<std::size_t>(n));
    }
    ::close(fds[0]);
    auto status = 0;
    REQUIRE(::waitpid(pid, &status, 0) == pid);
    REQUIRE(WIFEXITED(status));
    return report;
}

auto write_report(int fd, std::string const& text) -> void
{
    std::ignore = ::write(fd, text.data(), text.size());
}

} // namespace

// ISO-1: the logger must start no thread until start_writers(). Counted in a
// forked child, which starts with exactly one thread: the test process's other
// threads, left by earlier tests, can exit while this counts, which made an
// in-process count flaky. The child first proves that thread counting works by
// starting one helper thread; where it does not (no /proc, or NetBSD counting
// only the calling LWP) the scenario skips with a message instead of passing.
SCENARIO("The logger starts no thread until its writers are explicitly started", "[observability][logger][iso1]")
{
    GIVEN("a logger that has never been started, in a child process with one "
          "thread")
    {
        auto const report = counts_in_single_threaded_child([](int report_fd) {
            auto const baseline = merovingian::tests::count_process_tasks();
            {
                auto release = std::atomic<bool>{false};
                auto helper = std::thread{[&release] {
                    while (!release.load())
                    {
                        std::this_thread::yield();
                    }
                }};
                auto const with_helper = merovingian::tests::count_process_tasks();
                release.store(true);
                helper.join();
                if (baseline == 0U || with_helper != baseline + 1U)
                {
                    write_report(report_fd, "SKIP");
                    return;
                }
            }

            auto logger = SingleLog{};
            logger.set_console_log_level(LogLevel::off);
            logger.set_file_log_level(LogLevel::off);
            logger.info("iso1", "a message logged before the writers exist");
            logger.critical("iso1", "and a critical one");
            auto const after_use = merovingian::tests::count_process_tasks();
            auto const started_before_start = logger.writers_started();
            auto const started = logger.start_writers();
            auto const after_start = merovingian::tests::count_process_tasks();
            auto const started_again = logger.start_writers();
            auto const after_again = merovingian::tests::count_process_tasks();
            write_report(report_fd, "before=" + std::to_string(baseline) + " after_use=" + std::to_string(after_use) +
                                        " flag_before=" + std::to_string(started_before_start ? 1 : 0) +
                                        " started=" + std::to_string(started ? 1 : 0) +
                                        " after_start=" + std::to_string(after_start) +
                                        " again=" + std::to_string(started_again ? 1 : 0) +
                                        " after_again=" + std::to_string(after_again) + " ");
        });
        if (report == "SKIP")
        {
            SKIP("this platform's /proc/self/task does not reliably enumerate "
                 "process threads");
        }
        INFO("child report: " << report);
        auto const value = [&report](std::string_view key) {
            auto const token = " " + std::string{key} + "=";
            auto const padded = " " + report;
            auto const start = padded.find(token);
            REQUIRE(start != std::string::npos);
            auto const begin = start + token.size();
            return std::stoull(padded.substr(begin, padded.find(' ', begin) - begin));
        };
        auto const before = value("before");

        WHEN("it is constructed and used")
        {
            THEN("no thread was created and the logger reports its writers as not "
                 "started")
            {
                REQUIRE(value("flag_before") == 0U);
                REQUIRE(value("after_use") == before);
            }
        }

        WHEN("its writers are started")
        {
            THEN("exactly two writer threads appear, and starting again adds none")
            {
                REQUIRE(value("started") == 1U);
                REQUIRE(value("after_start") == before + 2U);
                REQUIRE(value("again") == 1U);
                REQUIRE(value("after_again") == before + 2U);
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

SCENARIO("A CRITICAL log is written synchronously even after writer threads have started",
         "[observability][logger][critical]")
{
    GIVEN("a logger whose writers are running and a file sink")
    {
        auto const directory = merovingian::tests::temporary_directory() / "merovingian-logger-critical-test";
        std::filesystem::create_directories(directory);
        auto const log_path = directory / "critical.log";

        auto console_capture = CoutCapture{};
        auto logger = SingleLog{};
        logger.set_console_log_level(LogLevel::info);
        logger.set_file_log_level(LogLevel::info);
        logger.set_log_file_path(log_path.string());
        REQUIRE(logger.start_writers());

        WHEN("a CRITICAL message is logged and the logger is left running")
        {
            logger.critical("critical-test", "fatal startup refusal");

            THEN("the message is already on the console and in the file before any flush or destruction")
            {
                REQUIRE(count_occurrences(console_capture.text(), "fatal startup refusal") == 1U);
                REQUIRE(count_occurrences(read_file(log_path), "fatal startup refusal") == 1U);
            }
        }

        // The logger destructor stops the writers; cleanup is safe after it runs.
        std::error_code ec;
        std::filesystem::remove_all(directory, ec);
    }
}
