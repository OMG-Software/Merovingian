// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SingleLog by James Chapman, BSD-3-Clause.
#pragma once

#include "merovingian/observability/observability.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <deque>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::observability
{

constexpr auto logger_internal_buffer_size = 10240U;
constexpr auto max_log_queue_size = 4096U;

enum class LogLevel
{
    trace = 100,
    debug = 200,
    info = 300,
    notice = 400,
    warning = 500,
    error = 600,
    critical = 700,
    off = 1000,
};
enum class LogEventSeverity
{
    // Per-event severity. Mirrors LogLevel so the threshold check is
    // uniform across the diagnostic and audit-routing paths. The
    // `log_diagnostic` free function takes one as its fourth arg with
    // a default of `LogEventSeverity::debug`, so the 40+ existing
    // call sites continue to compile unchanged.
    trace = 100,
    debug = 200,
    info = 300,
    notice = 400,
    warning = 500,
    error = 600,
    critical = 700,
};

class LowSeverityFlushPolicy final
{
public:
    using Clock = std::chrono::steady_clock;

    [[nodiscard]] static constexpr auto message_interval() noexcept -> std::size_t
    {
        return 100U;
    }

    [[nodiscard]] static constexpr auto time_interval() noexcept -> Clock::duration
    {
        return std::chrono::seconds{1};
    }

    [[nodiscard]] auto observe_message(bool immediate_flush, Clock::time_point now) noexcept -> bool
    {
        if (immediate_flush)
        {
            mark_flushed();
            return true;
        }

        if (m_pending_count == 0U)
        {
            m_next_deadline = now + time_interval();
        }

        ++m_pending_count;
        if (m_pending_count >= message_interval() || flush_due(now))
        {
            mark_flushed();
            return true;
        }

        return false;
    }

    [[nodiscard]] auto flush_due(Clock::time_point now) const noexcept -> bool
    {
        return m_next_deadline.has_value() && now >= *m_next_deadline;
    }

    auto mark_flushed() noexcept -> void
    {
        m_pending_count = 0U;
        m_next_deadline.reset();
    }

    [[nodiscard]] auto pending_count() const noexcept -> std::size_t
    {
        return m_pending_count;
    }

    [[nodiscard]] auto next_deadline() const noexcept -> std::optional<Clock::time_point>
    {
        return m_next_deadline;
    }

private:
    std::size_t m_pending_count{0U};
    std::optional<Clock::time_point> m_next_deadline{};
};

// L-10 / L-13 (security-audit-report-2026-09.md): tracks bounded-resource
// drop episodes so a caller can emit exactly one warning per contiguous run
// of drops rather than one per dropped item -- flooding a log/audit sink
// during an incident must not itself become the flood. Shared by
// `SingleLog::console_log`/`file_log` (a bounded queue silently discarding
// entries once full) and `local_audit_sink` in
// `src/homeserver/local_services.cpp` (silently no-opping while the
// thread-local database is unset/closed): both are "keep working, but tell
// the operator once" backpressure signals.
class DropEpisodePolicy final
{
public:
    // Call once per attempt. `accepted` is whether the attempt succeeded
    // (the queue had room / the audit sink persisted the event). Returns
    // true exactly once per drop episode: the first failed attempt after a
    // run of successes (or since construction). Every subsequent failed
    // attempt in the same episode returns false, so the caller emits at
    // most one warning per flood; a later success resets the episode so a
    // fresh flood warns again.
    [[nodiscard]] auto observe(bool accepted) noexcept -> bool
    {
        if (accepted)
        {
            m_in_drop_episode = false;
            return false;
        }

        ++m_dropped_total;
        auto const entering_episode = !m_in_drop_episode;
        m_in_drop_episode = true;
        return entering_episode;
    }

    [[nodiscard]] auto dropped_total() const noexcept -> std::size_t
    {
        return m_dropped_total;
    }

    [[nodiscard]] auto in_drop_episode() const noexcept -> bool
    {
        return m_in_drop_episode;
    }

private:
    std::size_t m_dropped_total{0U};
    bool m_in_drop_episode{false};
};

class SingleLog final
{
public:
    // The process-wide logger. Constructing it starts NO thread (ISO-1,
    // ADR-0082): until start_writers() is called every line is written
    // synchronously on the calling thread. A process that hardens itself
    // (Landlock, seccomp) must call start_writers() only after that, because a
    // thread that exists before the ruleset and filter are installed escapes
    // the Landlock ruleset.
    static auto instance() -> SingleLog&
    {
        static SingleLog logger;
        return logger;
    }

    // Constructs an independent logger with no writer threads. The process uses
    // instance(); direct construction exists so tests can observe a logger that
    // has genuinely never started.
    SingleLog() = default;

    SingleLog(SingleLog const&) = delete;
    auto operator=(SingleLog const&) -> SingleLog& = delete;
    SingleLog(SingleLog&&) = delete;
    auto operator=(SingleLog&&) -> SingleLog& = delete;

    ~SingleLog()
    {
        stop_writers();

        auto lock = std::lock_guard<std::mutex>{m_file_lock};
        if (m_file_out.is_open())
        {
            m_file_out << "\n\n";
            m_file_out.close();
        }
    }

    // Starts the console and file writer threads. Until this succeeds every log
    // call writes synchronously, so nothing logged earlier is lost and nothing
    // can deadlock waiting for a writer that does not exist. Idempotent. Returns
    // false, leaving the logger synchronous, when a thread cannot be created
    // (for example under a seccomp filter that forbids clone).
    [[nodiscard]] auto start_writers() -> bool
    {
        auto lock = std::lock_guard<std::mutex>{m_start_lock};
        if (m_writers_started.load(std::memory_order_acquire))
        {
            return true;
        }
        try
        {
            m_console_writer = std::thread{&SingleLog::console_writer, this};
            m_file_writer = std::thread{&SingleLog::file_writer, this};
        }
        catch (std::system_error const&)
        {
            stop_writers();
            return false;
        }
        m_writers_started.store(true, std::memory_order_release);
        return true;
    }

    [[nodiscard]] auto writers_started() const noexcept -> bool
    {
        return m_writers_started.load(std::memory_order_acquire);
    }

    auto set_console_log_level(LogLevel level) noexcept -> void
    {
        m_console_log_level.store(level);
    }

    auto set_file_log_level(LogLevel level) noexcept -> void
    {
        m_file_log_level.store(level);
    }

    // The default level is consulted when the per-logger level map has
    // no entry for a given logger. Defaults to LogLevel::info so a
    // misconfigured or empty `log_modules` config still silences the
    // http_server/sync_notifier noise that motivated this design.
    auto set_default_log_level(LogLevel level) noexcept -> void
    {
        m_default_log_level.store(level);
    }

    // Per-logger level. A module is the first whitespace-delimited
    // token of the diagnostic line (e.g. "http_server", "auth",
    // "sync_notifier"). Empty/blank logger names are treated as the
    // default. The map is read with a shared_mutex so the operator can
    // hot-reload log_modules on SIGHUP without blocking the hot path.
    auto set_module_log_level(std::string_view logger, LogLevel level) -> void
    {
        auto lock = std::lock_guard<std::shared_mutex>{m_module_levels_lock};
        m_module_levels[std::string{logger}] = level;
    }

    [[nodiscard]] auto module_log_level(std::string_view logger) const -> LogLevel
    {
        {
            auto lock = std::shared_lock<std::shared_mutex>{m_module_levels_lock};
            if (auto const it = m_module_levels.find(std::string{logger}); it != m_module_levels.end())
            {
                return it->second;
            }
        }
        return m_default_log_level.load();
    }

    auto set_log_file_path(std::string const& path) -> void
    {
        auto lock = std::lock_guard<std::mutex>{m_file_lock};
        m_file_path = path;
        if (m_file_out.is_open())
        {
            m_file_out.close();
        }
        m_file_out.open(m_file_path, std::ios_base::out);
        if (m_file_out.is_open())
        {
            m_file_out.rdbuf()->pubsetbuf(m_write_buffer.data(), logger_internal_buffer_size);
        }
    }

    auto trace(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::trace, module, make_log_line("TRACE", module, message));
    }

    auto debug(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::debug, module, make_log_line("DEBUG", module, message));
    }

    auto info(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::info, module, make_log_line("INFO", module, message));
    }

    auto notice(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::notice, module, make_log_line("NOTICE", module, message));
    }

    auto warning(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::warning, module, make_log_line("WARNING", module, message));
    }

    auto error(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::error, module, make_log_line("ERROR", module, message));
    }

    auto critical(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::critical, module, make_log_line("CRITICAL", module, message));
    }

    // L-13: total messages discarded because the console/file queue was at
    // `max_log_queue_size` when the entry arrived. An operator-visible
    // counter for the backpressure that used to be silent.
    [[nodiscard]] auto console_dropped_message_count() -> std::size_t
    {
        auto lock = std::lock_guard<std::mutex>{m_console_queue_lock};
        return m_console_drop_policy.dropped_total();
    }

    [[nodiscard]] auto file_dropped_message_count() -> std::size_t
    {
        auto lock = std::lock_guard<std::mutex>{m_file_queue_lock};
        return m_file_drop_policy.dropped_total();
    }

private:
    struct LogEntry final
    {
        std::string message{};
        bool flush{false};
    };

    // Signals both writers to drain their queues and exit, then joins whichever
    // exist. Also resets the exit flags so a later start_writers() can succeed.
    auto stop_writers() noexcept -> void
    {
        {
            auto lock = std::lock_guard<std::mutex>{m_console_queue_lock};
            m_console_exit = true;
        }
        m_console_cv.notify_all();

        {
            auto lock = std::lock_guard<std::mutex>{m_file_queue_lock};
            m_file_exit = true;
        }
        m_file_cv.notify_all();

        if (m_console_writer.joinable())
        {
            m_console_writer.join();
        }
        if (m_file_writer.joinable())
        {
            m_file_writer.join();
        }
        m_writers_started.store(false, std::memory_order_release);

        {
            auto lock = std::lock_guard<std::mutex>{m_console_queue_lock};
            m_console_exit = false;
        }
        {
            auto lock = std::lock_guard<std::mutex>{m_file_queue_lock};
            m_file_exit = false;
        }
    }

    static auto current_date_time() -> std::string
    {
        auto const now = std::chrono::system_clock::now();
        auto const milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        auto const time_now = std::chrono::system_clock::to_time_t(now);

        auto local = tm{};
        std::ignore = localtime_r(&time_now, &local);

        auto date = std::array<char, 32>{};
        auto zone = std::array<char, 10>{};
        auto result = std::array<char, 64>{};

        if (std::strftime(date.data(), date.size(), "%F %T", &local) == 0U)
        {
            return {};
        }
        if (std::strftime(zone.data(), zone.size(), "%z", &local) == 0U)
        {
            return {};
        }

        std::ignore = std::snprintf(result.data(), result.size(), "%s.%03d %s", date.data(),
                                    static_cast<int>(milliseconds.count()), zone.data());

        return std::string{result.data()};
    }

    // AUTH-9: the module and message are escaped here, at the one place every
    // console and file line is composed, so the trailing '\n' is the only line
    // break a record can contain whatever the caller passed in.
    static auto make_log_line(std::string const& level, std::string const& module, std::string const& message)
        -> std::string
    {
        auto stream = std::ostringstream{};
        stream << current_date_time() << "  <" << level << ">  " << escape_log_controls(module) << ":  "
               << escape_log_controls(message) << '\n';
        return stream.str();
    }

    auto log(LogLevel level, std::string_view module, std::string const& line) -> void
    {
        if (static_cast<int>(module_log_level(module)) > static_cast<int>(level))
        {
            return;
        }

        // M-11: every named method (and therefore every LOG_* macro, which
        // calls straight through to these) routes its composed line through
        // the same redaction helper the structured `log_diagnostic` path
        // uses, so a call site cannot bypass redaction by building a plain
        // std::string instead of a StructuredLogField.
        auto const redacted = redact_log_message(line);
        auto const flush = level >= LogLevel::notice;
        // CRITICAL logs precede process exit (hardening refusal, fatal startup
        // errors). After ADR-0082 writer threads start before the final
        // hardening self-check, so a queued CRITICAL message could be lost if
        // the main thread exits before the writer flushes. Write CRITICAL
        // synchronously on the calling thread, exactly as if writers had not
        // started.
        auto const is_critical = level >= LogLevel::critical;
        if (m_console_log_level.load() <= level)
        {
            if (is_critical)
            {
                console_log_sync(redacted);
            }
            else
            {
                console_log(redacted, flush);
            }
        }
        if (m_file_log_level.load() <= level)
        {
            if (is_critical)
            {
                file_log_sync(redacted);
            }
            else
            {
                file_log(redacted, flush);
            }
        }
    }

    // Synchronous console output used by CRITICAL logs so a fatal message is
    // never trapped in the bounded queue when the process is about to exit.
    auto console_log_sync(std::string const& message) -> void
    {
        auto lock = std::lock_guard<std::mutex>{m_console_out_lock};
        std::cout << message;
        std::cout.flush();
    }

    // Synchronous file output used by CRITICAL logs so a fatal message is
    // never trapped in the bounded queue when the process is about to exit.
    auto file_log_sync(std::string const& message) -> void
    {
        auto lock = std::lock_guard<std::mutex>{m_file_lock};
        if (m_file_out.is_open())
        {
            m_file_out << message;
            m_file_out.flush();
        }
    }

    auto console_log(std::string const& message, bool flush) -> void
    {
        if (!m_writers_started.load(std::memory_order_acquire))
        {
            // No writer thread yet (or ever): write on the calling thread.
            auto lock = std::lock_guard<std::mutex>{m_console_out_lock};
            std::cout << message;
            std::cout.flush();
            return;
        }
        auto warn = false;
        {
            auto lock = std::lock_guard<std::mutex>{m_console_queue_lock};
            auto const accepted = m_console_queue.size() < max_log_queue_size;
            if (accepted)
            {
                m_console_queue.push_back(LogEntry{message, flush});
            }
            warn = m_console_drop_policy.observe(accepted);
        }
        m_console_cv.notify_one();
        if (warn)
        {
            // L-13: emitted synchronously on stderr, bypassing the (already
            // full) bounded queue -- routing this warning through the same
            // queue it is reporting as full risks the warning itself being
            // dropped, silently defeating the purpose.
            std::cerr << "WARNING  console log queue full (" << max_log_queue_size
                      << " entries); dropping messages until it drains\n";
        }
    }

    auto file_log(std::string const& message, bool flush) -> void
    {
        if (!m_writers_started.load(std::memory_order_acquire))
        {
            auto lock = std::lock_guard<std::mutex>{m_file_lock};
            if (m_file_out.is_open())
            {
                m_file_out << message;
                m_file_out.flush();
            }
            return;
        }
        auto warn = false;
        {
            auto lock = std::lock_guard<std::mutex>{m_file_queue_lock};
            auto const accepted = m_file_queue.size() < max_log_queue_size;
            if (accepted)
            {
                m_file_queue.push_back(LogEntry{message, flush});
            }
            warn = m_file_drop_policy.observe(accepted);
        }
        if (warn)
        {
            std::cerr << "WARNING  file log queue full (" << max_log_queue_size
                      << " entries); dropping messages until it drains\n";
        }
        m_file_cv.notify_one();
    }

    auto console_writer() -> void
    {
        auto flush_policy = LowSeverityFlushPolicy{};

        while (true)
        {
            auto entry = LogEntry{};
            auto flush_without_entry = false;
            auto exit_without_entry = false;
            {
                auto lock = std::unique_lock<std::mutex>{m_console_queue_lock};
                while (!m_console_exit && m_console_queue.empty())
                {
                    if (auto const deadline = flush_policy.next_deadline(); deadline.has_value())
                    {
                        auto const ready = m_console_cv.wait_until(lock, *deadline, [this] {
                            return m_console_exit || !m_console_queue.empty();
                        });
                        if (!ready && m_console_queue.empty() &&
                            flush_policy.flush_due(LowSeverityFlushPolicy::Clock::now()))
                        {
                            flush_without_entry = true;
                            break;
                        }
                    }
                    else
                    {
                        m_console_cv.wait(lock, [this] {
                            return m_console_exit || !m_console_queue.empty();
                        });
                    }
                }

                if (!flush_without_entry)
                {
                    if (m_console_exit && m_console_queue.empty())
                    {
                        flush_without_entry = flush_policy.pending_count() != 0U;
                        exit_without_entry = true;
                    }
                    else if (!m_console_queue.empty())
                    {
                        entry = std::move(m_console_queue.front());
                        m_console_queue.pop_front();
                    }
                }
            }

            if (flush_without_entry)
            {
                {
                    auto lock = std::lock_guard<std::mutex>{m_console_out_lock};
                    std::cout.flush();
                }
                flush_policy.mark_flushed();
                if (exit_without_entry)
                {
                    break;
                }
                continue;
            }

            if (exit_without_entry)
            {
                break;
            }

            auto lock = std::lock_guard<std::mutex>{m_console_out_lock};
            std::cout << entry.message;
            if (flush_policy.observe_message(entry.flush, LowSeverityFlushPolicy::Clock::now()))
            {
                std::cout.flush();
            }
        }
    }

    auto file_writer() -> void
    {
        auto flush_policy = LowSeverityFlushPolicy{};

        while (true)
        {
            auto entry = LogEntry{};
            auto flush_without_entry = false;
            auto exit_without_entry = false;
            {
                auto lock = std::unique_lock<std::mutex>{m_file_queue_lock};
                while (!m_file_exit && m_file_queue.empty())
                {
                    if (auto const deadline = flush_policy.next_deadline(); deadline.has_value())
                    {
                        auto const ready = m_file_cv.wait_until(lock, *deadline, [this] {
                            return m_file_exit || !m_file_queue.empty();
                        });
                        if (!ready && m_file_queue.empty() &&
                            flush_policy.flush_due(LowSeverityFlushPolicy::Clock::now()))
                        {
                            flush_without_entry = true;
                            break;
                        }
                    }
                    else
                    {
                        m_file_cv.wait(lock, [this] {
                            return m_file_exit || !m_file_queue.empty();
                        });
                    }
                }

                if (!flush_without_entry)
                {
                    if (m_file_exit && m_file_queue.empty())
                    {
                        flush_without_entry = flush_policy.pending_count() != 0U;
                        exit_without_entry = true;
                    }
                    else if (!m_file_queue.empty())
                    {
                        entry = std::move(m_file_queue.front());
                        m_file_queue.pop_front();
                    }
                }
            }

            if (flush_without_entry)
            {
                auto lock = std::lock_guard<std::mutex>{m_file_lock};
                if (m_file_out.is_open())
                {
                    m_file_out.flush();
                }
                flush_policy.mark_flushed();
                if (exit_without_entry)
                {
                    break;
                }
                continue;
            }

            if (exit_without_entry)
            {
                break;
            }

            auto lock = std::lock_guard<std::mutex>{m_file_lock};
            if (m_file_out.is_open())
            {
                m_file_out << entry.message;
                if (flush_policy.observe_message(entry.flush, LowSeverityFlushPolicy::Clock::now()))
                {
                    m_file_out.flush();
                }
            }
            else
            {
                std::ignore = flush_policy.observe_message(entry.flush, LowSeverityFlushPolicy::Clock::now());
            }
        }
    }

    std::atomic<LogLevel> m_console_log_level{LogLevel::info};
    std::atomic<LogLevel> m_file_log_level{LogLevel::trace};
    std::atomic<LogLevel> m_default_log_level{LogLevel::info};
    mutable std::shared_mutex m_module_levels_lock{};
    std::unordered_map<std::string, LogLevel> m_module_levels{};
    std::ofstream m_file_out{};
    std::string m_file_path{};
    std::array<char, logger_internal_buffer_size> m_write_buffer{};

    std::mutex m_console_queue_lock{};
    std::mutex m_file_queue_lock{};
    std::mutex m_file_lock{};
    // Serialises writes to std::cout between the synchronous pre-start path and
    // the console writer thread, so lines never interleave across the switch.
    std::mutex m_console_out_lock{};
    std::mutex m_start_lock{};
    std::atomic<bool> m_writers_started{false};
    std::condition_variable m_console_cv{};
    std::condition_variable m_file_cv{};

    std::deque<LogEntry> m_console_queue{};
    std::deque<LogEntry> m_file_queue{};

    // L-13: guarded by the same mutex as the queue they describe
    // (m_console_queue_lock / m_file_queue_lock respectively) -- every
    // access happens from inside console_log()/file_log() while that lock
    // is held, so these need no synchronization of their own.
    DropEpisodePolicy m_console_drop_policy{};
    DropEpisodePolicy m_file_drop_policy{};

    bool m_console_exit{false};
    bool m_file_exit{false};

    std::thread m_console_writer{};
    std::thread m_file_writer{};
};

class FunctionTrace final
{
public:
    explicit FunctionTrace(std::string function_name)
        : m_function_name{std::move(function_name)}
    {
        auto stream = std::ostringstream{};
        stream << ">>> Entering: " << m_function_name;
        SingleLog::instance().trace("FunctionTrace", stream.str());
    }

    FunctionTrace(FunctionTrace const&) = delete;
    auto operator=(FunctionTrace const&) -> FunctionTrace& = delete;
    FunctionTrace(FunctionTrace&&) = delete;
    auto operator=(FunctionTrace&&) -> FunctionTrace& = delete;

    ~FunctionTrace()
    {
        auto stream = std::ostringstream{};
        stream << "<<< Exiting: " << m_function_name;
        SingleLog::instance().trace("FunctionTrace", stream.str());
    }

private:
    std::string m_function_name{};
};

// +-------------------------------------------------------------------------+
// |  log_diagnostic (0.5.0)                                                    |
// |                                                                         |
// |  These are the public entry points for the ~40 call sites that today     |
// |  construct a `diagnostic_log_summary` and pass it to LOG_DEBUG. They     |
// |  exist so a single call site can (a) declare its per-event severity,     |
// |  (b) auto-route severity >= warning into the `audit_log` table. The      |
// |  severity arg has a default of `LogEventSeverity::debug`, so every      |
// |  existing call site (which today emits at LOG_DEBUG) continues to       |
// |  build unchanged.                                                       |
// |                                                                         |
// |  The audit-routing side is opt-in: only the five high-signal failure    |
// |  call sites (rate_limit.exceeded, login.rejected,                        |
// |  access_token.rejected, request.rejected, registration_policy.denied)   |
// |  Five hand-picked call sites additionally call `append_local_audit`     |
// |  `log_diagnostic` and never write to audit_log.                         |
// +-------------------------------------------------------------------------+

[[nodiscard]] inline auto severity_at_or_above(LogEventSeverity a, LogEventSeverity b) noexcept -> bool
{
    return static_cast<int>(a) >= static_cast<int>(b);
}

// Splits a structured-log message into the first whitespace-delimited token
// (the module/logger name) and the rest. Used by the module-level filter.
[[nodiscard]] inline auto split_logger_from_message(std::string_view message)
    -> std::pair<std::string_view, std::string_view>
{
    auto const ws = message.find(' ');
    if (ws == std::string_view::npos)
    {
        return {message, std::string_view{}};
    }
    return {message.substr(0U, ws), message.substr(ws + 1U)};
}

[[nodiscard]] inline auto severity_to_log_level(LogEventSeverity severity) noexcept -> LogLevel
{
    return static_cast<LogLevel>(static_cast<int>(severity));
}

// Build the message body for a diagnostic log line: "event=<event> key=value ...".
// The module name and level header are added by the SingleLog named methods via
// make_log_line, so they must not be included here.
[[nodiscard]] inline auto diagnostic_message(std::string_view event, std::vector<StructuredLogField> const& fields)
    -> std::string
{
    auto msg = std::string{"event="} + std::string{event};
    for (auto const& field : fields)
    {
        msg += " " + field.key + "=" + redact_log_value(field);
    }
    return msg;
}

// Public free-function entry point. Emits a properly formatted log line at the
// requested severity using the logger name as the module, so the output is:
//   <timestamp>  <LEVEL>  <logger>:  event=<event> key=value ...
// Every existing call site omits the severity arg so it defaults to debug.
inline auto log_diagnostic(std::string_view logger, std::string_view event,
                           std::vector<StructuredLogField> const& fields = {},
                           LogEventSeverity severity = LogEventSeverity::debug) -> void
{
    auto const mod = std::string{logger};
    auto const msg = diagnostic_message(event, fields);
    auto& log = SingleLog::instance();
    switch (severity)
    {
    case LogEventSeverity::trace:
        log.trace(mod, msg);
        break;
    case LogEventSeverity::debug:
        log.debug(mod, msg);
        break;
    case LogEventSeverity::info:
        log.info(mod, msg);
        break;
    case LogEventSeverity::notice:
        log.notice(mod, msg);
        break;
    case LogEventSeverity::warning:
        log.warning(mod, msg);
        break;
    case LogEventSeverity::error:
        log.error(mod, msg);
        break;
    case LogEventSeverity::critical:
        log.critical(mod, msg);
        break;
    }
}

// +-------------------------------------------------------------------------+
// |  Audit-routing sink (0.5.0)                                              |
// |                                                                         |
// |  The `log_diagnostic_audit` helper below emits the diagnostic line and,  |
// |  when severity is at or above `warning`, invokes the registered audit    |
// |  sink with the audit row fields. The sink is a function pointer set by  |
// |  the homeserver at startup; the default sink is a no-op. The reason     |
// |  this lives here (in `observability/`) rather than `homeserver/` is the |
// |  dependency direction: the `auth::registration_policy` function wants to |
// |  call it, but `auth/` is below `homeserver/` in the module stack and    |
// |  must not depend on `homeserver/`. The sink indirection keeps the       |
// |  helper in the lower layer without dragging `LocalDatabase` into every  |
// |  module that wants audit routing.                                       |
// +-------------------------------------------------------------------------+

struct AuditSinkFields final
{
    AuditCategory category{AuditCategory::auth};
    std::string_view event_type{};
    std::string_view actor{};
    std::string_view target{};
    std::string_view reason{};
};

using AuditSink = auto (*)(AuditSinkFields const&) -> void;

// Default no-op sink. The homeserver installs a real one at startup
// that calls `append_local_audit`; modules below `homeserver/` see
// only this default and never touch the database directly.
inline auto default_audit_sink(AuditSinkFields const& /*fields*/) -> void
{
}

// L-09 (security-audit-report-2026-09.md): `set_audit_sink()` writes during
// thread startup while `log_diagnostic_audit()` reads from arbitrary
// threads, with no `std::atomic`/mutex/happens-before edge between them.
// A plain function pointer is a trivially-copyable pointer-sized value, so
// `std::atomic<AuditSink>` is lock-free on every platform this project
// targets -- the read path (`log_diagnostic_audit`, on the hot path of
// every warning-or-above diagnostic) stays a single relaxed-cost atomic
// load, no lock acquired.
inline auto the_audit_sink() noexcept -> std::atomic<AuditSink>&
{
    static auto sink = std::atomic<AuditSink>{&default_audit_sink};
    return sink;
}

inline auto set_audit_sink(AuditSink sink) noexcept -> void
{
    the_audit_sink().store(sink, std::memory_order_release);
}

inline auto log_diagnostic_audit(std::string_view logger, std::string_view event,
                                 std::vector<StructuredLogField> const& fields, LogEventSeverity severity,
                                 AuditSinkFields const& audit_fields) -> void
{
    log_diagnostic(logger, event, fields, severity);
    if (static_cast<int>(severity) >= static_cast<int>(LogEventSeverity::warning))
    {
        the_audit_sink().load(std::memory_order_acquire)(audit_fields);
    }
}

} // namespace merovingian::observability

#define LOG_FUNCTION_TRACE                                                                                             \
    auto merovingian_function_trace_guard = ::merovingian::observability::FunctionTrace                                \
    {                                                                                                                  \
        __func__                                                                                                       \
    }

#define LOG_DEBUG(message) ::merovingian::observability::SingleLog::instance().debug(__func__, message)

#define LOG_INFO(message) ::merovingian::observability::SingleLog::instance().info(__func__, message)

#define LOG_NOTICE(message) ::merovingian::observability::SingleLog::instance().notice(__func__, message)

#define LOG_WARNING(message) ::merovingian::observability::SingleLog::instance().warning(__func__, message)

#define LOG_ERROR(message) ::merovingian::observability::SingleLog::instance().error(__func__, message)

#define LOG_CRITICAL(message) ::merovingian::observability::SingleLog::instance().critical(__func__, message)

// L-12 (security-audit-report-2026-09.md): the LOGF_* macros and the
// `string_format` helper they built on (a `std::string const&` forwarded
// straight into `std::snprintf` as the format argument -- CWE-134, a
// type-unsafe/format-string API) were unused anywhere in `src/`. Deleted
// outright rather than deprecated: there is no call site to migrate, and a
// deleted API cannot be reintroduced by accident the way a `[[deprecated]]`
// one can. Use `LOG_*` (plain std::string, redacted via M-11's
// `redact_log_message`) or `log_diagnostic`/`StructuredLogField` instead.
