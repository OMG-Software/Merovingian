// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SingleLog by James Chapman, BSD-3-Clause.
#pragma once

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
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
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

class SingleLog final
{
public:
    static auto instance() -> SingleLog&
    {
        static SingleLog logger;
        return logger;
    }

    SingleLog(SingleLog const&) = delete;
    auto operator=(SingleLog const&) -> SingleLog& = delete;
    SingleLog(SingleLog&&) = delete;
    auto operator=(SingleLog&&) -> SingleLog& = delete;

    ~SingleLog()
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

        auto lock = std::lock_guard<std::mutex>{m_file_lock};
        if (m_file_out.is_open())
        {
            m_file_out << "\n\n";
            m_file_out.close();
        }
    }

    auto set_console_log_level(LogLevel level) noexcept -> void
    {
        m_console_log_level.store(level);
    }

    auto set_file_log_level(LogLevel level) noexcept -> void
    {
        m_file_log_level.store(level);
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

    auto log(LogLevel level, std::string const& line) -> void
    {
        auto const flush = level >= LogLevel::notice;
        if (m_console_log_level.load() <= level)
        {
            console_log(line, flush);
        }
        if (m_file_log_level.load() <= level)
        {
            file_log(line, flush);
        }
    }

    auto trace(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::trace, make_log_line("TRACE", module, message));
    }

    auto debug(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::debug, make_log_line("DEBUG", module, message));
    }

    auto info(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::info, make_log_line("INFO", module, message));
    }

    auto notice(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::notice, make_log_line("NOTICE", module, message));
    }

    auto warning(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::warning, make_log_line("WARNING", module, message));
    }

    auto error(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::error, make_log_line("ERROR", module, message));
    }

    auto critical(std::string const& module, std::string const& message) -> void
    {
        log(LogLevel::critical, make_log_line("CRITICAL", module, message));
    }

private:
    struct LogEntry final
    {
        std::string message{};
        bool flush{false};
    };

    SingleLog()
        : m_console_writer{&SingleLog::console_writer, this}
        , m_file_writer{&SingleLog::file_writer, this}
    {
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

    static auto make_log_line(std::string const& level, std::string const& module, std::string const& message)
        -> std::string
    {
        auto stream = std::ostringstream{};
        stream << current_date_time() << "  <" << level << ">  " << module << ":  " << message << '\n';
        return stream.str();
    }

    auto console_log(std::string const& message, bool flush) -> void
    {
        {
            auto lock = std::lock_guard<std::mutex>{m_console_queue_lock};
            if (m_console_queue.size() < max_log_queue_size)
            {
                m_console_queue.push_back(LogEntry{message, flush});
            }
        }
        m_console_cv.notify_one();
    }

    auto file_log(std::string const& message, bool flush) -> void
    {
        {
            auto lock = std::lock_guard<std::mutex>{m_file_queue_lock};
            if (m_file_queue.size() < max_log_queue_size)
            {
                m_file_queue.push_back(LogEntry{message, flush});
            }
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
                std::cout.flush();
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
    std::ofstream m_file_out{};
    std::string m_file_path{};
    std::array<char, logger_internal_buffer_size> m_write_buffer{};

    std::mutex m_console_queue_lock{};
    std::mutex m_file_queue_lock{};
    std::mutex m_file_lock{};
    std::condition_variable m_console_cv{};
    std::condition_variable m_file_cv{};

    std::deque<LogEntry> m_console_queue{};
    std::deque<LogEntry> m_file_queue{};

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

template <typename... Args>
auto string_format(std::string const& format, Args&&... args) -> std::string
{
    auto const required = std::snprintf(nullptr, 0, format.c_str(), std::forward<Args>(args)...);
    if (required < 0)
    {
        return {};
    }

    auto buffer = std::vector<char>(static_cast<std::size_t>(required) + 1U);
    std::ignore = std::snprintf(buffer.data(), buffer.size(), format.c_str(), std::forward<Args>(args)...);

    return std::string{buffer.data(), static_cast<std::size_t>(required)};
}

} // namespace merovingian::observability

#define LOG_FUNCTION_TRACE                                                                                             \
    auto merovingian_function_trace_guard = ::merovingian::observability::FunctionTrace                                \
    {                                                                                                                  \
        __func__                                                                                                       \
    }

#define LOG_TRACE(message) ::merovingian::observability::SingleLog::instance().trace(__func__, message)

#define LOG_DEBUG(message) ::merovingian::observability::SingleLog::instance().debug(__func__, message)

#define LOG_INFO(message) ::merovingian::observability::SingleLog::instance().info(__func__, message)

#define LOG_NOTICE(message) ::merovingian::observability::SingleLog::instance().notice(__func__, message)

#define LOG_WARNING(message) ::merovingian::observability::SingleLog::instance().warning(__func__, message)

#define LOG_ERROR(message) ::merovingian::observability::SingleLog::instance().error(__func__, message)

#define LOG_CRITICAL(message) ::merovingian::observability::SingleLog::instance().critical(__func__, message)

#define LOGF_TRACE(format, ...)                                                                                        \
    ::merovingian::observability::SingleLog::instance().trace(                                                         \
        __func__, ::merovingian::observability::string_format(format, __VA_ARGS__))

#define LOGF_DEBUG(format, ...)                                                                                        \
    ::merovingian::observability::SingleLog::instance().debug(                                                         \
        __func__, ::merovingian::observability::string_format(format, __VA_ARGS__))

#define LOGF_INFO(format, ...)                                                                                         \
    ::merovingian::observability::SingleLog::instance().info(                                                          \
        __func__, ::merovingian::observability::string_format(format, __VA_ARGS__))

#define LOGF_NOTICE(format, ...)                                                                                       \
    ::merovingian::observability::SingleLog::instance().notice(                                                        \
        __func__, ::merovingian::observability::string_format(format, __VA_ARGS__))

#define LOGF_WARNING(format, ...)                                                                                      \
    ::merovingian::observability::SingleLog::instance().warning(                                                       \
        __func__, ::merovingian::observability::string_format(format, __VA_ARGS__))

#define LOGF_ERROR(format, ...)                                                                                        \
    ::merovingian::observability::SingleLog::instance().error(                                                         \
        __func__, ::merovingian::observability::string_format(format, __VA_ARGS__))

#define LOGF_CRITICAL(format, ...)                                                                                     \
    ::merovingian::observability::SingleLog::instance().critical(                                                      \
        __func__, ::merovingian::observability::string_format(format, __VA_ARGS__))
