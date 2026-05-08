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
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace merovingian::observability {

constexpr auto logger_internal_buffer_size = 10240U;
constexpr auto max_log_queue_size = 4096U;

enum class LogLevel {
    trace = 100,
    debug = 200,
    info = 300,
    notice = 400,
    warning = 500,
    error = 600,
    critical = 700,
    off = 1000,
};

class SingleLog final {
public:
    static auto instance() -> SingleLog& {
        static SingleLog logger;
        return logger;
    }

    SingleLog(SingleLog const&) = delete;
    auto operator=(SingleLog const&) -> SingleLog& = delete;
    SingleLog(SingleLog&&) = delete;
    auto operator=(SingleLog&&) -> SingleLog& = delete;

    ~SingleLog() {
        {
            auto lock = std::lock_guard<std::mutex>{console_queue_lock_};
            console_exit_ = true;
        }
        console_cv_.notify_all();

        {
            auto lock = std::lock_guard<std::mutex>{file_queue_lock_};
            file_exit_ = true;
        }
        file_cv_.notify_all();

        if (console_writer_.joinable()) {
            console_writer_.join();
        }
        if (file_writer_.joinable()) {
            file_writer_.join();
        }

        auto lock = std::lock_guard<std::mutex>{file_lock_};
        if (file_out_.is_open()) {
            file_out_ << "\n\n";
            file_out_.close();
        }
    }

    auto set_console_log_level(LogLevel level) noexcept -> void {
        console_log_level_.store(level);
    }

    auto set_file_log_level(LogLevel level) noexcept -> void {
        file_log_level_.store(level);
    }

    auto set_log_file_path(std::string const& path) -> void {
        auto lock = std::lock_guard<std::mutex>{file_lock_};
        file_path_ = path;
        if (file_out_.is_open()) {
            file_out_.close();
        }
        file_out_.open(file_path_, std::ios_base::out);
        if (file_out_.is_open()) {
            file_out_.rdbuf()->pubsetbuf(write_buffer_.data(), logger_internal_buffer_size);
        }
    }

    auto log(LogLevel level, std::string const& line) -> void {
        auto const flush = level >= LogLevel::notice;
        if (console_log_level_.load() <= level) {
            console_log(line, flush);
        }
        if (file_log_level_.load() <= level) {
            file_log(line, flush);
        }
    }

    auto trace(std::string const& module, std::string const& message) -> void {
        log(LogLevel::trace, make_log_line("TRACE", module, message));
    }

    auto debug(std::string const& module, std::string const& message) -> void {
        log(LogLevel::debug, make_log_line("DEBUG", module, message));
    }

    auto info(std::string const& module, std::string const& message) -> void {
        log(LogLevel::info, make_log_line("INFO", module, message));
    }

    auto notice(std::string const& module, std::string const& message) -> void {
        log(LogLevel::notice, make_log_line("NOTICE", module, message));
    }

    auto warning(std::string const& module, std::string const& message) -> void {
        log(LogLevel::warning, make_log_line("WARNING", module, message));
    }

    auto error(std::string const& module, std::string const& message) -> void {
        log(LogLevel::error, make_log_line("ERROR", module, message));
    }

    auto critical(std::string const& module, std::string const& message) -> void {
        log(LogLevel::critical, make_log_line("CRITICAL", module, message));
    }

private:
    struct LogEntry final {
        std::string message{};
        bool flush{false};
    };

    static constexpr std::size_t low_severity_flush_interval = 100U;

    SingleLog()
        : console_writer_{&SingleLog::console_writer, this},
          file_writer_{&SingleLog::file_writer, this} {
    }

    static auto current_date_time() -> std::string {
        auto const now = std::chrono::system_clock::now();
        auto const ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        auto const time_now = std::chrono::system_clock::to_time_t(now);

        auto local = tm{};
        static_cast<void>(localtime_r(&time_now, &local));

        auto date = std::array<char, 32>{};
        auto zone = std::array<char, 10>{};
        auto result = std::array<char, 64>{};

        if (std::strftime(date.data(), date.size(), "%F %T", &local) == 0U) {
            return {};
        }
        if (std::strftime(zone.data(), zone.size(), "%z", &local) == 0U) {
            return {};
        }

        static_cast<void>(std::snprintf(
            result.data(),
            result.size(),
            "%s.%03d %s",
            date.data(),
            static_cast<int>(ms.count()),
            zone.data()
        ));

        return std::string{result.data()};
    }

    static auto make_log_line(std::string const& level, std::string const& module, std::string const& message)
        -> std::string {
        auto stream = std::ostringstream{};
        stream << current_date_time() << "  <" << level << ">  " << module << ":  " << message << '\n';
        return stream.str();
    }

    auto console_log(std::string const& message, bool flush) -> void {
        {
            auto lock = std::lock_guard<std::mutex>{console_queue_lock_};
            if (console_queue_.size() < max_log_queue_size) {
                console_queue_.push_back(LogEntry{message, flush});
            }
        }
        console_cv_.notify_one();
    }

    auto file_log(std::string const& message, bool flush) -> void {
        {
            auto lock = std::lock_guard<std::mutex>{file_queue_lock_};
            if (file_queue_.size() < max_log_queue_size) {
                file_queue_.push_back(LogEntry{message, flush});
            }
        }
        file_cv_.notify_one();
    }

    auto console_writer() -> void {
        while (true) {
            auto entry = LogEntry{};
            {
                auto lock = std::unique_lock<std::mutex>{console_queue_lock_};
                console_cv_.wait(lock, [this] { return console_exit_ || !console_queue_.empty(); });
                if (console_exit_ && console_queue_.empty()) {
                    break;
                }
                entry = std::move(console_queue_.front());
                console_queue_.pop_front();
            }

            std::cout << entry.message;
            if (entry.flush) {
                std::cout.flush();
            }
        }
    }

    auto file_writer() -> void {
        auto low_severity_since_flush = std::size_t{0U};

        while (true) {
            auto entry = LogEntry{};
            {
                auto lock = std::unique_lock<std::mutex>{file_queue_lock_};
                file_cv_.wait(lock, [this] { return file_exit_ || !file_queue_.empty(); });
                if (file_exit_ && file_queue_.empty()) {
                    break;
                }
                entry = std::move(file_queue_.front());
                file_queue_.pop_front();
            }

            auto lock = std::lock_guard<std::mutex>{file_lock_};
            if (file_out_.is_open()) {
                file_out_ << entry.message;
                if (entry.flush) {
                    file_out_.flush();
                    low_severity_since_flush = 0U;
                } else if (++low_severity_since_flush >= low_severity_flush_interval) {
                    file_out_.flush();
                    low_severity_since_flush = 0U;
                }
            }
        }
    }

    std::atomic<LogLevel> console_log_level_{LogLevel::info};
    std::atomic<LogLevel> file_log_level_{LogLevel::trace};
    std::ofstream file_out_{};
    std::string file_path_{};
    std::array<char, logger_internal_buffer_size> write_buffer_{};

    std::mutex console_queue_lock_{};
    std::mutex file_queue_lock_{};
    std::mutex file_lock_{};
    std::condition_variable console_cv_{};
    std::condition_variable file_cv_{};

    std::deque<LogEntry> console_queue_{};
    std::deque<LogEntry> file_queue_{};

    bool console_exit_{false};
    bool file_exit_{false};

    std::thread console_writer_{};
    std::thread file_writer_{};
};

class FunctionTrace final {
public:
    explicit FunctionTrace(std::string function_name)
        : function_name_{std::move(function_name)} {
        auto stream = std::ostringstream{};
        stream << ">>> Entering: " << function_name_;
        SingleLog::instance().trace("FunctionTrace", stream.str());
    }

    FunctionTrace(FunctionTrace const&) = delete;
    auto operator=(FunctionTrace const&) -> FunctionTrace& = delete;
    FunctionTrace(FunctionTrace&&) = delete;
    auto operator=(FunctionTrace&&) -> FunctionTrace& = delete;

    ~FunctionTrace() {
        auto stream = std::ostringstream{};
        stream << "<<< Exiting: " << function_name_;
        SingleLog::instance().trace("FunctionTrace", stream.str());
    }

private:
    std::string function_name_{};
};

template <typename... Args>
auto string_format(std::string const& format, Args&&... args) -> std::string {
    auto const required = std::snprintf(nullptr, 0, format.c_str(), std::forward<Args>(args)...);
    if (required < 0) {
        return {};
    }

    auto buffer = std::vector<char>(static_cast<std::size_t>(required) + 1U);
    static_cast<void>(std::snprintf(
        buffer.data(),
        buffer.size(),
        format.c_str(),
        std::forward<Args>(args)...
    ));

    return std::string{buffer.data(), static_cast<std::size_t>(required)};
}

} // namespace merovingian::observability

#define LOG_FUNCTION_TRACE \
    auto merovingian_function_trace_guard = ::merovingian::observability::FunctionTrace{__func__}

#define LOG_TRACE(message) \
    ::merovingian::observability::SingleLog::instance().trace(__func__, message)

#define LOG_DEBUG(message) \
    ::merovingian::observability::SingleLog::instance().debug(__func__, message)

#define LOG_INFO(message) \
    ::merovingian::observability::SingleLog::instance().info(__func__, message)

#define LOG_NOTICE(message) \
    ::merovingian::observability::SingleLog::instance().notice(__func__, message)

#define LOG_WARNING(message) \
    ::merovingian::observability::SingleLog::instance().warning(__func__, message)

#define LOG_ERROR(message) \
    ::merovingian::observability::SingleLog::instance().error(__func__, message)

#define LOG_CRITICAL(message) \
    ::merovingian::observability::SingleLog::instance().critical(__func__, message)

#define LOGF_TRACE(format, ...) \
    ::merovingian::observability::SingleLog::instance().trace( \
        __func__, \
        ::merovingian::observability::string_format(format, __VA_ARGS__) \
    )

#define LOGF_DEBUG(format, ...) \
    ::merovingian::observability::SingleLog::instance().debug( \
        __func__, \
        ::merovingian::observability::string_format(format, __VA_ARGS__) \
    )

#define LOGF_INFO(format, ...) \
    ::merovingian::observability::SingleLog::instance().info( \
        __func__, \
        ::merovingian::observability::string_format(format, __VA_ARGS__) \
    )

#define LOGF_NOTICE(format, ...) \
    ::merovingian::observability::SingleLog::instance().notice( \
        __func__, \
        ::merovingian::observability::string_format(format, __VA_ARGS__) \
    )

#define LOGF_WARNING(format, ...) \
    ::merovingian::observability::SingleLog::instance().warning( \
        __func__, \
        ::merovingian::observability::string_format(format, __VA_ARGS__) \
    )

#define LOGF_ERROR(format, ...) \
    ::merovingian::observability::SingleLog::instance().error( \
        __func__, \
        ::merovingian::observability::string_format(format, __VA_ARGS__) \
    )

#define LOGF_CRITICAL(format, ...) \
    ::merovingian::observability::SingleLog::instance().critical( \
        __func__, \
        ::merovingian::observability::string_format(format, __VA_ARGS__) \
    )
