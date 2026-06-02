// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/net/thread_pool.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <cassert>
#include <exception>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if __has_include(<cxxabi.h>) && defined(__GNUC__)
#include <cxxabi.h>
#define MEROVINGIAN_HAS_CXXABI 1
#else
#define MEROVINGIAN_HAS_CXXABI 0
#endif

namespace merovingian::net
{

namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("thread_pool", event, std::move(fields)));
    }

    // The thread_pool catch-all previously logged only {"action":"swallowed"}.
    // For a security-first homeserver an unhandled exception in a worker is a
    // signal worth keeping; capture the mangled type name and the
    // std::exception message so postmortem can identify the throwing site. We
    // log the raw mangled name (not demangled) to keep this portable across
    // libstdc++ / libc++ / MSVC, and fall back to "unknown" on toolchains
    // without <cxxabi.h>.
    [[nodiscard]] auto current_exception_type_name() noexcept -> char const*
    {
#if MEROVINGIAN_HAS_CXXABI
        auto const* type = abi::__cxa_current_exception_type();
        return type == nullptr ? "unknown" : type->name();
#else
        return "unknown";
#endif
    }

    [[nodiscard]] auto current_exception_message() noexcept -> std::string
    {
        try
        {
            std::rethrow_exception(std::current_exception());
        }
        catch (std::exception const& ex)
        {
            return std::string{ex.what()};
        }
        catch (...)
        {
            return {};
        }
    }

    // Set to true while inside a worker_loop() invocation; request_stop()
    // debug-asserts it is not currently set, catching re-entrancy bugs at
    // test time. Release builds elide the check.
    thread_local bool in_worker = false;

} // namespace

ThreadPool::ThreadPool(std::size_t worker_count)
{
    workers_.reserve(worker_count);
    try
    {
        for (auto i = std::size_t{0U}; i < worker_count; ++i)
        {
            workers_.emplace_back([this] { worker_loop(); });
        }
    }
    catch (...)
    {
        // Join all threads that were successfully created before rethrowing.
        // Without this, joinable threads would call std::terminate on destruction.
        request_stop();
        throw;
    }
    log_diagnostic("pool.started", {{"workers", std::to_string(worker_count), false}});
}

ThreadPool::~ThreadPool()
{
    request_stop();
}

auto ThreadPool::submit(std::function<void()> work) -> bool
{
    {
        auto lock = std::lock_guard{queue_mutex_};
        if (stopping_)
        {
            log_diagnostic("submit.dropped", {{"reason", "pool_stopped", false}});
            return false;
        }
        queue_.push(std::move(work));
    }
    queue_cv_.notify_one();
    return true;
}

// CONTRACT: Worker callbacks must not re-enter the pool (no submit, no
// request_stop, no destructor). Re-entrancy deadlocks request_stop() on the
// join() call below. Debug builds assert the contract via the `in_worker`
// thread_local set in worker_loop(); release builds elide the check.
auto ThreadPool::request_stop() -> void
{
#ifndef NDEBUG
    assert(!in_worker && "ThreadPool::request_stop must not be called from inside a worker callback");
#endif
    {
        auto lock = std::lock_guard{queue_mutex_};
        if (stopping_)
        {
            return;
        }
        stopping_ = true;
    }
    queue_cv_.notify_all();
    for (auto& worker : workers_)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }
}

auto ThreadPool::running() const -> bool
{
    auto lock = std::lock_guard{queue_mutex_};
    return !stopping_;
}

auto ThreadPool::worker_loop() -> void
{
    in_worker = true;
    while (true)
    {
        auto work = std::function<void()>{};
        {
            auto lock = std::unique_lock{queue_mutex_};
            queue_cv_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
            if (stopping_ && queue_.empty())
            {
                return;
            }
            // stopping_ is true and queue is non-empty: drain remaining items.
            work = std::move(queue_.front());
            queue_.pop();
        }
        try
        {
            work();
        }
        catch (...)
        {
            // Log the exception type and message so an unhandled throw in a
            // worker is diagnosable from the log stream. We never let the
            // exception escape the worker loop — std::thread::join would
            // call std::terminate.
            log_diagnostic("worker.exception",
                           {
                               {"action", "swallowed",                  false},
                               {"type",   current_exception_type_name(), false},
                               {"what",   current_exception_message(),   false}
            });
        }
    }
}

} // namespace merovingian::net
