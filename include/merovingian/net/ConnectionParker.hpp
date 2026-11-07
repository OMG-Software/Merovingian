// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <thread>

namespace merovingian::net
{

// Holds connections that are not being served (ADR-0077, audit finding HTTP-1).
//
// A worker thread is a scarce resource: the main request pool has a fixed
// number of them, and a thread that waits on a quiet socket serves nobody. The
// parker owns every connection that is waiting for input — a new connection
// before its first byte, a kept-alive connection between requests — on ONE
// thread, in one poll(2) set. A connection is handed to the dispatch callback
// (which submits it to the pool) only once it is readable, or already has input
// buffered above the socket.
//
// Dispatch is bounded twice:
//   - at most `max_active` connections are out at once (the pool size), so the
//     pool's queue never grows past its workers;
//   - at most `max_active_per_client` of them may share one client key, so one
//     client cannot take every worker. A connection with an empty key is exempt
//     from this second cap (a trusted reverse proxy, which carries many
//     clients over one address) but not from the first.
// A readable connection that is over either cap stays parked and leaves the
// poll set, so it cannot spin the loop; it is dispatched, oldest first, when an
// ActiveShare is released.
//
// Ownership: a connection is owned by exactly one of {the parker, the holder of
// the Dispatched value it was handed out in}. Handing it back is park() again.
//
// Threading and lock order: one internal mutex, a leaf. It is never held while
// calling the dispatch callback, polling, closing a connection or calling any
// Connection method, so a callback may call park() or release shares freely.
//
// Every thread-starting call is explicit (start()): no thread may start before
// process hardening (ADR-0082).
class ConnectionParker final
{
public:
    // A connection the parker can hold. The HTTP layer derives from it; the
    // parker only polls fd() and never reads or writes it. Destroying the
    // object closes the connection.
    class Connection
    {
    public:
        Connection() = default;
        virtual ~Connection() = default;
        Connection(Connection const&) = delete;
        auto operator=(Connection const&) -> Connection& = delete;
        Connection(Connection&&) = delete;
        auto operator=(Connection&&) -> Connection& = delete;

        [[nodiscard]] virtual auto fd() const noexcept -> int = 0;
        // Input already held above the socket (pipelined bytes, decrypted TLS
        // records): the connection is ready without the socket being readable.
        [[nodiscard]] virtual auto has_buffered_input() const noexcept -> bool = 0;
        // Called once, on the parker thread, when the connection's deadline
        // passed before it became readable; it is destroyed straight after.
        virtual auto on_park_expired() noexcept -> void
        {
        }
    };

    struct Limits final
    {
        std::size_t max_active{1U};
        std::size_t max_active_per_client{1U};
    };

    class State;

    // One dispatched connection's claim on the caps. Releasing it (on
    // destruction) frees the slot and wakes the parker, on every path.
    class ActiveShare final
    {
    public:
        ActiveShare() noexcept = default;
        ActiveShare(ActiveShare const&) = delete;
        auto operator=(ActiveShare const&) -> ActiveShare& = delete;
        ActiveShare(ActiveShare&& other) noexcept;
        auto operator=(ActiveShare&& other) noexcept -> ActiveShare&;
        ~ActiveShare();

        // Release now rather than at destruction (a connection handed to a
        // different pool no longer holds a main-pool worker).
        auto release() noexcept -> void;
        [[nodiscard]] auto held() const noexcept -> bool;

    private:
        friend class ConnectionParker;
        ActiveShare(std::shared_ptr<State> state, std::string client_key) noexcept; // SHARED_PTR: reviewed — see State

        std::shared_ptr<State> m_state{}; // SHARED_PTR: reviewed — a share may outlive the parker object
        std::string m_client_key{};
    };

    struct Dispatched final
    {
        std::unique_ptr<Connection> connection{};
        std::string client_key{};
        ActiveShare share{};
    };

    // Runs on the parker thread, without the parker's lock held. It owns the
    // value it is given; dropping it closes the connection.
    using DispatchFn = std::function<void(Dispatched)>;

    ConnectionParker(Limits limits, DispatchFn dispatch);
    ConnectionParker(ConnectionParker const&) = delete;
    auto operator=(ConnectionParker const&) -> ConnectionParker& = delete;
    ConnectionParker(ConnectionParker&&) = delete;
    auto operator=(ConnectionParker&&) -> ConnectionParker& = delete;
    // Stops the thread (request_stop) and closes every parked connection.
    ~ConnectionParker();

    // Opens the wake pipe and starts the thread. False when either failed; the
    // parker then refuses every connection (fail closed).
    [[nodiscard]] auto start() -> bool;

    // Stops the thread, closes every parked connection and refuses later ones.
    // Bounded: the thread is woken at once and does no I/O but close().
    // Idempotent. Must not be called from the dispatch callback.
    auto request_stop() -> void;

    [[nodiscard]] auto running() const -> bool;

    // Takes ownership of `connection`. It is dispatched once readable (or at
    // once when it has buffered input); if it is not readable by `deadline` it
    // is closed. `client_key` empty exempts it from the per-client cap.
    // Returns false, having closed the connection, when the parker is stopped
    // or not started. Safe from any thread.
    auto park(std::unique_ptr<Connection> connection, std::string client_key,
              std::chrono::steady_clock::time_point deadline) -> bool;

    // Connections the parker holds right now (waiting or ready).
    [[nodiscard]] auto parked() const -> std::size_t;
    // Dispatched connections whose share has not been released.
    [[nodiscard]] auto active() const -> std::size_t;
    [[nodiscard]] auto active(std::string const& client_key) const -> std::size_t;

private:
    std::shared_ptr<State> m_state; // SHARED_PTR: reviewed — shared with the thread and every ActiveShare
    std::thread m_thread{};
};

} // namespace merovingian::net
