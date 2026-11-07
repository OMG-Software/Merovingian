// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LocalDatabase.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <memory>

namespace merovingian::homeserver
{

// Install the active `LocalDatabase` pointer used by the audit sink
// (see `merovingian::observability::log_diagnostic_audit`). Pass
// `nullptr` to detach. The install is stored in a thread_local so the
// audit-sink call site (which lives in a module below `homeserver/`)
// can route through the same code path without taking a dependency
// on `LocalDatabase`. See `LocalDatabaseScope` for the RAII wrapper
// that binds the install to a runtime's lifetime.
auto install_local_audit_database(LocalDatabase* database) noexcept -> void;

// Test-only accessor for the audit-sink database pointer. Production
// code uses `install_local_audit_database` to set it; tests read it
// back to assert the sink was wired up. The `LocalDatabaseScope`
// dtor uses it to check whether the install still belongs to this
// scope before clearing, so the forward-declaration must precede
// the class definition.
[[nodiscard]] auto current_audit_database() noexcept -> LocalDatabase*;
auto set_current_audit_database(LocalDatabase* database) noexcept -> void;

// RAII scope guard that wires the active `LocalDatabase` into the
// audit sink on construction and *clears* the install on destruction
// (if the install still belongs to this scope). The lifetime is bound
// to the scope object's identity, so any other code that takes over
// the install (a move of the owning runtime, a `reset()` re-seat, or
// a later scope at an inner block) disables the dtor's clear: a
// scope is only allowed to undo an install it actually owns.
//
// The intended owner is `HomeserverRuntime`, which embeds a
// `std::unique_ptr<LocalDatabaseScope> audit_sink_scope` as a member
// so the install is installed on runtime construction and cleared on
// runtime destruction — no call site needs to remember it. Storing
// the `LocalDatabase&` by address means the dtor can compare against
// the current thread_local and avoid clearing an install that
// belongs to a different (e.g. moved-into) scope.
//
// The dtor is a no-op when `current_audit_database() != m_installed`
// so the move ctor of `HomeserverRuntime` can construct a fresh
// scope (re-installing on the new `database`) without the source's
// scope tearing it down. `reset()` re-seats the install when the
// database member is replaced by move-assignment.
class LocalDatabaseScope final
{
public:
    explicit LocalDatabaseScope(LocalDatabase& database) noexcept
        : m_installed{&database}
    {
        install_local_audit_database(m_installed);
    }
    ~LocalDatabaseScope() noexcept
    {
        if (current_audit_database() == m_installed)
        {
            install_local_audit_database(nullptr);
        }
    }

    // Re-seat the scope on a new `LocalDatabase` (e.g. after the
    // owning runtime's `database` member is replaced by a move). The
    // old install is cleared only if it is still the active one; the
    // new install then takes its place. Safe to call multiple times
    // on the same scope object.
    auto reset(LocalDatabase& database) noexcept -> void
    {
        if (current_audit_database() == m_installed)
        {
            install_local_audit_database(nullptr);
        }
        m_installed = &database;
        install_local_audit_database(m_installed);
    }

    LocalDatabaseScope(LocalDatabaseScope const&) = delete;
    auto operator=(LocalDatabaseScope const&) -> LocalDatabaseScope& = delete;
    LocalDatabaseScope(LocalDatabaseScope&&) = delete;
    auto operator=(LocalDatabaseScope&&) -> LocalDatabaseScope& = delete;

private:
    LocalDatabase* m_installed{nullptr};
};

} // namespace merovingian::homeserver
