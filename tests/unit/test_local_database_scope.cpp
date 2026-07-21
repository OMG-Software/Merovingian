// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |  AUDIT-SCOPE GUARD                                                        |
// |                                                                         |
// |  These scenarios cover the lifetime contract of the `LocalDatabaseScope`|
// |  RAII guard. The guard wires a `LocalDatabase&` into the audit sink on |
// |  construction, clears the install (if still ours) on destruction, and  |
// |  supports re-seating on a different database via `reset()`. The tests  |
// |  exercise the install-on-construction, clear-on-destruction, and the   |
// |  reset re-seat — the three behaviours the runtime relies on.           |
// +-------------------------------------------------------------------------+

#include "merovingian/auth/session.hpp"
#include "merovingian/homeserver/local_services.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <thread>
#include <tuple>
#include <type_traits>

namespace
{

// A test-only stand-in for a real `LocalDatabase` instance. The scope
// guard only ever takes the address of one of these objects, so the
// fields can stay empty — the sink's `database->opened` check is what
// the guard itself is exercising, and we never call it.
[[nodiscard]] auto make_dummy_database() -> merovingian::homeserver::LocalDatabase
{
    return merovingian::homeserver::LocalDatabase{};
}

// Resets the thread_local between scenarios. The scope's dtor also
// resets it (when the install is still ours), but if a scenario ends
// with a non-null prior install left dangling from a manual
// `install_local_audit_database` call, the next scenario would see
// it. Clearing here keeps the test scenarios independent.
struct AuditDatabaseReset
{
    ~AuditDatabaseReset()
    {
        merovingian::homeserver::set_current_audit_database(nullptr);
    }
};

} // namespace

SCENARIO("LocalDatabaseScope installs its database pointer on construction", "[homeserver][audit][scope]")
{
    AuditDatabaseReset const reset{};
    GIVEN("a clean thread_local audit-sink pointer")
    {
        merovingian::homeserver::set_current_audit_database(nullptr);
        REQUIRE(merovingian::homeserver::current_audit_database() == nullptr);

        WHEN("a LocalDatabaseScope is created with a database")
        {
            auto scoped = make_dummy_database();
            auto scope = merovingian::homeserver::LocalDatabaseScope{scoped};

            THEN("the active audit-sink pointer is the scoped database")
            {
                REQUIRE(merovingian::homeserver::current_audit_database() == &scoped);
            }
        }
    }
}

SCENARIO("LocalDatabaseScope clears the install on destruction (to nullptr)", "[homeserver][audit][scope]")
{
    AuditDatabaseReset const reset{};
    GIVEN("a database and a LocalDatabaseScope in an inner block")
    {
        auto scoped = make_dummy_database();
        {
            auto scope = merovingian::homeserver::LocalDatabaseScope{scoped};
            // Sanity: the scope installed the pointer.
            REQUIRE(merovingian::homeserver::current_audit_database() == &scoped);
        } // scope's dtor runs here, clearing the install.

        THEN("the thread_local is cleared to nullptr after the inner block exits")
        {
            REQUIRE(merovingian::homeserver::current_audit_database() == nullptr);
        }
    }
}

SCENARIO("LocalDatabaseScope::reset re-seats the install on a new database", "[homeserver][audit][scope]")
{
    AuditDatabaseReset const reset{};
    GIVEN("a LocalDatabaseScope guarding an initial database")
    {
        auto first = make_dummy_database();
        auto scope = merovingian::homeserver::LocalDatabaseScope{first};
        REQUIRE(merovingian::homeserver::current_audit_database() == &first);

        WHEN("reset is called with a different database")
        {
            auto second = make_dummy_database();
            scope.reset(second);

            THEN("the active audit-sink pointer is the new database")
            {
                REQUIRE(merovingian::homeserver::current_audit_database() == &second);
            }
        }
    }
}

// Regression test for #420: the audit-sink database pointer is thread_local,
// installed by LocalDatabaseScope only on the thread that constructs it
// (the main thread). Production HTTP handlers run on ThreadPool worker
// threads, which never got the install — so the audit sink silently no-oped
// there. This directly exercises the mechanism the fix relies on
// (installing the pointer on whichever thread the callback runs on, exactly
// what ThreadPool's on_thread_start hook now does in main.cpp) rather than
// the ThreadPool wiring itself.
SCENARIO("A worker thread must install the audit-sink database itself, or denials are silently dropped",
         "[homeserver][audit][scope][security]")
{
    AuditDatabaseReset const reset{};
    GIVEN("a database and a registration policy that denies")
    {
        auto database = make_dummy_database();
        database.opened = true;
        auto const denying_policy =
            merovingian::auth::RegistrationPolicy{.enabled = true, .require_token = true, .token_present = false};

        WHEN("registration_policy runs on a thread that never installed the audit database")
        {
            auto worker = std::thread{[&] {
                // This thread's own thread_local slot starts nullptr — no
                // install happened here, mirroring a ThreadPool worker
                // before the #420 fix.
                std::ignore = merovingian::auth::registration_policy(denying_policy);
            }};
            worker.join();

            THEN("the denial is silently dropped: no audit row is recorded")
            {
                REQUIRE(database.audit_events.empty());
            }
        }

        WHEN("registration_policy runs on a thread that installs the audit database first")
        {
            auto worker = std::thread{[&] {
                merovingian::homeserver::install_local_audit_database(&database);
                std::ignore = merovingian::auth::registration_policy(denying_policy);
            }};
            worker.join();

            THEN("the denial is recorded in the audit log")
            {
                REQUIRE_FALSE(database.audit_events.empty());
                REQUIRE(database.audit_events.back().event_type == "registration_policy.denied");
            }
        }
    }
}

SCENARIO("LocalDatabaseScope is non-copyable and non-movable", "[homeserver][audit][scope]")
{
    GIVEN("a LocalDatabaseScope value")
    {
        auto const scoped = make_dummy_database();
        auto const scope =
            merovingian::homeserver::LocalDatabaseScope{const_cast<merovingian::homeserver::LocalDatabase&>(scoped)};

        THEN("copy construction and move construction are deleted")
        {
            // The static_assert below fails to compile if any of the
            // copy or move special members is ever made available.
            // It documents the intent at the type level rather than
            // the runtime level.
            static_assert(!std::is_copy_constructible_v<merovingian::homeserver::LocalDatabaseScope>,
                          "LocalDatabaseScope must not be copy-constructible");
            static_assert(!std::is_copy_assignable_v<merovingian::homeserver::LocalDatabaseScope>,
                          "LocalDatabaseScope must not be copy-assignable");
            static_assert(!std::is_move_constructible_v<merovingian::homeserver::LocalDatabaseScope>,
                          "LocalDatabaseScope must not be move-constructible");
            static_assert(!std::is_move_assignable_v<merovingian::homeserver::LocalDatabaseScope>,
                          "LocalDatabaseScope must not be move-assignable");
            SUCCEED("LocalDatabaseScope is correctly non-copyable and non-movable");
        }
    }
}
