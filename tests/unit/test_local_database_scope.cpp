// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |  AUDIT-SCOPE GUARD                                                        |
// |                                                                         |
// |  These scenarios cover the lifetime contract of the `LocalDatabaseScope`|
// |  RAII guard. The guard wires a `LocalDatabase&` into the audit sink on |
// |  construction and restores the prior sink pointer on destruction.      |
// |  The test exercises the swap, the restore-on-scope-exit, and the       |
// |  no-restoration of a null prior pointer.                                |
// +-------------------------------------------------------------------------+

#include "merovingian/homeserver/local_services.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
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

} // namespace

SCENARIO("LocalDatabaseScope installs a pointer and restores the prior install on exit",
         "[homeserver][audit][scope]")
{
    GIVEN("a prior audit-sink install (a sentinel pointer)")
    {
        auto sentinel = make_dummy_database();
        merovingian::homeserver::install_local_audit_database(&sentinel);
        REQUIRE(merovingian::homeserver::current_audit_database() == &sentinel);

        WHEN("a LocalDatabaseScope is created with a different database")
        {
            auto scoped = make_dummy_database();
            {
                auto scope = merovingian::homeserver::LocalDatabaseScope{scoped};

                THEN("the active audit-sink pointer is the scoped one")
                {
                    REQUIRE(merovingian::homeserver::current_audit_database() == &scoped);
                }
            }

            THEN("on scope exit the prior sentinel is restored")
            {
                REQUIRE(merovingian::homeserver::current_audit_database() == &sentinel);
            }
        }
    }
}

SCENARIO("LocalDatabaseScope restores a null prior pointer to a null install", "[homeserver][audit][scope]")
{
    GIVEN("no prior audit-sink install (the thread_local is null)")
    {
        merovingian::homeserver::install_local_audit_database(nullptr);
        REQUIRE(merovingian::homeserver::current_audit_database() == nullptr);

        WHEN("a LocalDatabaseScope is created")
        {
            auto scoped = make_dummy_database();
            {
                auto scope = merovingian::homeserver::LocalDatabaseScope{scoped};

                THEN("the active audit-sink pointer is the scoped one")
                {
                    REQUIRE(merovingian::homeserver::current_audit_database() == &scoped);
                }
            }

            THEN("on scope exit the prior null pointer is restored")
            {
                REQUIRE(merovingian::homeserver::current_audit_database() == nullptr);
            }
        }
    }
}

SCENARIO("LocalDatabaseScope is non-copyable and non-movable", "[homeserver][audit][scope]")
{
    GIVEN("a LocalDatabaseScope value")
    {
        auto const scoped = make_dummy_database();
        auto const scope = merovingian::homeserver::LocalDatabaseScope{const_cast<merovingian::homeserver::LocalDatabase&>(scoped)};

        THEN("copy construction is deleted")
        {
            // The static_assert below fails to compile if the copy
            // constructor is ever made available. It documents the
            // intent at the type level rather than the runtime level.
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
