// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/elf_probe.hpp"
#include "merovingian/platform/hardening_self_check.hpp"

#include <catch2/catch_test_macros.hpp>

namespace mp = merovingian::platform;

// ---------------------------------------------------------------------------
// linker_hardening_check_from_probe — mapping logic
// ---------------------------------------------------------------------------

SCENARIO("linker hardening check is enabled only when the probe confirms all three ELF flags",
         "[platform][hardening][elf]")
{
    GIVEN("a probe result indicating all three linker-hardening flags are set")
    {
        auto const probe = mp::ElfHardeningResult{
            .probed = true,
            .has_relro = true,
            .has_bind_now = true,
            .has_noexec_stack = true,
        };

        WHEN("the linker hardening check is derived")
        {
            auto const check = mp::linker_hardening_check_from_probe(probe);

            THEN("status is enabled")
            {
                REQUIRE(check.status == mp::HardeningStatus::enabled);
            }
        }
    }

    GIVEN("a probe result where the probe did not execute")
    {
        auto const probe = mp::ElfHardeningResult{.probed = false};

        WHEN("the linker hardening check is derived")
        {
            auto const check = mp::linker_hardening_check_from_probe(probe);

            THEN("status is unknown — cannot verify what the binary has")
            {
                REQUIRE(check.status == mp::HardeningStatus::unknown);
                REQUIRE_FALSE(check.note.empty());
            }
        }
    }

    GIVEN("a probe result where PT_GNU_RELRO is absent")
    {
        auto const probe = mp::ElfHardeningResult{
            .probed = true,
            .has_relro = false,
            .has_bind_now = true,
            .has_noexec_stack = true,
        };

        WHEN("the linker hardening check is derived")
        {
            auto const check = mp::linker_hardening_check_from_probe(probe);

            THEN("status is unknown — could be a static or dev build without -z,relro")
            {
                REQUIRE(check.status == mp::HardeningStatus::unknown);
            }
        }
    }

    GIVEN("a probe result where DT_BIND_NOW is absent")
    {
        auto const probe = mp::ElfHardeningResult{
            .probed = true,
            .has_relro = true,
            .has_bind_now = false,
            .has_noexec_stack = true,
        };

        WHEN("the linker hardening check is derived")
        {
            auto const check = mp::linker_hardening_check_from_probe(probe);

            THEN("status is unknown — full RELRO requires -z,now which static builds omit")
            {
                REQUIRE(check.status == mp::HardeningStatus::unknown);
            }
        }
    }

    GIVEN("a probe result where the noexec stack flag is absent")
    {
        auto const probe = mp::ElfHardeningResult{
            .probed = true,
            .has_relro = true,
            .has_bind_now = true,
            .has_noexec_stack = false,
        };

        WHEN("the linker hardening check is derived")
        {
            auto const check = mp::linker_hardening_check_from_probe(probe);

            THEN("status is unknown — noexecstack not confirmed by probe")
            {
                REQUIRE(check.status == mp::HardeningStatus::unknown);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// relro_check_from_probe — mapping logic
// ---------------------------------------------------------------------------

SCENARIO("RELRO check is enabled only when the probe finds PT_GNU_RELRO", "[platform][hardening][elf]")
{
    GIVEN("a probe result where PT_GNU_RELRO is present")
    {
        auto const probe = mp::ElfHardeningResult{
            .probed = true,
            .has_relro = true,
        };

        WHEN("the RELRO check is derived")
        {
            auto const check = mp::relro_check_from_probe(probe);

            THEN("status is enabled")
            {
                REQUIRE(check.status == mp::HardeningStatus::enabled);
            }
        }
    }

    GIVEN("a probe result where PT_GNU_RELRO is absent")
    {
        auto const probe = mp::ElfHardeningResult{
            .probed = true,
            .has_relro = false,
        };

        WHEN("the RELRO check is derived")
        {
            auto const check = mp::relro_check_from_probe(probe);

            THEN("status is unknown — static or non-hardened build")
            {
                REQUIRE(check.status == mp::HardeningStatus::unknown);
                REQUIRE_FALSE(check.note.empty());
            }
        }
    }

    GIVEN("a probe result where the probe did not execute")
    {
        auto const probe = mp::ElfHardeningResult{.probed = false};

        WHEN("the RELRO check is derived")
        {
            auto const check = mp::relro_check_from_probe(probe);

            THEN("status is unknown")
            {
                REQUIRE(check.status == mp::HardeningStatus::unknown);
            }
        }
    }

    GIVEN("bind-now is set but RELRO is absent")
    {
        auto const probe = mp::ElfHardeningResult{
            .probed = true,
            .has_relro = false,
            .has_bind_now = true,
        };

        WHEN("the RELRO check is derived")
        {
            auto const check = mp::relro_check_from_probe(probe);

            THEN("status is unknown — RELRO is independent of bind-now")
            {
                REQUIRE(check.status == mp::HardeningStatus::unknown);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// probe_elf_hardening() — integration probe (Linux only)
// ---------------------------------------------------------------------------

#ifdef __linux__
SCENARIO("ELF hardening probe executes successfully against the running test binary on Linux",
         "[platform][hardening][elf]")
{
    GIVEN("the running test binary on Linux")
    {
        WHEN("the ELF probe runs")
        {
            auto const result = mp::probe_elf_hardening();

            THEN("the probe reports it executed successfully")
            {
                // The probe must be able to open /proc/self/exe and parse the
                // 64-bit ELF headers of the test binary.
                REQUIRE(result.probed);
            }

            AND_THEN("noexec stack is confirmed because -Wl,-z,noexecstack is in meson.build hardening flags")
            {
                // -Wl,-z,noexecstack is unconditionally in hardening_link_flags
                // when hardening=true (the CI default). The test binary inherits this.
                REQUIRE(result.has_noexec_stack);
            }
        }
    }
}
#endif // __linux__
