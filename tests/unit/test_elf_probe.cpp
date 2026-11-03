// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/elf_probe.hpp"
#include "merovingian/platform/hardening_self_check.hpp"

#include <catch2/catch_test_macros.hpp>

#ifdef __linux__
#include <fstream>
#include <vector>

#include <elf.h>
#endif

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
// probe_elf_hardening() — integration probe
// ---------------------------------------------------------------------------

SCENARIO("ELF hardening probe reads the running test binary on every platform", "[platform][hardening][elf]")
{
    GIVEN("the running test binary")
    {
        WHEN("the ELF probe runs")
        {
            auto const result = mp::probe_elf_hardening();

            THEN("the probe reports it executed successfully")
            {
                // A BSD server used to get an empty result here, which refused
                // it at startup (ADR-0378).
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

#ifdef __linux__
namespace
{

// Reads the same facts from the file on disk, independently of the probe,
// which only looks at the image in memory.
[[nodiscard]] auto read_elf_facts_from_file() -> mp::ElfHardeningResult
{
    auto file = std::ifstream{"/proc/self/exe", std::ios::binary};
    auto ehdr = Elf64_Ehdr{};
    file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));

    auto phdrs = std::vector<Elf64_Phdr>(ehdr.e_phnum);
    file.seekg(static_cast<std::streamoff>(ehdr.e_phoff));
    file.read(reinterpret_cast<char*>(phdrs.data()), static_cast<std::streamsize>(phdrs.size() * sizeof(Elf64_Phdr)));

    auto facts = mp::ElfHardeningResult{.probed = file.good(), .is_pie = ehdr.e_type == ET_DYN};
    for (auto const& ph : phdrs)
    {
        facts.has_relro = facts.has_relro || ph.p_type == PT_GNU_RELRO;
        if (ph.p_type == PT_GNU_STACK)
            facts.has_noexec_stack = (ph.p_flags & static_cast<Elf64_Word>(PF_X)) == 0U;
        if (ph.p_type != PT_DYNAMIC)
            continue;

        auto dyns = std::vector<Elf64_Dyn>(ph.p_filesz / sizeof(Elf64_Dyn));
        file.seekg(static_cast<std::streamoff>(ph.p_offset));
        file.read(reinterpret_cast<char*>(dyns.data()), static_cast<std::streamsize>(dyns.size() * sizeof(Elf64_Dyn)));
        for (auto const& dyn : dyns)
        {
            if (dyn.d_tag == DT_NULL)
                break;
            auto const flags = static_cast<Elf64_Xword>(dyn.d_un.d_val);
            facts.has_bind_now = facts.has_bind_now || dyn.d_tag == DT_BIND_NOW ||
                                 (dyn.d_tag == DT_FLAGS && (flags & static_cast<Elf64_Xword>(DF_BIND_NOW)) != 0U);
        }
    }
    return facts;
}

} // namespace

SCENARIO("ELF hardening probe agrees with the binary's file on disk", "[platform][hardening][elf]")
{
    GIVEN("the facts read from the running binary's file")
    {
        auto const file = read_elf_facts_from_file();
        REQUIRE(file.probed);

        WHEN("the ELF probe reads the image in memory")
        {
            auto const memory = mp::probe_elf_hardening();

            THEN("every fact matches, so a BSD run of the same code can be trusted")
            {
                REQUIRE(memory.is_pie == file.is_pie);
                REQUIRE(memory.has_relro == file.has_relro);
                REQUIRE(memory.has_bind_now == file.has_bind_now);
                REQUIRE(memory.has_noexec_stack == file.has_noexec_stack);
            }
        }
    }
}
#endif // __linux__
