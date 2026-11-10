// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/ElfHardeningResult.hpp"
#include "merovingian/platform/HardeningSelfCheck.hpp"
#include "merovingian/platform/HardeningStatus.hpp"
#include "merovingian/platform/ElfProbe.hpp"

#include <catch2/catch_test_macros.hpp>
#include <link.h>

#include <array>
#include <cstddef>
#include <cstdint>

#ifdef __linux__
#include <fstream>
#include <vector>
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
// pie_check_from_probe — mapping logic
// ---------------------------------------------------------------------------

SCENARIO("PIE check is enabled only when the probe confirms a position-independent image", "[platform][hardening][elf]")
{
    GIVEN("a probe result confirming PIE")
    {
        auto const probe = mp::ElfHardeningResult{.probed = true, .is_pie = true};

        WHEN("the PIE check is derived")
        {
            auto const check = mp::pie_check_from_probe(probe);

            THEN("status is enabled")
            {
                REQUIRE(check.status == mp::HardeningStatus::enabled);
            }
        }
    }

    GIVEN("a probe result where the binary is not PIE")
    {
        auto const probe = mp::ElfHardeningResult{.probed = true, .is_pie = false};

        WHEN("the PIE check is derived")
        {
            auto const check = mp::pie_check_from_probe(probe);

            THEN("status is unknown and says how to fix it")
            {
                REQUIRE(check.status == mp::HardeningStatus::unknown);
                REQUIRE_FALSE(check.note.empty());
            }
        }
    }

    GIVEN("a probe result where the probe did not execute")
    {
        auto const probe = mp::ElfHardeningResult{.probed = false, .is_pie = true};

        WHEN("the PIE check is derived")
        {
            auto const check = mp::pie_check_from_probe(probe);

            THEN("status is unknown")
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

// ---------------------------------------------------------------------------
// read_elf_hardening() — headers no running test binary has
// ---------------------------------------------------------------------------

namespace
{

// OpenBSD's headers do not define PT_GNU_STACK.
constexpr auto k_gnu_stack_segment = Elf64_Word{0x6474E551U};
constexpr auto k_nonzero_load_offset = std::uintptr_t{0x1000U};

[[nodiscard]] auto image_with(Elf64_Phdr const& header, std::array<Elf64_Phdr, 1U>& storage) -> dl_phdr_info
{
    storage[0] = header;
    auto info = dl_phdr_info{};
    info.dlpi_addr = k_nonzero_load_offset;
    info.dlpi_phdr = storage.data();
    info.dlpi_phnum = 1U;
    return info;
}

// Reads a dynamic section through the same path a loaded image takes. The
// load offset is 0 here, so p_vaddr is simply the section's address.
template <std::size_t Count>
[[nodiscard]] auto bind_now_from(std::array<Elf64_Dyn, Count> const& dynamic) -> bool
{
    auto storage = std::array<Elf64_Phdr, 1U>{};
    storage[0].p_type = PT_DYNAMIC;
    storage[0].p_vaddr = reinterpret_cast<std::uintptr_t>(dynamic.data());
    storage[0].p_memsz = sizeof(dynamic);

    auto info = dl_phdr_info{};
    info.dlpi_phdr = storage.data();
    info.dlpi_phnum = 1U;
    return mp::read_elf_hardening(info).has_bind_now;
}

[[nodiscard]] auto dyn_entry(std::int64_t tag, Elf64_Xword value = 0U) -> Elf64_Dyn
{
    auto entry = Elf64_Dyn{};
    entry.d_tag = static_cast<decltype(entry.d_tag)>(tag);
    entry.d_un.d_val = value;
    return entry;
}

} // namespace

SCENARIO("ELF hardening is only reported from headers that prove it", "[platform][hardening][elf]")
{
    GIVEN("an image with no program headers")
    {
        auto const info = dl_phdr_info{};

        WHEN("it is read")
        {
            auto const result = mp::read_elf_hardening(info);

            THEN("the probe did not run, so nothing is confirmed")
            {
                REQUIRE_FALSE(result.probed);
                REQUIRE_FALSE(result.is_pie);
            }
        }
    }

    GIVEN("an image loaded at a non-zero offset with a RELRO segment")
    {
        auto storage = std::array<Elf64_Phdr, 1U>{};
        auto header = Elf64_Phdr{};
        header.p_type = PT_GNU_RELRO;
        auto const info = image_with(header, storage);

        WHEN("it is read")
        {
            auto const result = mp::read_elf_hardening(info);

            THEN("PIE and RELRO are confirmed, and a stack with no segment is not")
            {
                REQUIRE(result.probed);
                REQUIRE(result.is_pie);
                REQUIRE(result.has_relro);
                REQUIRE_FALSE(result.has_noexec_stack);
            }
        }
    }

    GIVEN("an image running at its link address")
    {
        auto storage = std::array<Elf64_Phdr, 1U>{};
        auto info = image_with(Elf64_Phdr{}, storage);
        info.dlpi_addr = 0U;

        WHEN("it is read")
        {
            auto const result = mp::read_elf_hardening(info);

            THEN("it is not PIE")
            {
                REQUIRE(result.probed);
                REQUIRE_FALSE(result.is_pie);
            }
        }
    }

    GIVEN("a stack segment")
    {
        auto storage = std::array<Elf64_Phdr, 1U>{};
        auto header = Elf64_Phdr{};
        header.p_type = k_gnu_stack_segment;

        WHEN("it is not executable")
        {
            header.p_flags = PF_R | PF_W;
            auto const result = mp::read_elf_hardening(image_with(header, storage));

            THEN("the noexec stack is confirmed")
            {
                REQUIRE(result.has_noexec_stack);
            }
        }

        WHEN("it is executable")
        {
            header.p_flags = PF_R | PF_W | PF_X;
            auto const result = mp::read_elf_hardening(image_with(header, storage));

            THEN("the noexec stack is not confirmed")
            {
                REQUIRE_FALSE(result.has_noexec_stack);
            }
        }
    }
}

SCENARIO("BIND_NOW is only reported when the dynamic section asks for it", "[platform][hardening][elf]")
{
    GIVEN("a dynamic section with DT_BIND_NOW")
    {
        auto const dynamic = std::array{dyn_entry(DT_BIND_NOW), dyn_entry(DT_NULL)};

        WHEN("the probe reads it")
        {
            auto const has_bind_now = bind_now_from(dynamic);

            THEN("BIND_NOW is confirmed")
            {
                REQUIRE(has_bind_now);
            }
        }
    }

    GIVEN("a dynamic section whose DT_FLAGS has DF_BIND_NOW set")
    {
        auto const dynamic = std::array{dyn_entry(DT_FLAGS, DF_BIND_NOW), dyn_entry(DT_NULL)};

        WHEN("the probe reads it")
        {
            auto const has_bind_now = bind_now_from(dynamic);

            THEN("BIND_NOW is confirmed")
            {
                REQUIRE(has_bind_now);
            }
        }
    }

    GIVEN("a dynamic section whose DT_FLAGS has every flag except DF_BIND_NOW")
    {
        auto const dynamic =
            std::array{dyn_entry(DT_FLAGS, ~static_cast<Elf64_Xword>(DF_BIND_NOW)), dyn_entry(DT_NULL)};

        WHEN("the probe reads it")
        {
            auto const has_bind_now = bind_now_from(dynamic);

            THEN("BIND_NOW is not confirmed")
            {
                REQUIRE_FALSE(has_bind_now);
            }
        }
    }

    GIVEN("a dynamic section with the request only after the DT_NULL terminator")
    {
        auto const dynamic = std::array{dyn_entry(DT_NULL), dyn_entry(DT_BIND_NOW)};

        WHEN("the probe reads it")
        {
            auto const has_bind_now = bind_now_from(dynamic);

            THEN("it is not part of the section, so BIND_NOW is not confirmed")
            {
                REQUIRE_FALSE(has_bind_now);
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
