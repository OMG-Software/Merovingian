// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/elf_probe.hpp"

#include <cstddef>
#include <span>
#include <tuple>

#include <link.h>

namespace merovingian::platform
{

namespace
{

    void read_dynamic_section(dl_phdr_info const& info, Elf64_Phdr const& dynamic, ElfHardeningResult& result) noexcept
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr) — the loader maps it
        // here
        auto const* const first = reinterpret_cast<Elf64_Dyn const*>(info.dlpi_addr + dynamic.p_vaddr);

        // DT_BIND_NOW and DF_BIND_NOW in DT_FLAGS both encode the -z,now linker
        // flag; different linker versions use either form.
        for (auto const& dyn : std::span{first, static_cast<std::size_t>(dynamic.p_memsz / sizeof(Elf64_Dyn))})
        {
            if (dyn.d_tag == DT_NULL)
                break;
            if (dyn.d_tag == DT_BIND_NOW || (dyn.d_tag == DT_FLAGS && (static_cast<Elf64_Xword>(dyn.d_un.d_val) &
                                                                       static_cast<Elf64_Xword>(DF_BIND_NOW)) != 0U))
            {
                result.has_bind_now = true;
                break;
            }
        }
    }

    // dl_iterate_phdr visits the main program first, so stopping after one call
    // reads the server's own image and not a shared library's.
    auto read_main_program(dl_phdr_info* info, std::size_t /*size*/, void* data) noexcept -> int
    {
        auto& result = *static_cast<ElfHardeningResult*>(data);
        if (info->dlpi_phdr == nullptr || info->dlpi_phnum == 0U)
            return 1;

        // An ET_EXEC binary runs at its link address, so its load offset is 0,
        // and a kernel never maps a PIE there. A wrong answer can only be
        // "not PIE", which refuses startup.
        result.is_pie = info->dlpi_addr != 0U;
        result.probed = true;

        for (auto const& ph : std::span<Elf64_Phdr const>{info->dlpi_phdr, info->dlpi_phnum})
        {
            switch (ph.p_type)
            {
            case PT_GNU_RELRO:
                result.has_relro = true;
                break;
            case PT_GNU_STACK:
                // PF_X set means executable stack — the linker flag is -z,noexecstack.
                result.has_noexec_stack = (ph.p_flags & static_cast<Elf64_Word>(PF_X)) == 0U;
                break;
            case PT_DYNAMIC:
                read_dynamic_section(*info, ph, result);
                break;
            default:
                break;
            }
        }
        return 1;
    }

} // namespace

auto probe_elf_hardening() -> ElfHardeningResult
{
    auto result = ElfHardeningResult{};
    std::ignore = ::dl_iterate_phdr(read_main_program, &result);
    return result;
}

} // namespace merovingian::platform
