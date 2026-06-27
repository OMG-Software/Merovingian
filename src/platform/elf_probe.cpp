// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/elf_probe.hpp"

#ifdef __linux__
#include <cstddef>
#include <cstdint>
#include <vector>

#include <elf.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace merovingian::platform
{

#ifdef __linux__
namespace
{

    // RAII fd guard — no raw close() calls scattered through the probe logic.
    struct FdGuard final
    {
        int fd{-1};
        explicit FdGuard(int f) noexcept
            : fd{f}
        {
        }
        ~FdGuard() noexcept
        {
            if (fd >= 0)
                ::close(fd);
        }
        FdGuard(FdGuard const&) = delete;
        FdGuard& operator=(FdGuard const&) = delete;
        FdGuard(FdGuard&&) = delete;
        FdGuard& operator=(FdGuard&&) = delete;
    };

    [[nodiscard]] auto read_elf_hardening() -> ElfHardeningResult
    {
        auto result = ElfHardeningResult{};

        auto guard = FdGuard{::open("/proc/self/exe", O_RDONLY | O_CLOEXEC)};
        if (guard.fd < 0)
            return result;

        Elf64_Ehdr ehdr{};
        if (::read(guard.fd, &ehdr, sizeof(ehdr)) != static_cast<ssize_t>(sizeof(ehdr)))
            return result;

        // Validate ELF magic and 64-bit class — the server only targets 64-bit.
        if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1 || ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
            ehdr.e_ident[EI_MAG3] != ELFMAG3 || ehdr.e_ident[EI_CLASS] != ELFCLASS64)
            return result;

        if (ehdr.e_phentsize != sizeof(Elf64_Phdr) || ehdr.e_phnum == 0)
            return result;

        if (::lseek(guard.fd, static_cast<off_t>(ehdr.e_phoff), SEEK_SET) < 0)
            return result;

        auto phdrs = std::vector<Elf64_Phdr>(ehdr.e_phnum);
        auto const ph_bytes = static_cast<ssize_t>(ehdr.e_phnum * sizeof(Elf64_Phdr));
        if (::read(guard.fd, phdrs.data(), static_cast<std::size_t>(ph_bytes)) != ph_bytes)
            return result;

        // Probe ran successfully; individual flag fields are updated below.
        result.probed = true;

        Elf64_Off dynamic_offset = 0;
        Elf64_Xword dynamic_filesz = 0;

        for (auto const& ph : phdrs)
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
                dynamic_offset = ph.p_offset;
                dynamic_filesz = ph.p_filesz;
                break;
            default:
                break;
            }
        }

        // Walk the dynamic section looking for DT_BIND_NOW or DF_BIND_NOW in DT_FLAGS.
        // Both encode the -z,now linker flag; different linker versions use either form.
        if (dynamic_offset != 0U && dynamic_filesz >= sizeof(Elf64_Dyn))
        {
            if (::lseek(guard.fd, static_cast<off_t>(dynamic_offset), SEEK_SET) >= 0)
            {
                auto const dyn_count = dynamic_filesz / sizeof(Elf64_Dyn);
                auto dyns = std::vector<Elf64_Dyn>(dyn_count);
                auto const dyn_bytes = static_cast<ssize_t>(dyn_count * sizeof(Elf64_Dyn));
                if (::read(guard.fd, dyns.data(), static_cast<std::size_t>(dyn_bytes)) == dyn_bytes)
                {
                    for (auto const& dyn : dyns)
                    {
                        if (dyn.d_tag == DT_NULL)
                            break;
                        if (dyn.d_tag == DT_BIND_NOW)
                        {
                            result.has_bind_now = true;
                            break;
                        }
                        if (dyn.d_tag == DT_FLAGS &&
                            (static_cast<Elf64_Xword>(dyn.d_un.d_val) & static_cast<Elf64_Xword>(DF_BIND_NOW)) != 0U)
                        {
                            result.has_bind_now = true;
                            break;
                        }
                    }
                }
            }
        }

        return result;
    }

} // namespace
#endif // __linux__

auto probe_elf_hardening() -> ElfHardeningResult
{
#ifdef __linux__
    return read_elf_hardening();
#else
    return {}; // probed = false — ELF /proc probe not available on this platform
#endif
}

} // namespace merovingian::platform
