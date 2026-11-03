// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::platform
{

// Results from parsing the running binary's ELF program headers.
// All fields remain false when the probe cannot execute. The server targets
// 64-bit only.
struct ElfHardeningResult final
{
    bool probed{false};           // true when the probe could read the program headers
    bool is_pie{false};           // loaded at a non-zero offset (position-independent executable)
    bool has_relro{false};        // PT_GNU_RELRO segment present
    bool has_bind_now{false};     // DT_BIND_NOW or DF_BIND_NOW in PT_DYNAMIC
    bool has_noexec_stack{false}; // PT_GNU_STACK present without PF_X
};

// Checks PT_GNU_RELRO, DT_BIND_NOW, and PT_GNU_STACK on the running program's
// image in memory, through dl_iterate_phdr. It opens no file, so it works
// inside Capsicum and on OpenBSD, which has no path to the executable (ADR-0378).
[[nodiscard]] auto probe_elf_hardening() -> ElfHardeningResult;

} // namespace merovingian::platform
