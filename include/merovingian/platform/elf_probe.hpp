// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::platform
{

// Results from parsing the running binary's ELF program headers.
// All fields remain false when the probe cannot execute (non-Linux, read
// error, or 32-bit ELF — the server targets 64-bit only).
struct ElfHardeningResult final
{
    bool probed{false};           // true when the probe could open and parse the binary
    bool has_relro{false};        // PT_GNU_RELRO segment present
    bool has_bind_now{false};     // DT_BIND_NOW or DF_BIND_NOW in PT_DYNAMIC
    bool has_noexec_stack{false}; // PT_GNU_STACK present without PF_X
};

// Reads /proc/self/exe on Linux and checks PT_GNU_RELRO, DT_BIND_NOW, and
// PT_GNU_STACK. Returns a zeroed result on all other platforms.
[[nodiscard]] auto probe_elf_hardening() -> ElfHardeningResult;

} // namespace merovingian::platform
