// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/platform/ElfHardeningResult.hpp"

struct dl_phdr_info;

namespace merovingian::platform
{

// Checks PT_GNU_RELRO, DT_BIND_NOW, and PT_GNU_STACK on the running program's
// image in memory, through dl_iterate_phdr. It opens no file, so it works
// inside Capsicum and on OpenBSD, which has no path to the executable (ADR-0378).
[[nodiscard]] auto probe_elf_hardening() -> ElfHardeningResult;

// The probe's reading of one loaded image. Separate so tests can give it headers
// that the running binary does not have.
[[nodiscard]] auto read_elf_hardening(::dl_phdr_info const& info) noexcept -> ElfHardeningResult;

} // namespace merovingian::platform
