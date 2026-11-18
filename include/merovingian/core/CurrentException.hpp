// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::core
{

// The mangled type name of the exception being handled (`abi::__cxa_current_exception_type`), for a log line that
// must say what was thrown without its message, which can hold request data (ADR-0803). "unknown" when no exception
// is being handled or the toolchain has no <cxxabi.h>. Not demangled: the helper stays portable across libstdc++ and
// libc++. The text comes from the program's own type information, never from a request. Call it only inside a
// `catch` block.
[[nodiscard]] auto current_exception_type_name() noexcept -> char const*;

} // namespace merovingian::core
