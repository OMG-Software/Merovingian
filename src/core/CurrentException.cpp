// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/CurrentException.hpp"

#if __has_include(<cxxabi.h>) && defined(__GNUC__)
#include <cxxabi.h>
#define MEROVINGIAN_HAS_CXXABI 1
#else
#define MEROVINGIAN_HAS_CXXABI 0
#endif

namespace merovingian::core
{

auto current_exception_type_name() noexcept -> char const*
{
#if MEROVINGIAN_HAS_CXXABI
    auto const* type = abi::__cxa_current_exception_type();
    return type == nullptr ? "unknown" : type->name();
#else
    return "unknown";
#endif
}

} // namespace merovingian::core
