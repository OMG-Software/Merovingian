// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/AppserviceRegistration.hpp"
#include "merovingian/core/Error.hpp"

#include <optional>

namespace merovingian::appservice
{

// Result of parsing or loading one registration document: either a
// populated `value` (parsing succeeded) or an `error` describing why not.
// Not `std::expected<AppserviceRegistration, core::Error>` — this project's
// toolchain (clang + libstdc++, see docs/dev-environment.md) does not build
// `<expected>` cleanly, and no other module in the codebase uses it, so
// fallible operations here follow the same `optional value + separate
// error` shape used throughout ConfigParser.cpp and AuthService.cpp.
struct AppserviceRegistrationParseResult final
{
    std::optional<AppserviceRegistration> value{};
    core::Error error{};
};

} // namespace merovingian::appservice
