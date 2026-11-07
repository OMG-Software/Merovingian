// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <memory>
#include <regex>
#include <string>

namespace merovingian::appservice
{

// One entry of a `namespaces.{users,aliases,rooms}` array (Matrix v1.19
// Application Service API §Registration). `regex` is a POSIX regular
// expression, matched over the whole identifier as `namespace_matches()`
// below describes, but through the compiled form held here. `exclusive` marks
// this namespace as reserved for this appservice: no other appservice or
// human user may create/delete entities matching it.
//
// The pattern is compiled once, when the namespace is built (registration
// load), and every copy shares that compiled form: the interest check runs per
// event, per registration and per room member while runtime.mutex is held, so
// compiling per match is not an option (security audit run-1). `compiled` is
// null when the pattern does not compile; such a namespace matches nothing.
// The pattern is private and set only by the constructor, so it can never
// drift from its compiled form.
class Namespace final
{
public:
    Namespace() = default;
    Namespace(bool exclusive_value, std::string regex_value);

    [[nodiscard]] auto regex() const noexcept -> std::string const&;
    [[nodiscard]] auto compiled() const noexcept
        -> std::shared_ptr<std::regex const> const&; // SHARED_PTR: reviewed — immutable; shared by namespace copies

    bool exclusive{false};

private:
    std::string m_regex{};
    std::shared_ptr<std::regex const> m_compiled{}; // SHARED_PTR: reviewed — immutable; shared by namespace copies
};

} // namespace merovingian::appservice
