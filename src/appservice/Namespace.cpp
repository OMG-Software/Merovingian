// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/appservice/Namespace.hpp"

#include <memory>
#include <regex>
#include <string>
#include <utility>

namespace merovingian::appservice
{

Namespace::Namespace(bool exclusive_value, std::string regex_value)
    : exclusive{exclusive_value}
    , m_regex{std::move(regex_value)}
{
    try
    {
        m_compiled = std::make_shared<std::regex const>(m_regex.begin(), m_regex.end(), std::regex::extended);
    }
    catch (std::regex_error const&)
    {
        // Matches nothing (fail closed); validate_registrations() reports the
        // malformed pattern at startup.
        m_compiled = nullptr;
    }
}

auto Namespace::regex() const noexcept -> std::string const&
{
    return m_regex;
}

auto Namespace::compiled() const noexcept
    -> std::shared_ptr<std::regex const> const& // SHARED_PTR: reviewed — immutable
{
    return m_compiled;
}

} // namespace merovingian::appservice
