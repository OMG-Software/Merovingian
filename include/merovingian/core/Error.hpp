// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/ErrorCode.hpp"

#include <string>
#include <utility>

namespace merovingian::core
{

class Error final
{
public:
    Error() = default;

    Error(ErrorCode code, std::string message)
        : m_code{code}
        , m_message{std::move(message)}
    {
    }

    [[nodiscard]] auto code() const noexcept -> ErrorCode
    {
        return m_code;
    }

    [[nodiscard]] auto message() const noexcept -> std::string const&
    {
        return m_message;
    }

private:
    ErrorCode m_code{ErrorCode::none};
    std::string m_message{};
};

} // namespace merovingian::core
