// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <utility>

namespace merovingian::core
{

enum class ErrorCode
{
    none = 0,
    invalid_argument,
    io_failure,
    parse_failure,
    internal_failure,
};

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
