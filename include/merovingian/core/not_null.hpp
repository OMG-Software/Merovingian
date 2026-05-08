// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <stdexcept>

namespace merovingian::core
{

template <typename T>
class not_null final
{
public:
    explicit constexpr not_null(T value)
        : m_value{value}
    {
        if (m_value == nullptr)
        {
            throw std::invalid_argument{"not_null constructed with nullptr"};
        }
    }

    [[nodiscard]] constexpr auto get() const noexcept -> T
    {
        return m_value;
    }

    [[nodiscard]] constexpr operator T() const noexcept
    {
        return m_value;
    }

private:
    T m_value;
};

} // namespace merovingian::core
