// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <stdexcept>

namespace merovingian::core {

template <typename T>
class not_null final {
public:
    explicit constexpr not_null(T value)
        : value_{value} {
        if (value_ == nullptr) {
            throw std::invalid_argument{"not_null constructed with nullptr"};
        }
    }

    [[nodiscard]] constexpr auto get() const noexcept -> T {
        return value_;
    }

    [[nodiscard]] constexpr operator T() const noexcept {
        return value_;
    }

private:
    T value_;
};

} // namespace merovingian::core
