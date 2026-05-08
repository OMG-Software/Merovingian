// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::core {

enum class ErrorCode {
    none = 0,
    invalid_argument,
    io_failure,
    parse_failure,
    internal_failure,
};

class Error final {
public:
    Error() = default;

    Error(ErrorCode code, std::string message)
        : code_{code},
          message_{std::move(message)} {
    }

    [[nodiscard]] auto code() const noexcept -> ErrorCode {
        return code_;
    }

    [[nodiscard]] auto message() const noexcept -> std::string const& {
        return message_;
    }

private:
    ErrorCode code_{ErrorCode::none};
    std::string message_{};
};

} // namespace merovingian::core
