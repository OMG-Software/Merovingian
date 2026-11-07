// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/secret_buffer.hpp"

#include <string_view>

namespace merovingian::appservice
{

// Module-internal: the bytes of a secret token as a string_view, for constant-time comparison.
// The view is valid only while `secret` is alive and unchanged.
[[nodiscard]] inline auto secret_view(core::SecretBuffer const& secret) noexcept -> std::string_view
{
    auto const bytes = secret.bytes();
    return {reinterpret_cast<char const*>(bytes.data()), bytes.size()};
}

} // namespace merovingian::appservice
