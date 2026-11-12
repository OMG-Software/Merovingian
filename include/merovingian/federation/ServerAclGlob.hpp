// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <optional>
#include <string_view>

namespace merovingian::federation
{

// Matrix v1.19 server ACL glob matching: '*' matches zero or more characters and '?' exactly one, compared
// case-insensitively over the whole of `text`. It is a two-pointer match that remembers the last '*', so the work is
// linear in pattern plus text for every pattern a real ACL contains. Each step of the loop spends one unit of
// `steps_left`; when none is left the match stops and the answer is std::nullopt (not "no match"), so a caller can
// bound the total work of one ACL check.
[[nodiscard]] auto server_acl_glob_match(std::string_view pattern, std::string_view text,
                                         std::size_t& steps_left) noexcept -> std::optional<bool>;

} // namespace merovingian::federation
