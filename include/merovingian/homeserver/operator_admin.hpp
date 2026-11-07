// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/trust_safety/ReviewTarget.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// The largest body the operator accounts route reads. A request is `{"action":...,"confirm":...}`; anything
// larger is refused unread with 413.
inline constexpr auto operator_account_body_limit = std::size_t{4096U};

// An answer from an operator route. The operator surface answers an error with a plain-text line and a
// result with a JSON object (the same convention as /_merovingian/admin/audit, which is JSON, and the
// admin_auth_denied lines, which are text), never with a Matrix `errcode` body (ADR-0504).
struct OperatorReply final
{
    std::uint16_t status{500U};
    std::string body{};
    bool json{false};
};

// GET and POST /_merovingian/admin/accounts/{userId}. `admin_id` is the authenticated administrator and
// `encoded_user_id` the path segment as received. Call under runtime.mutex; no blocking network call is made.
[[nodiscard]] auto operator_account_request(HomeserverRuntime& runtime, std::string_view admin_id,
                                            std::string_view method, std::string_view encoded_user_id,
                                            std::string_view body) -> OperatorReply;

// A review target type as it is spelled in a path: `media`, `room`, `federation` or `federation_server`.
[[nodiscard]] auto review_target_from_name(std::string_view name) -> std::optional<trust_safety::ReviewTarget>;

struct ReviewOutcome final
{
    std::uint16_t status{200U};
    std::string errcode{};
    std::string message{};
};

// The one implementation of "hold this target for review", behind both POST
// /_matrix/client/v3/admin/safety/review/{targetType}/{targetId} and POST
// /_merovingian/admin/review/{targetType}/{targetId}. `target_id` is already percent-decoded. The caller has
// already proven `admin_user` is an administrator. Call under runtime.mutex.
[[nodiscard]] auto apply_admin_review(HomeserverRuntime& runtime, std::string_view admin_user,
                                      std::optional<trust_safety::ReviewTarget> target, std::string_view target_id,
                                      std::string_view body) -> ReviewOutcome;

// POST /_merovingian/admin/review/{targetType}/{targetId}: `type_and_id` is the path after the prefix. Splits
// it, decodes the identifier once and calls apply_admin_review.
[[nodiscard]] auto operator_review_request(HomeserverRuntime& runtime, std::string_view admin_id,
                                           std::string_view type_and_id, std::string_view body) -> OperatorReply;

} // namespace merovingian::homeserver
