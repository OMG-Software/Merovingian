// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/DelayedEventStatus.hpp"

#include <optional>
#include <string_view>

namespace merovingian::database
{

// The text the `delayed_events.status` column holds for `status`: `scheduled`, `sent`, `cancelled` or `failed`.
[[nodiscard]] auto delayed_event_status_text(DelayedEventStatus status) noexcept -> std::string_view;
// The status `text` names, byte for byte; nullopt for any other text, so a hydrating loader can refuse the row.
[[nodiscard]] auto parse_delayed_event_status(std::string_view text) noexcept -> std::optional<DelayedEventStatus>;

} // namespace merovingian::database
