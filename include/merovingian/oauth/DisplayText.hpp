// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Module-internal helper shared by the oauth sources; not intended as public API.

#include <string_view>

namespace merovingian::oauth
{

// Whether `text` may be shown to a user: valid UTF-8 holding no control character and no character that changes
// how the text around it is displayed. Refused: C0 controls and DEL (U+0000 to U+001F, U+007F), C1 controls (U+0080
// to U+009F), the line and paragraph separators (U+2028, U+2029) and the bidirectional formatting characters
// (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069), which can make a client's name read as another
// (ADR-0771). Nothing is stripped or replaced: the caller refuses the text.
[[nodiscard]] auto display_text_is_safe(std::string_view text) noexcept -> bool;

} // namespace merovingian::oauth
