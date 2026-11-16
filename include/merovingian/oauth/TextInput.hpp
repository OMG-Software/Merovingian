// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/HtmlName.hpp"
#include "merovingian/oauth/HtmlText.hpp"

#include <optional>

namespace merovingian::oauth
{

// A labelled, required text or password input of a page form.
struct TextInput final
{
    // The form field name, also the base of the element id.
    HtmlName name;
    HtmlText label;
    // The `autocomplete` token, such as `username`, `current-password` or `new-password`.
    HtmlName autocomplete;
    // A password input: its value is never written into the page.
    bool concealed{false};
    // A prefilled value, such as a login hint. Refused for a concealed input.
    std::optional<HtmlText> value{};
};

} // namespace merovingian::oauth
