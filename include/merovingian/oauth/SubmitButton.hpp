// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/HtmlName.hpp"
#include "merovingian/oauth/HtmlText.hpp"

namespace merovingian::oauth
{

// A submit button of a page form; the form posts `name=value` for the button pressed, such as `decision=approve`.
struct SubmitButton final
{
    HtmlName name;
    HtmlName value;
    HtmlText label;
};

} // namespace merovingian::oauth
