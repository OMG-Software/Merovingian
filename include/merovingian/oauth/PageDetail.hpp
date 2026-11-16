// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/HtmlText.hpp"

namespace merovingian::oauth
{

// One labelled line of a page's detail list, such as the consent page's client name, host, next address and device
// ID. The value is shown isolated from the text around it (`<bdi>`).
struct PageDetail final
{
    HtmlText label;
    HtmlText value;
};

} // namespace merovingian::oauth
