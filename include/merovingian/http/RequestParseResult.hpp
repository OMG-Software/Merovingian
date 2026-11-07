// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/RequestErrorCode.hpp"
#include "merovingian/http/RequestHead.hpp"

namespace merovingian::http
{

struct RequestParseResult final
{
    RequestHead request{};
    RequestErrorCode error{RequestErrorCode::none};
};

} // namespace merovingian::http
