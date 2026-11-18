// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::oauth
{

// The registered `application_type` (spec "Client metadata"), which selects the redirect URI rules.
enum class ApplicationType
{
    web,
    native,
};

} // namespace merovingian::oauth
