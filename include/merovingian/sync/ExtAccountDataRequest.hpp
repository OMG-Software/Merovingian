// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::sync
{

// MSC4186 §extensions.account_data
struct ExtAccountDataRequest final
{
    bool enabled{false};
};

} // namespace merovingian::sync
