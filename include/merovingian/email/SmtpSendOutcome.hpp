// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/email/SmtpSendResult.hpp"

#include <string>

namespace merovingian::email
{

struct SmtpSendOutcome final
{
    SmtpSendResult result{SmtpSendResult::failed};
    // For logs: libcurl's error name, or why it was refused locally. Never a secret.
    std::string detail{};
};

} // namespace merovingian::email
