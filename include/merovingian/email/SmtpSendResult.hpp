// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::email
{

enum class SmtpSendResult : std::uint8_t
{
    sent,
    // The recipient or sender failed is_safe_mailbox_address, or settings are unusable; resending
    // the same message cannot succeed.
    refused_locally,
    // The libcurl this server runs on was built without the relay's protocol.
    protocol_unavailable,
    // password_file could not be read as a secret file.
    credentials_unavailable,
    // The relay could not be reached, would not start TLS, failed verification, refused AUTH, a
    // command, or the message, or did not answer in time.
    failed,
};

} // namespace merovingian::email
