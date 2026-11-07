// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::homeserver
{

// How write_streamed_body ended. After read_failed or write_failed the response is incomplete, so the caller
// closes the connection.
enum class StreamedBodyResult
{
    complete,
    read_failed,
    write_failed
};

} // namespace merovingian::homeserver
