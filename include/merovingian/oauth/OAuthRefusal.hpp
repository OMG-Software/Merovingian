// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/Error.hpp"

#include <string>

namespace merovingian::oauth
{

// Why an OAuth 2.0 input was refused: the wire `error` code (one of OAuthErrorCodes.hpp) beside the project's
// core::Error. The error's message is fixed text, safe to send as `error_description`; it never quotes the input.
// The core::Error code says what kind of failure it was: ErrorCode::parse_failure for a grammar or rule failure,
// ErrorCode::invalid_argument for a cap exceeded, ErrorCode::internal_failure when a crypto primitive failed.
//
// This is the shape federation::PublicRoomsRefusal uses for a Matrix `errcode` (ADR-0768): the protocol code is a
// string field beside core::Error, not an error enum of the module's own.
struct OAuthRefusal final
{
    std::string error_code{};
    core::Error error{};
};

} // namespace merovingian::oauth
