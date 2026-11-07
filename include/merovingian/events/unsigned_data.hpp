// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace merovingian::events
{

// A PDU received from another server without its top-level `unsigned` object.
//
// `unsigned` is written by whichever server relays an event and is covered by no signature or hash
// (SS API "Calculating the reference hash for an event", "Calculating the content hash for an event",
// "Signing events": the `signatures` and `unsigned` properties are removed first), so a copy a remote
// server supplies says nothing this server can check. Every path that stores a received PDU stores
// it through these, so the stored event holds nothing but what its signatures cover, and removing
// the member changes neither the event ID, the content hash nor any signature check (ADR-0402).
[[nodiscard]] auto without_unsigned(canonicaljson::Value const& event) -> canonicaljson::Value;

// As above for an event in text. `event_json` is returned unchanged when it holds no top-level
// `unsigned`. Nothing when the text is not a JSON object or cannot be written back: a caller refuses
// the event rather than store it with the member.
[[nodiscard]] auto without_unsigned_json(std::string_view event_json) -> std::optional<std::string>;

} // namespace merovingian::events
