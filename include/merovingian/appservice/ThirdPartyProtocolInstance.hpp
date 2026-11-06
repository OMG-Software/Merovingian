// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"

#include <string>

namespace merovingian::appservice
{

// One entry of a Protocol response's `instances` array. `icon` and
// `network_id` are the spec's optional/required fields respectively;
// `instance_id` is NOT stored here — the spec requires the HOMESERVER to
// mint it ("This field is added to the response ... by the homeserver"), so
// it is assigned when the client-server response is built, not when this
// type is parsed from the appservice's reply.
struct ThirdPartyProtocolInstance final
{
    std::string desc{};
    canonicaljson::Object fields{}; // preset search-field values; string members only (see .cpp)
    std::string icon{};             // empty means absent
    std::string network_id{};
};

} // namespace merovingian::appservice
