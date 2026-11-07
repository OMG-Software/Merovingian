// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/ThirdPartyFieldType.hpp"
#include "merovingian/appservice/ThirdPartyProtocolInstance.hpp"

#include <string>
#include <utility>
#include <vector>

namespace merovingian::appservice
{

// A `GET /_matrix/app/v1/thirdparty/protocol/{protocol}` response, bounded
// and type-checked field-by-field before being trusted. See appservice_
// client.cpp's parse_protocol_object for the exact bounds applied — an
// appservice/bridge is not a trusted peer (src/appservice/AGENTS.md).
struct ThirdPartyProtocol final
{
    std::vector<std::pair<std::string, ThirdPartyFieldType>> field_types{};
    std::string icon{};
    std::vector<ThirdPartyProtocolInstance> instances{};
    std::vector<std::string> location_fields{};
    std::vector<std::string> user_fields{};
};

} // namespace merovingian::appservice
