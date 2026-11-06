// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/ThirdPartyProtocol.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <cstdint>
#include <string>

namespace merovingian::appservice
{

// Outcome of `GET /_matrix/app/v1/thirdparty/protocol/{protocol}`. `found`
// mirrors the query-result convention above: true only on a 200 whose body
// parsed into a well-formed Protocol object; false on 404 ("no protocol was
// found") — `ok` is false only for a transport failure, an unexpected
// status, or a 200 whose body could not be parsed as a Protocol object
// (a malformed/hostile appservice reply), none of which the caller may
// treat as "not found".
struct AppserviceThirdPartyProtocolResult final
{
    bool ok{false};
    bool disabled{false};
    std::uint16_t status{0U};
    bool found{false};
    ThirdPartyProtocol protocol{};
    http::OutboundError error{http::OutboundError::none};
    std::string error_detail{};
};

} // namespace merovingian::appservice
