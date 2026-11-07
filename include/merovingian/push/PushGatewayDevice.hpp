// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::push
{

// One entry of the Push Gateway `/notify` request's `devices` array: one
// pusher to notify. `data_format` mirrors the pusher's `data.format`
// (excluding `url`, which routes the request instead of being sent in the
// body); `tweak_sound`/`tweak_highlight` come from push-rule evaluation.
struct PushGatewayDevice final
{
    std::string app_id{};
    std::string pushkey{};
    std::uint64_t pushkey_ts{0U};
    std::optional<std::string> data_format{};
    // Every OTHER member of the pusher's `data` dictionary as supplied at
    // registration, beyond `format` (above). Matrix v1.19 Push Gateway API:
    // the notify request's Device object's `data` field is "the data
    // dictionary passed in at pusher creation minus the url key" — so any
    // custom member (routing/credential fields a specific gateway depends
    // on, for example) MUST be forwarded to the gateway verbatim, not just
    // `format`. `url` itself is never part of this: it only ever routes the
    // request (see PushGatewayClient::notify's `gateway_url` parameter) and
    // must never appear in the request body. build_device_object() also
    // defensively skips any `url`/`format` member found here, so a caller
    // that (incorrectly) includes either key can never produce a duplicate
    // or leak the routing URL into the body. Empty/nullopt when the
    // pusher's `data` had no members beyond `url`/`format`.
    std::optional<canonicaljson::Object> data_extra{};
    std::optional<std::string> tweak_sound{};
    bool tweak_highlight{false};
};

} // namespace merovingian::push
