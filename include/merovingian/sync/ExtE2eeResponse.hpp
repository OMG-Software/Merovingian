// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace merovingian::sync
{

struct ExtE2eeResponse final
{
    std::vector<std::string> changed{}; // user IDs whose device lists changed
    std::vector<std::string> left{};    // user IDs who left shared rooms
    std::map<std::string, std::uint64_t> device_one_time_keys_count{};
    std::vector<std::string> device_unused_fallback_key_types{};
    // MSC4543 "Device lists": the response to a request without `pos` carries no `device_lists` at all. The handler,
    // which knows whether the request had one, clears this (and empties `changed` and `left`) for such a request.
    bool device_lists{true};
};

} // namespace merovingian::sync
