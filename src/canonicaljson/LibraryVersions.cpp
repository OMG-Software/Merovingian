// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/LibraryVersions.hpp"

#include "merovingian/core/LibraryVersion.hpp"

#include <yyjson.h>

#include <bit>
#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::canonicaljson
{

auto format_yyjson_version(std::uint32_t version) -> std::string
{
    return std::to_string((version >> 16U) & 0xFFU) + "." + std::to_string((version >> 8U) & 0xFFU) + "." +
           std::to_string(version & 0xFFU);
}

auto library_versions() -> std::vector<core::LibraryVersion>
{
    // yyjson reports a number, so its object is found from one of its functions.
    return {core::describe_library("yyjson", format_yyjson_version(::yyjson_version()), YYJSON_VERSION_STRING,
                                   std::bit_cast<void const*>(&::yyjson_version))};
}

} // namespace merovingian::canonicaljson
