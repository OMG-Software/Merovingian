// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/http/request.hpp>

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto const input = std::string_view{reinterpret_cast<char const*>(data), size};
    auto const parsed = merovingian::http::parse_request_head(input);
    static_cast<void>(parsed);
    return 0;
}
