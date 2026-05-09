// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/http/request.hpp>

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto input = std::string{};
    input.reserve(size);
    for (auto index = std::size_t{0U}; index < size; ++index)
    {
        input.push_back(static_cast<char>(data[index]));
    }

    auto const parsed = merovingian::http::parse_request_head(input);
    static_cast<void>(parsed);
    return 0;
}
