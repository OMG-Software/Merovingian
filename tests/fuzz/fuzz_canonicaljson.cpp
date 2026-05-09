// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/canonicaljson/parser.hpp>
#include <merovingian/canonicaljson/serializer.hpp>

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

    auto const parsed = merovingian::canonicaljson::parse_lossless(input);
    if (parsed.error == merovingian::canonicaljson::ParseError::none)
    {
        auto const result = merovingian::canonicaljson::serialize_canonical(parsed.value);
        static_cast<void>(result);
    }
    return 0;
}
