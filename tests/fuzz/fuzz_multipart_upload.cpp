// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the multipart/mixed parser that reads a remote server's federation media download
// (parse_federation_media_multipart). The remote chooses both the Content-Type boundary and the
// body, so both come from the input: the bytes before the first NUL are the Content-Type header
// value, the rest is the body. Input with no NUL is a body under a fixed, valid boundary, so the
// part and header scanning is reached without the fuzzer first having to invent a boundary.

#include "fuzz_input.hpp"
#include "merovingian/homeserver/MediaService.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto const input = merovingian::fuzz::to_string(data, size);
    if (input.find('\0') == std::string::npos)
    {
        std::ignore = merovingian::homeserver::parse_federation_media_multipart("multipart/mixed; boundary=b", input);
        return 0;
    }
    auto const [content_type, body] = merovingian::fuzz::split_at_nul(input);
    std::ignore = merovingian::homeserver::parse_federation_media_multipart(content_type, body);
    return 0;
}
