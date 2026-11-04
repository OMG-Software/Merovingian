// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the URL preview surface that reads a page chosen by whoever asks for the preview:
// the OpenGraph and <title> extractor over the HTML, the content-type check, and the resolver
// that turns an og:image value or a redirect Location into a URL. The extractor and the
// content-type check take the whole input. The resolver takes the bytes before the first NUL as
// the base URL and the rest as the reference.

#include "fuzz_input.hpp"
#include "merovingian/media/url_preview.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto const input = merovingian::fuzz::to_string(data, size);
    std::ignore = merovingian::media::extract_open_graph(input);
    std::ignore = merovingian::media::content_type_is_html(input);
    auto const [base, reference] = merovingian::fuzz::split_at_nul(input);
    std::ignore = merovingian::media::resolve_preview_reference(base, reference);
    return 0;
}
