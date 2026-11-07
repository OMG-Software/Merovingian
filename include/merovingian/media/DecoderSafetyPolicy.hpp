// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::media
{

struct DecoderSafetyPolicy final
{
    std::uint64_t max_input_bytes{0U};
    std::uint64_t max_output_bytes{0U};
    std::uint64_t max_pixels{0U};
    std::uint32_t max_animation_frames{1U};
    std::uint32_t max_expansion_ratio{100U};
    bool unsafe_decoders_disabled{true};
};

} // namespace merovingian::media
