// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::media
{

struct DecoderSafetyRequest final
{
    std::uint64_t input_bytes{0U};
    std::uint64_t estimated_output_bytes{0U};
    std::uint64_t pixels{0U};
    std::uint32_t animation_frames{1U};
    bool decoder_marked_safe{true};
};

} // namespace merovingian::media
