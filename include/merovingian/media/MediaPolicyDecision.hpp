// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/MediaDisposition.hpp"

#include <string>

namespace merovingian::media
{

struct MediaPolicyDecision final
{
    MediaDisposition disposition{MediaDisposition::reject};
    std::string reason{};
};

} // namespace merovingian::media
