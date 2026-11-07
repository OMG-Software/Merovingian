// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/EduType.hpp"

#include <string>

namespace merovingian::federation
{

struct InboundEduEnvelope final
{
    EduType type{EduType::unknown};
    std::string edu_type{};
    std::string content_json{};
    std::string origin{};
};

} // namespace merovingian::federation
