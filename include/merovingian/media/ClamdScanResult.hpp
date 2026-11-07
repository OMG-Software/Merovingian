// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/ClamdVerdict.hpp"

#include <string>

namespace merovingian::media
{

struct ClamdScanResult final
{
    ClamdVerdict verdict{ClamdVerdict::failed};
    // `infected`: the signature name clamd reported. `failed` and `oversize`: why. Empty for `clean`. Printable
    // ASCII only and at most 128 bytes, so it is safe to log.
    std::string detail{};

    [[nodiscard]] auto is_clean() const noexcept -> bool
    {
        return verdict == ClamdVerdict::clean;
    }
};

} // namespace merovingian::media
