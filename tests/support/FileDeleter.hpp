// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdio>
#include <tuple>

namespace merovingian::tests::tls_mock
{

struct FileDeleter final
{
    auto operator()(std::FILE* file) const noexcept -> void
    {
        if (file != nullptr)
        {
            std::ignore = std::fclose(file);
        }
    }
};

} // namespace merovingian::tests::tls_mock
