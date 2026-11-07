// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/Header.hpp"
#include "merovingian/http/HttpVersion.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::http
{

struct RequestHead final
{
    std::string method{};
    std::string target{};
    std::vector<Header> headers{};
    std::uint64_t content_length{0U};
    bool has_content_length{false};
    HttpVersion version{HttpVersion::http_1_1};
};

} // namespace merovingian::http
