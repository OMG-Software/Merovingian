// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string>

namespace merovingian::federation
{

struct FederationAcceptedTransaction final
{
    std::string origin{};
    std::string transaction_id{};
    std::size_t pdu_count{0U};
    std::size_t edu_count{0U};
    // The 200 body the transaction was first answered with, replayed to a
    // retry of it. Empty when it did not fit the ring's byte budget (ADR-0283).
    std::string response_body{};
};

} // namespace merovingian::federation
