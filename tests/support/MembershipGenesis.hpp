// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::tests::membership_acceptor_fixture
{

// The event IDs of the events `seed_room_genesis` stores.
struct Genesis final
{
    std::string create_id{};
    std::string pl_id{};
    std::string admin_member_id{};
    std::string join_rules_id{};
};

} // namespace merovingian::tests::membership_acceptor_fixture
