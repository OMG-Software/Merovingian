// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace merovingian::federation
{

// The glob steps ALL the ACL checks of one inbound EDU or request may spend together (ADR-0653), however many rooms it
// names. A request makes one and passes it to every check; a check spends from it and, once it is spent, a check that
// still needs a step refuses its server. Answers already remembered cost no step.
inline constexpr auto server_acl_request_glob_steps = std::size_t{1'000'000U};

struct ServerAclBudget final
{
    std::size_t steps_left{server_acl_request_glob_steps};
};

} // namespace merovingian::federation
