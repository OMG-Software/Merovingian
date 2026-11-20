// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/RequiredStateElement.hpp"

#include <vector>

namespace merovingian::sync
{

// One room config's MSC4186 `required_state` request ("RequiredStateRequest"): the state to return, the state to
// filter out of it, and whether members are lazy-loaded. An element's omitted field matches every type or every state
// key; a present one, "*" included, matches only itself (`RequiredStateElement`).
//
// The configs of the rules a room matches are kept apart rather than merged, because MSC4186 "Combining
// `required_state`" asks for the union of what each returns, and one config's `exclude` must not filter what another
// config returns. With `lazy_members`, an include element matches `m.room.member` events only when it names that type:
// `{}` is "everything except the members, which are lazily loaded" (MSC4186 "Lazy loaded memberships", ADR-0865).
struct RequiredStateConfig final
{
    std::vector<RequiredStateElement> include{};
    std::vector<RequiredStateElement> exclude{};
    bool lazy_members{false};

    [[nodiscard]] auto operator==(RequiredStateConfig const&) const -> bool = default;
};

} // namespace merovingian::sync
