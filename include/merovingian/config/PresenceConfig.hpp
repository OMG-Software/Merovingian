// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::config
{

// Matrix v1.19 CS API "Presence". With `enabled=false` the server tracks and exchanges no
// presence: GET answers 404, PUT answers 200 and keeps nothing, /sync carries no `presence`
// events and does not mark users online, no m.presence EDU is sent, and an inbound one is
// dropped. Restart required: main and the federation worker read it once at start-up.
struct PresenceConfig final
{
    bool enabled{true};
};

} // namespace merovingian::config
