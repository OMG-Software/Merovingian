// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/signal_hardening.hpp"

#include <cerrno>
#include <cstring>
#include <string>

#include <signal.h>

namespace merovingian::platform
{

auto ignore_sigpipe() noexcept -> HardeningPlanDecision
{
    struct ::sigaction action
    {
    };
    action.sa_handler = SIG_IGN;
    if (::sigemptyset(&action.sa_mask) != 0 || ::sigaction(SIGPIPE, &action, nullptr) != 0)
    {
        auto const error = errno;
        try
        {
            return HardeningPlanDecision{.accepted = false,
                                         .fail_closed = true,
                                         .reason = "failed to ignore SIGPIPE: " + std::string{std::strerror(error)}};
        }
        catch (...)
        {
            // Allocation failed while building the reason; the refusal is what matters.
            return HardeningPlanDecision{.accepted = false, .fail_closed = true, .reason = {}};
        }
    }
    return HardeningPlanDecision{.accepted = true, .fail_closed = true, .reason = {}};
}

} // namespace merovingian::platform
