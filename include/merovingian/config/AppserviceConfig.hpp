// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::config
{

// Matrix v1.19 Application Service API configuration. `registration_files`
// lists paths to appservice registration documents (see
// `merovingian::appservice::load_registrations`), each describing one
// bridge/bot's as_token/hs_token, namespaces, and outbound URL. Empty by
// default: with no registration files, the Application Service surface
// (as_token auth, transactions, query hooks, third-party endpoints) is
// entirely inert. Restart required — see reload_policy.cpp: the registry is
// built once at start_runtime() time.
struct AppserviceConfig final
{
    std::vector<std::string> registration_files{};
    std::uint32_t connect_timeout_seconds{10U};
    std::uint32_t total_timeout_seconds{30U};
    std::string response_max_size{"16MiB"};
    // The most events that may sit queued (appservice_outbox rows) for ONE appservice. At the cap
    // further events for that appservice are not queued, counted, logged at warning level and
    // audited, so a bridge that never returns cannot grow the store and every in-memory mirror
    // without bound (ADR-0191, refining ADR-0163). Restart required like the rest of appservice.*.
    std::uint32_t max_queued_events{100000U};
};

} // namespace merovingian::config
