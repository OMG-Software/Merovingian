// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/Config.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/SchemaState.hpp"

#include <cstdint>
#include <functional>

namespace merovingian::homeserver
{

struct RuntimeStartOptions final
{
    config::Config config{};
    database::SchemaState existing_state{};
    // True for the federation worker (ADR-0078): the runtime loads no server
    // signing secret, mints no key, publishes no key document, and installs a
    // crypto::RefusingEd25519Provider that fails every sign and verify request.
    // The worker never signs and never asks main to sign for it.
    bool signing_disabled{false};
    // ADR-0062 part 2: which tables to hydrate from the store. The federation
    // worker sets this to TableLoadProfile::federation_worker before calling
    // start_runtime so it never pulls server_signing_keys and the other
    // credential-bearing tables into its own process memory, regardless of
    // which database credentials it connects with. See
    // database::table_load_profile_includes.
    database::TableLoadProfile database_load_profile{database::TableLoadProfile::full};
    // True when the caller has already hardened this process and installed a
    // seccomp filter that the main-process controls would violate. The
    // federation worker sets it when federation.worker.apply_hardening is on:
    // its worker filter denies setrlimit (ISO-2, ADR-0112), so re-applying
    // the main profile's core-dump limit here kills the worker with SIGSYS.
    bool process_hardening_applied_by_caller{false};
    // FED-10, ADR-0153: the number of federation worker shards this runtime is
    // one of. A worker passes federation.worker.shards so its key-resolution
    // budgets are its share of the configured ones; main leaves it at 1.
    std::uint32_t key_resolution_shards{1U};
    // False for the federation worker (ADR-0296): the runtime reads no
    // `appservice.registration_files`, holds no as_token or hs_token, and
    // creates no appservice sender user. Registrations are secrets kept outside
    // the worker's filesystem grants, and everything that consults the registry
    // runs in the main process.
    bool load_appservices{true};
    // Set by the federation worker only (ADR-0733): the worker opens no database, so its in-memory store is filled
    // from what main sends over the IPC channel. Called once with the freshly opened store, before the limits are
    // set and before hydration, so the runtime hydrates from the filled rows exactly as it would from a database.
    // Returning false leaves the database unopened and start_runtime refuses to start.
    std::function<bool(database::PersistentStore&)> fill_store{};
};

} // namespace merovingian::homeserver
