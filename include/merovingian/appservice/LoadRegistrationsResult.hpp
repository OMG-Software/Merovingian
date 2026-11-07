// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/AppserviceRegistrationFinding.hpp"
#include "merovingian/appservice/AppserviceRegistry.hpp"

#include <vector>

namespace merovingian::appservice
{

// Loads and validates every registration file named in `paths`, in order.
// A file that fails to load or parse is recorded in `findings` and
// skipped (fail-closed per-file, not fail-closed for the whole server —
// one operator typo in one bridge's file must not prevent every other
// appservice, or the rest of the homeserver, from starting). The returned
// registry contains only the registrations that parsed AND passed
// cross-registration validation (duplicate id/as_token); when a duplicate
// is found, every registration is dropped and the problem is recorded,
// since the spec-mandated uniqueness makes a duplicate a fail-closed
// condition (routing further requests would be ambiguous).
//
// ADR-0515: a registration whose non-null `url` is not a valid http(s) url, has a query string, or is
// `http` to a host that is neither a loopback IP literal nor in `allowed_cleartext_hosts`
// (`appservice.allow_cleartext_hosts`) is rejected as a per-file finding, because the hs_token is sent
// to that url in every request. The finding names the problem and never contains a token or the url.
struct LoadRegistrationsResult final
{
    AppserviceRegistry registry{};
    std::vector<AppserviceRegistrationFinding> findings{};
};

} // namespace merovingian::appservice
