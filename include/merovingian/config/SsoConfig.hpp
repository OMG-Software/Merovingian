// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/SsoIdentityProvider.hpp"

#include <string>
#include <vector>

namespace merovingian::config
{

// SSO login configuration (Matrix v1.19 CS API §"Client login via SSO").
// Disabled by default, mirroring OidcConfig's opt-in pattern. `enabled`
// gates both advertising `m.login.sso` from `GET /login` and routing
// `GET /login/sso/redirect[/{idpId}]` — a misconfigured or disabled SSO
// setup fails closed (flow not advertised, redirect endpoints 404) rather
// than half-serving the flow.
//
// Merovingian does not itself implement an external SSO protocol client
// (CAS/SAML/OIDC) — `authorization_url` is the operator-configured HTTPS
// endpoint of that external system, which `/login/sso/redirect[/{idpId}]`
// redirects the browser to per spec step "redirect the user's browser to
// the SSO login page". Once that external system has authenticated the
// user, its own integration adapter maps the verified identity to a local
// Matrix user id and calls `homeserver::complete_sso_login` to mint the
// short-lived `m.login.token` login token and complete the redirect back
// to the client's `redirectUrl` (spec steps "generate a short-term login
// token" / "redirect the user's browser to the URI thus built"); see
// docs/auth-identity.md for the full boundary.
//
// `redirect_url_allowlist` is the operator's allowlist of HTTPS URL
// prefixes a client's `redirectUrl` query parameter is validated against
// before the homeserver ever redirects a browser (and, later, a login
// token) there — this is the control that prevents `/login/sso/redirect`
// from being an open redirect (see docs/threat-model.md).
struct SsoConfig final
{
    bool enabled{false};
    std::string authorization_url{};
    std::vector<SsoIdentityProvider> identity_providers{};
    std::vector<std::string> redirect_url_allowlist{};
};

} // namespace merovingian::config
