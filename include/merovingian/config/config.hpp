// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/rate_limit.hpp"
#include "merovingian/observability/logger.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::config
{

struct CorsConfig final
{
    // Origins to allow. Wildcard `*` is the default and means any origin is
    // allowed to make cross-origin requests. The CORS spec forbids combining
    // `*` with `allow_credentials=true`; the config parser enforces that.
    std::vector<std::string> allowed_origins{"*"};
    // How long the preflight result may be cached, in seconds.
    std::uint32_t max_age{86400U};
    // Whether to allow browser credentials (cookies, client TLS certs).
    // Matrix clients authenticate with bearer tokens so this is false by
    // default; flip it on only when you know what you are doing.
    bool allow_credentials{false};
    // Methods advertised in the preflight `Access-Control-Allow-Methods`
    // header. Empty string falls back to the standard list.
    std::string allow_methods{"GET, POST, PUT, DELETE, OPTIONS"};
    // Headers advertised in the preflight `Access-Control-Allow-Headers`
    // header. Empty string falls back to `authorization, content-type`,
    // which is the set Matrix clients actually use.
    std::string allow_headers{"authorization, content-type"};
};

// HTTP/1.1 persistent-connection (keep-alive) policy. Matrix v1.19 is served
// over HTTP/1.1, where persistent connections are the default; keeping a
// connection open saves a full TLS handshake per request. The fields mirror
// `merovingian::http::KeepAlivePolicy` (validated by
// `http::keep_alive_policy_is_valid()` and `config::validate()`):
//   keep_alive              — master switch; false restores the historical
//                             close-after-every-response behaviour.
//   keep_alive_idle_seconds — how long a kept-alive connection may sit idle
//                             (no next request) before the server closes it.
//                             Range 1..300; restart required.
//   keep_alive_max_connections — process-wide cap on connections parked idle
//                             waiting for a next request. Each parked
//                             connection occupies a main-pool worker thread,
//                             so the cap bounds how many workers a client can
//                             tie up. Range 1..4096; restart required.
struct HttpTransportConfig final
{
    bool keep_alive{true};
    std::uint32_t keep_alive_idle_seconds{15U};
    std::uint32_t keep_alive_max_connections{8U};
};

struct TurnServerConfig final
{
    // TURN server URI advertised to clients, e.g. "turn:turn.example.org:3478?transport=udp".
    // When empty the TURN endpoint returns an empty object so VoIP clients
    // gracefully disable relay support.
    std::string server{};
    // Static credentials issued to authenticated clients. Shared-secret
    // time-limited usernames are not yet implemented; until then the operator
    // supplies a service account or uses a TURN server that does not require
    // authentication.
    std::string username{};
    std::string password{};
    // Lifetime in seconds advertised in the response. Defaults to 24 hours.
    std::uint32_t ttl_seconds{86400U};
};

// Identity Service API configuration (Matrix v1.19 Identity Service API).
// The homeserver acts as a client of one or more remote identity servers for
// third-party identifier (3PID) invites, binds, unbinds, and requestToken
// flows. `trusted_servers` is the allowlist of IS base URLs the homeserver
// will contact: a 3PID invite/bind whose `id_server` is not in this list is
// refused (M_UNRECOGNIZED / 404), so operators pin the IS attack surface.
// `default_server` is the IS used when a client omits `id_server` from a
// requestToken/bind call. `allowed_bind_domains` restricts which domains a
// user may bind an email 3PID for (preventing bind-of-someone-else's-domain
// abuse). Timeouts bound the outbound IS HTTP calls (see OutboundClient).
// Empty by default: with no trusted servers, every 3PID operation that
// requires an IS fails closed with a clear error rather than silently
// minting tokens locally.
struct IdentityServerConfig final
{
    std::vector<std::string> trusted_servers{};
    std::string default_server{};
    std::vector<std::string> allowed_bind_domains{};
    std::uint32_t connect_timeout_seconds{10U};
    std::uint32_t total_timeout_seconds{30U};
};

// OIDC authorisation server metadata configuration for MSC2965 discovery.
// When `enabled` is false, GET /_matrix/client/v1/auth_metadata returns
// 404 M_UNRECOGNIZED. When enabled, the endpoint returns RFC 8414 metadata
// built from these fields; no actual OAuth flow is implemented here.
struct OidcConfig final
{
    bool enabled{false};
    std::string issuer{};
    std::string authorization_endpoint{};
    std::string token_endpoint{};
    std::string registration_endpoint{};
    std::string revocation_endpoint{};
    std::string device_authorization_endpoint{};
    std::string account_management_uri{};
    std::vector<std::string> account_management_actions_supported{};
};

// A single SSO identity provider advertised in the `m.login.sso` login flow
// (Matrix v1.19 CS API §"Client login via SSO", `IdP` shape). `id` and
// `name` are required by spec; `icon` (an `mxc://` URI) and `brand` are
// optional UI hints and are omitted from the advertised flow when empty.
struct SsoIdentityProvider final
{
    std::string id{};
    std::string name{};
    std::string icon{};
    std::string brand{};
};

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

// Push Gateway API delivery configuration (Matrix v1.19 push-gateway-api /
// CS API push-notifications module). `enabled` gates the entire outbound
// delivery path and defaults to false, mirroring OidcConfig's pattern, so
// merging this capability cannot cause an existing deployment to start
// sending traffic to gateways on upgrade — an operator must explicitly opt
// in. Timeouts mirror IdentityServerConfig's operator-tunable connect/total
// pair; a pusher's gateway URL is client-supplied (any client can register
// one), so these bound how long the homeserver waits on a host it does not
// control.
struct PushConfig final
{
    bool enabled{false};
    std::uint32_t connect_timeout_seconds{10U};
    std::uint32_t total_timeout_seconds{30U};
};

struct ServerConfig final
{
    std::string server_name{"example.org"};
    std::string public_baseurl{"https://matrix.example.org"};
    std::vector<std::string> trusted_proxies{};
    // CORS preflight policy. Wildcard `*` is the default origin and is safe
    // for Matrix because clients authenticate with `Authorization: Bearer`
    // tokens, not browser-credentialed cookies. A `*` in `allowed_origins`
    // combined with `allow_credentials=true` is rejected at config-parse
    // time per the CORS spec.
    CorsConfig cors{};
    // HTTP/1.1 persistent-connection (keep-alive) policy for the client and
    // federation listeners. See merovingian/http/keep_alive.hpp for the
    // semantics of each field; validation enforces the documented ranges.
    HttpTransportConfig http{};
    // TURN relay configuration for GET /_matrix/client/v3/voip/turnServer.
    // Empty by default; when populated the endpoint returns real credentials.
    TurnServerConfig turn{};
    // OIDC discovery metadata. Empty by default; when populated the
    // auth_metadata endpoint advertises the configured OAuth 2.0 server.
    OidcConfig oidc{};
    // Identity Service API client config for 3PID invites/bind/unbind/
    // requestToken. Empty by default; with no trusted servers the homeserver
    // refuses 3PID operations that need an IS rather than minting locally.
    IdentityServerConfig identity_server{};
    // Push Gateway API delivery config. Disabled by default (see PushConfig).
    PushConfig push{};
    // SSO login config. Disabled by default (see SsoConfig).
    SsoConfig sso{};
};

struct ListenerConfig final
{
    std::string bind{};
    bool tls{false};
    bool reverse_proxy{true};
    std::string tls_certificate_file{};
    std::string tls_private_key_file{};
};

struct ListenersConfig final
{
    ListenerConfig client{"127.0.0.1:8008", false};
    ListenerConfig federation{"127.0.0.1:8009", false};
};

enum class DatabaseBackend
{
    postgresql,
    sqlite,
};

enum class DatabaseRole
{
    runtime,
    migration,
};

struct DatabaseConfig final
{
    std::string uri_file{"/etc/merovingian/db-uri"};
    std::uint32_t pool_size{16U};
    DatabaseBackend backend{DatabaseBackend::postgresql};
    DatabaseRole role{DatabaseRole::runtime};
    // PostgreSQL role separation (packaging/postgresql/provision-roles.sql).
    // The login role is granted two NOLOGIN roles: one with DDL rights used
    // for the migration phase, one with DML-only rights used to serve. Both
    // empty means no SET ROLE is issued and the connection keeps whatever
    // privileges its login role has — the pre-separation behaviour, so an
    // existing single-role deployment is unaffected by upgrading.
    //
    // When either IS set, a failed SET ROLE aborts the open. Continuing would
    // serve traffic with more privilege than the operator asked for, which is
    // the exact outcome this separation exists to prevent.
    std::string migration_role{};
    std::string runtime_role{};
    std::string sqlite_path{"/var/lib/merovingian/merovingian.sqlite3"};
};

struct RegistrationSecurityConfig final
{
    bool enabled{false};
    bool require_token{true};
    std::string token_file{};
};

struct EncryptionSecurityConfig final
{
    bool default_for_new_rooms{true};
    bool require_for_direct_messages{true};
    bool require_for_private_rooms{true};
    bool allow_unencrypted_public_rooms{true};
    bool block_unencrypted_federated_private_rooms{true};
};

struct FederationSecurityConfig final
{
    bool enabled{true};
    std::string default_policy{"allow"};
    std::vector<std::string> allowed_servers{};
    std::vector<std::string> denied_servers{};
    bool require_valid_tls{true};
    bool verify_json_signatures{true};
    std::vector<std::string> deny_ip_ranges{
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7",
    };
    std::string max_transaction_size{"10MiB"};
    // Matrix Server-Server API v1.19 caps /send transactions at 50 PDUs
    // and 100 EDUs. Operators may lower these caps but validation rejects
    // values above the spec maximum.
    std::uint32_t max_transaction_pdus{50U};
    std::uint32_t max_transaction_edus{100U};
    // Authenticated inbound federation pressure caps. These are keyed by the
    // verified remote origin, not by client IP or claimed event sender.
    http::RateLimitPolicy per_origin_transaction_rate{120U, 60U};
    http::RateLimitPolicy per_origin_pdu_rate{600U, 60U};
    http::RateLimitPolicy per_origin_edu_rate{1200U, 60U};
    // Per-origin cap on inbound federation requests OUTSIDE /send (query,
    // backfill, membership, key and state endpoints). /send keeps its own
    // weighted transaction/PDU/EDU trio above and is exempt so a transaction
    // and its contents are never double-counted.
    http::RateLimitPolicy per_origin_request_rate{600U, 60U};
    // Budgets for remote signing-key resolution, which necessarily happens
    // BEFORE a request's X-Matrix signature can be checked -- verifying the
    // signature requires the key. Without a budget, an unauthenticated sender
    // can name any origin in an X-Matrix header and make this server perform
    // .well-known + SRV + DNS discovery and an outbound GET
    // /_matrix/key/v2/server against a host of their choosing: a DoS surface
    // here and a reflection vector at the named third party. Unlike the
    // per_origin_* budgets above, these are keyed on the source IP, because
    // the origin is precisely the field the attacker controls and varies.
    //
    // `security.federation.default_policy=deny` with a populated
    // `allowed_servers` list closes this independently -- the policy check runs
    // before resolution -- so allow-list deployments are unaffected either way.
    //
    // key_resolution_per_ip_rate bounds how often one source IP may cause a
    // resolution of an origin this server has no usable cached key for.
    http::RateLimitPolicy key_resolution_per_ip_rate{10U, 60U};
    // Cap on resolutions in flight across the whole process, so a sender
    // spreading across many source IPs still cannot exhaust the outbound path.
    // Over the cap the request is rejected rather than queued: queuing converts
    // an overload into a slower overload while holding the resources anyway.
    // Must be >= 1 (validated); 0 would deadlock every resolution.
    std::uint32_t key_resolution_max_in_flight{8U};
    // How long a failed resolution is remembered, so repeated requests naming
    // the same unresolvable origin are cheap. Bounds the honest-misconfiguration
    // case; a sender varying the origin defeats it by design, which is what the
    // two budgets above are for. "0s" disables the negative cache.
    std::string key_resolution_failure_ttl{"300s"};
    std::string remote_timeout{"60s"};
    // Separate, extendable budget for the make_join/send_join/make_leave/send_leave
    // membership dance. A large remote room's make_join can take longer than the
    // 60s general federation timeout; this is distinct from `remote_timeout`.
    std::string join_timeout{"180s"};
    // Cap on concurrent make_join candidate probes and inbound sender-key fan-out.
    // Must be >= 1 (validated); 0 would degenerate to no work.
    std::uint32_t join_parallelism{8U};
    // Overall wall-clock budget for the whole make_join race across ALL candidates,
    // independent of the per-candidate `join_timeout`. Without this, a large `via`
    // list races in batches of `join_parallelism` and can take many minutes even
    // though each individual candidate stays within its own budget — long after the
    // calling client's own HTTP request has timed out. Candidates still in flight
    // when the deadline is reached are moved to `orphan_futures_` to finish in the
    // background, same as when a candidate loses to a winner.
    std::string join_race_deadline{"45s"};
    // Hard cap on the number of via-derived candidates actually raced. Every
    // candidate is spawned as an OS thread immediately (throttled to run by
    // `join_parallelism`, but not to spawn), so an unbounded `via` list means
    // unbounded upfront thread creation. Must be >= 1 (validated).
    std::uint32_t join_max_candidates{20U};
    // Cap on concurrent remote signing-key resolutions when verifying the
    // signatures of events in a send_join response's `state`/`auth_chain`
    // arrays (one m.room.member per room member — thousands for a large
    // room). Distinct (sender_domain, key_id) pairs are deduplicated before
    // this cap is applied, so it bounds concurrent *distinct home servers*
    // contacted, not concurrent events. Must be >= 1 (validated).
    std::uint32_t join_state_key_parallelism{100U};
    // Response body cap applied specifically to make_join/send_join, distinct
    // from the general 16 MiB http::OutboundRequest default. A send_join
    // response embeds the room's full current state (one m.room.member per
    // member) plus the auth chain; for a genuinely large room (tens of
    // thousands of members) this routinely exceeds 16 MiB and the call was
    // rejected outright with `response_too_large` even after join_timeout
    // gave it enough wall-clock time. Restart required: this also sizes the
    // federation-worker IPC frame cap, which is fixed at worker spawn time
    // (see reload_policy.cpp).
    std::string join_response_max_size{"64MiB"};
};

struct MediaSecurityConfig final
{
    std::string max_upload_size{"50MiB"};
    std::vector<std::string> allowed_mime_types{};
    bool quarantine_unknown_mime{true};
    bool enable_av_scanner{true};
    // Acceptance disposition for authenticated local uploads. One of "allow",
    // "allow-after-scan", "quarantine", "deny". Validated by validate_config()
    // via is_valid_media_acceptance_policy(); parsed into
    // media::MediaAcceptancePolicy by media::make_runtime_media_config().
    std::string local_upload_policy{"allow-after-scan"};
    // Acceptance disposition for bytes fetched from a federated origin
    // server. Defaults to "quarantine" rather than mirroring
    // local_upload_policy's default: remote media has no accountable local
    // uploader and, unlike a local upload, is never covered by a real scanner
    // verdict today, so it is held for admin review unless an operator opts
    // into a looser policy.
    std::string remote_fetch_media_policy{"quarantine"};
    bool block_private_ip_fetches{true};
    std::string remote_fetch_timeout{"30s"};
    bool remote_fetch_enabled{false};
    bool decode_in_sandbox{true};
};

struct TrustSafetySecurityConfig final
{
    bool enabled{false};
    std::string policy_server_url{};
    std::string policy_server_timeout{"5s"};
    bool policy_server_allow_without_result{false};
};

struct LoggingSecurityConfig final
{
    bool redact_tokens{true};
    bool redact_event_content{true};
    bool structured{true};
};

// At-rest protection for high-value server secrets. The master key file
// contains raw secret material that is hashed with domain separation to
// derive the key used to encrypt the Ed25519 signing secret before it is
// written to the database. When empty, fresh signing keys cannot be created
// (legacy plaintext keys may still be loaded for migration).
struct SecretsSecurityConfig final
{
    std::string master_key_file{};
};

// Per-endpoint rate-limit policies. The values populate
// `http::RateLimitEngine` at `start_client_server()` time; restart
// required (see `src/config/reload_policy.cpp`). The 0.5.0 design doc
// (`docs/log-filtering-design.md`) lists the operator-agreed defaults,
// now expressed through the route tiers in `http::rate_limit_tier_for()`:
// 20/min per IP for the auth-sensitive tier (/login, /register, /refresh
// and the */requestToken family), 5/min per user for /login, 30/min for
// keys/devices, 20/min for media and search, 120/min for federation routes
// on the client listener, 90/min for everything else.
struct ClientRateLimitsConfig final
{
    std::unordered_map<std::string, http::RateLimitPolicy> per_ip{};
    std::unordered_map<std::string, http::RateLimitPolicy> per_user{};
    // Per-tier overrides keyed by tier name (auth_sensitive, media, sync,
    // federation, admin, generic). Validated against
    // `http::rate_limit_tier_from_name()` so a typo is a parse finding.
    std::unordered_map<std::string, http::RateLimitPolicy> tier{};
    http::RateLimitPolicy default_per_ip{90U, 60U};
};

// Per-module log level overrides. Populated from `log_modules.<name>=<level>`
// keys in `merovingian.conf`. The wildcard key `*` sets the default for
// modules without an explicit entry (equivalent to
// `SingleLog::set_default_log_level`). Hot-reload is deliberately not
// supported in 0.5.0: log_modules affects startup-time bootstrap only
// and restart is required.
struct LogModulesConfig final
{
    std::unordered_map<std::string, observability::LogLevel> levels{};
};

// Out-of-process federation worker configuration.
// All inbound federation requests (except key-server) are dispatched to
// merovingian-fed-worker over an encrypted AF_UNIX socketpair channel,
// freeing the main thread pool for client-server requests.
// The worker is mandatory: startup fails if the worker process cannot be launched.
struct FederationWorkerConfig final
{
    // Maximum seconds to wait for the worker to respond.
    std::uint32_t request_timeout_seconds{120U};
    // Number of processing threads in the worker process reserved for
    // endpoints answerable entirely from the worker's own local, room-scoped
    // snapshot: make_join/make_leave/make_knock, backfill, query/directory,
    // state, state_ids, get_missing_events, hierarchy. These never block on
    // main and should always complete quickly.
    std::uint32_t threads{4U};
    // Number of processing threads reserved for endpoints that can block on a
    // synchronous IPC round-trip back to main (transaction PDUs/EDUs,
    // send_join/send_leave/send_knock, invite, and the query-provider relays:
    // profile, keys, claim_keys, user_devices, event) or on outbound HTTP to a
    // remote server. Deliberately a separate pool from `threads`: these
    // threads spend nearly all their time blocked on I/O rather than
    // consuming CPU, so sizing generously is cheap, whereas sharing a single
    // small pool between the two classes lets a burst of slow relay calls
    // starve the fast local endpoints above of any thread to run on — see
    // docs/architecture.md, "Federation worker relay pool separation".
    std::uint32_t relay_threads{32U};
    // Number of independent federation worker processes. shard=1 is the
    // Phase 1/2 single-worker behaviour. Requests are routed by
    // fnv1a_32(room_id) % shards; non-room endpoints go to shard 0. shards=0
    // is rejected at config validation time.
    std::uint32_t shards{1U};
    // Absolute path to the merovingian-fed-worker binary. Empty means use
    // the compile-time libexec default.
    std::string worker_binary{};
    // Apply the worker-specific runtime hardening sequence (RLIMIT_CORE=0,
    // PR_SET_NO_NEW_PRIVS, capability-bounding drop, worker seccomp-bpf filter
    // that denies execve/execveat) at worker startup (issue #319). Default true
    // so production workers are sandboxed; tests that exercise the worker
    // binary directly set this false to avoid the strict filter while the
    // filter allowlist is validated separately in unit tests.
    bool apply_hardening{true};
};

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
};

struct SecurityConfig final
{
    RegistrationSecurityConfig registration{};
    EncryptionSecurityConfig encryption{};
    FederationSecurityConfig federation{};
    MediaSecurityConfig media{};
    TrustSafetySecurityConfig trust_safety{};
    LoggingSecurityConfig logging{};
    SecretsSecurityConfig secrets{};
    // Server-side token expiry, in milliseconds. 0 disables expiry for that
    // token kind (treated as no expiry). Defaults: access 1h, refresh 30d. The
    // advertised expires_in_ms reads from access_token_lifetime_ms so the
    // advertised TTL matches the enforced one.
    std::int64_t access_token_lifetime_ms{3600000};
    std::int64_t refresh_token_lifetime_ms{2592000000};
};

class Config final
{
public:
    Config() = default;

    Config(ServerConfig server, ListenersConfig listeners, DatabaseConfig database, SecurityConfig security,
           ClientRateLimitsConfig client_rate_limits, LogModulesConfig log_modules,
           FederationWorkerConfig federation_worker = {}, AppserviceConfig appservice = {});

    [[nodiscard]] auto server() const noexcept -> ServerConfig const&;
    [[nodiscard]] auto server() noexcept -> ServerConfig&;
    [[nodiscard]] auto listeners() const noexcept -> ListenersConfig const&;
    [[nodiscard]] auto listeners() noexcept -> ListenersConfig&;
    [[nodiscard]] auto database() const noexcept -> DatabaseConfig const&;
    [[nodiscard]] auto database() noexcept -> DatabaseConfig&;
    [[nodiscard]] auto security() const noexcept -> SecurityConfig const&;
    [[nodiscard]] auto security() noexcept -> SecurityConfig&;
    [[nodiscard]] auto client_rate_limits() const noexcept -> ClientRateLimitsConfig const&;
    [[nodiscard]] auto client_rate_limits() noexcept -> ClientRateLimitsConfig&;
    [[nodiscard]] auto log_modules() const noexcept -> LogModulesConfig const&;
    [[nodiscard]] auto log_modules() noexcept -> LogModulesConfig&;
    [[nodiscard]] auto federation_worker() const noexcept -> FederationWorkerConfig const&;
    [[nodiscard]] auto federation_worker() noexcept -> FederationWorkerConfig&;
    [[nodiscard]] auto appservice() const noexcept -> AppserviceConfig const&;
    [[nodiscard]] auto appservice() noexcept -> AppserviceConfig&;

private:
    ServerConfig m_server{};
    ListenersConfig m_listeners{};
    DatabaseConfig m_database{};
    SecurityConfig m_security{};
    ClientRateLimitsConfig m_client_rate_limits{};
    LogModulesConfig m_log_modules{};
    FederationWorkerConfig m_federation_worker{};
    AppserviceConfig m_appservice{};
};

struct ConfigValidationFinding final
{
    std::string field{};
    std::string message{};
};

struct SizeLimitParseResult final
{
    bool valid{false};
    std::uint64_t bytes{0U};
};

struct DurationParseResult final
{
    bool valid{false};
    std::uint32_t seconds{0U};
};

[[nodiscard]] auto is_ascii_digit(char value) noexcept -> bool;
[[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool;
[[nodiscard]] auto database_backend_name(DatabaseBackend backend) noexcept -> std::string_view;
[[nodiscard]] auto parse_database_backend(std::string_view value) noexcept -> std::optional<DatabaseBackend>;
[[nodiscard]] auto database_backend_performance_warning(DatabaseBackend backend) noexcept -> std::string_view;
[[nodiscard]] auto database_role_name(DatabaseRole role) noexcept -> std::string_view;
[[nodiscard]] auto parse_database_role(std::string_view value) noexcept -> std::optional<DatabaseRole>;
[[nodiscard]] auto parse_port(std::string_view value) noexcept -> std::uint32_t;
[[nodiscard]] auto listener_host(std::string_view bind) noexcept -> std::string_view;
[[nodiscard]] auto is_loopback_host(std::string_view host) noexcept -> bool;
[[nodiscard]] auto is_valid_listener_bind(std::string_view bind) noexcept -> bool;
[[nodiscard]] auto is_public_listener(ListenerConfig const& listener) noexcept -> bool;
[[nodiscard]] auto is_safe_cleartext_listener(ListenerConfig const& listener) noexcept -> bool;
[[nodiscard]] auto is_valid_public_baseurl(std::string_view public_baseurl) noexcept -> bool;
[[nodiscard]] auto is_valid_https_url(std::string_view url) noexcept -> bool;
[[nodiscard]] auto is_valid_https_origin_url(std::string_view url) noexcept -> bool;
[[nodiscard]] auto is_valid_federation_policy(std::string_view policy) noexcept -> bool;
[[nodiscard]] auto is_valid_media_acceptance_policy(std::string_view policy) noexcept -> bool;
[[nodiscard]] auto is_valid_federation_server_name(std::string_view server_name) noexcept -> bool;
[[nodiscard]] auto parse_size_limit(std::string_view value) noexcept -> SizeLimitParseResult;
[[nodiscard]] auto parse_duration_seconds(std::string_view value) noexcept -> DurationParseResult;
[[nodiscard]] auto is_private_or_loopback_range(std::string_view range) noexcept -> bool;
[[nodiscard]] auto parse_rate_limit_policy(std::string_view value) noexcept -> std::optional<http::RateLimitPolicy>;
[[nodiscard]] auto parse_log_level(std::string_view value) noexcept -> std::optional<observability::LogLevel>;
[[nodiscard]] auto log_level_name(observability::LogLevel level) noexcept -> std::string_view;
[[nodiscard]] auto validate(Config const& config) -> std::vector<ConfigValidationFinding>;
[[nodiscard]] auto is_valid(Config const& config) -> bool;

} // namespace merovingian::config
