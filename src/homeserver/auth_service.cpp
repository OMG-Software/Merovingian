// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/auth_service.hpp"

#include "merovingian/appservice/masquerade_token.hpp"
#include "merovingian/auth/identity.hpp"
#include "merovingian/auth/password.hpp"
#include "merovingian/auth/session.hpp"
#include "merovingian/auth/token.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/constant_time.hpp"
#include "merovingian/crypto/master_key.hpp"
#include "merovingian/crypto/random.hpp"
#include "merovingian/crypto/token_key.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("auth", event, std::move(fields), severity);
    }

    [[nodiscard]] auto token_hash_is_v2(std::string_view token_hash) noexcept -> bool
    {
        return token_hash.starts_with("token-hash:v2:");
    }

    [[nodiscard]] auto token_hash_is_v3(std::string_view token_hash) noexcept -> bool
    {
        return token_hash.starts_with("token-hash:v3:");
    }

    [[nodiscard]] auto token_hash_is_v4(std::string_view token_hash) noexcept -> bool
    {
        return token_hash.starts_with("token-hash:v4:");
    }

    [[nodiscard]] auto dummy_password_hash() -> std::string const*
    {
        static auto const dummy = auth::hash_password("merovingian-invalid-login-dummy");
        return dummy.has_value() ? &(*dummy) : nullptr;
    }

    [[nodiscard]] auto user_id_from_localpart(std::string_view server_name, std::string_view localpart) -> std::string
    {
        return "@" + std::string{localpart} + ":" + std::string{server_name};
    }

    // Master key material loading is shared with the federation worker process
    // via crypto::load_master_key_material (declared in
    // merovingian/crypto/master_key.hpp) so both processes derive the same keys
    // from the same file without the material crossing the IPC boundary.

    // v3 HMAC key: derived from the operator's master key file with a distinct
    // domain separator from the v4 key (issue #322). Retained only for validating
    // legacy tokens; new tokens MUST use the v4 key. Deriving v3 from the master
    // key — instead of copying the Ed25519 signing seed — enforces key
    // separation. This invalidates stored token-hash:v3: hashes; affected
    // sessions re-login and are upgraded to v4 via upgrade_v3_access_token_to_v4.
    // If no master key is configured, v3 hashing is unavailable (fail-closed).
    // Both token HMAC keys, derived together and cached.
    //
    // #487: these derivations are on the hot path — lookup_token_hashes() calls
    // both on every authenticated request — and each one used to read the
    // operator's master key file from disk. That meant two open+read cycles of
    // the server's root secret per request, and two sodium_mlock/munlock pairs
    // of a 4 KiB SecretBuffer. Besides the blocking I/O, the mlock churn could
    // exhaust RLIMIT_MEMLOCK under concurrency, at which point SecretBuffer
    // silently falls back to unpinned (swappable) memory for the root secret.
    //
    // The cache is invalidated on the file's identity (see
    // crypto::master_key_file_identity) rather than on the path alone, so
    // replacing the master key file still takes effect without a restart — the
    // steady-state cost is one stat() instead of two full reads.
    struct TokenHmacKeys final
    {
        std::optional<crypto::TokenHmacKey> v3{};
        std::optional<crypto::TokenHmacKey> v4{};
    };

    [[nodiscard]] auto token_hmac_keys(HomeserverRuntime const& runtime) -> TokenHmacKeys
    {
        auto const& path = runtime.config.security().secrets.master_key_file;
        if (path.empty())
        {
            return {};
        }

        // Guards the cache below. Held only across the derivation itself, never
        // across a call that can block on anything but this file read.
        static auto cache_mutex = std::mutex{};
        static auto cached_identity = std::string{};
        static auto cached_keys = TokenHmacKeys{};

        auto const identity = crypto::master_key_file_identity(path);
        auto guard = std::lock_guard{cache_mutex};
        // An unreadable file yields an empty identity, which never matches the
        // cached one, so this falls through to a fresh (and failing) load rather
        // than serving keys for a file that has since become unreadable.
        if (!identity.empty() && identity == cached_identity)
        {
            return cached_keys;
        }

        auto const material = crypto::load_master_key_material(path);
        if (!material.has_value())
        {
            cached_identity.clear();
            cached_keys = {};
            return {};
        }
        auto keys = TokenHmacKeys{crypto::derive_token_hmac_key_v3(material->bytes()),
                                  crypto::derive_token_hmac_key(material->bytes())};
        cached_identity = identity;
        cached_keys = keys;
        return keys;
    }

    // v3 HMAC key: retained only for validating legacy tokens; new tokens MUST
    // use the v4 key.
    [[nodiscard]] auto token_hmac_key_v3(HomeserverRuntime const& runtime) -> std::optional<crypto::TokenHmacKey>
    {
        return token_hmac_keys(runtime).v3;
    }

    // v4 HMAC key: derived from the operator's master key file, completely
    // independent from the Ed25519 signing secret. If no master key is configured,
    // v4 hashing is unavailable and the code falls back to v3/v2.
    [[nodiscard]] auto token_hmac_key_v4(HomeserverRuntime const& runtime) -> std::optional<crypto::TokenHmacKey>
    {
        return token_hmac_keys(runtime).v4;
    }

    // Per-account failed-login throttle (#487).
    //
    // The HTTP rate limiter buckets /login per source IP, and its per-user tier is
    // keyed on the authenticated user — which, before a login succeeds, is nobody.
    // Guesses against a single account distributed over many source IPs therefore
    // accumulated against nothing at all. This tracks failures against the claimed
    // user_id instead, which is the identity an attacker is actually attacking.
    //
    // Tracking a claimed identity does mean a third party can deliberately trip an
    // account's lockout — the standard account-lockout trade-off. It is bounded
    // rather than eliminated: the lockout is a fixed short window (not escalating,
    // not sticky), any successful login clears the history, and the window is
    // deliberately short enough to be an inconvenience rather than a denial of
    // service. Operators who want different numbers currently need a rebuild;
    // exposing these as configuration is tracked in docs/todos/capability-gaps.md.
    constexpr auto max_failed_login_attempts = std::size_t{5U};
    constexpr auto failed_login_window = std::chrono::minutes{15};
    constexpr auto failed_login_lockout = std::chrono::minutes{15};

    // Drops records whose window has fully elapsed. Caller holds runtime.mutex.
    auto expire_failed_logins(std::unordered_map<std::string, FailedLoginRecord>& records,
                              std::chrono::steady_clock::time_point now) -> void
    {
        for (auto it = records.begin(); it != records.end();)
        {
            auto const idle = now - it->second.last_failure;
            it = (idle > failed_login_window && idle > failed_login_lockout) ? records.erase(it) : std::next(it);
        }
    }

    // Milliseconds remaining before this account may attempt a login again, or 0
    // when it is not locked out.
    [[nodiscard]] auto failed_login_lockout_remaining_ms(HomeserverRuntime& runtime, std::string_view user_id)
        -> std::uint64_t
    {
        auto const now = std::chrono::steady_clock::now();
        auto guard = std::lock_guard{runtime.mutex};
        auto const it = runtime.failed_logins.find(std::string{user_id});
        if (it == runtime.failed_logins.end() || it->second.count < max_failed_login_attempts)
        {
            return 0U;
        }
        auto const unlock_at = it->second.last_failure + failed_login_lockout;
        if (now >= unlock_at)
        {
            // The lockout has expired; clear it so the next failure starts a fresh
            // window rather than immediately re-locking on the stale count.
            runtime.failed_logins.erase(it);
            return 0U;
        }
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(unlock_at - now).count());
    }

    auto record_failed_login(HomeserverRuntime& runtime, std::string_view user_id) -> void
    {
        auto const now = std::chrono::steady_clock::now();
        auto guard = std::lock_guard{runtime.mutex};
        expire_failed_logins(runtime.failed_logins, now);
        auto& record = runtime.failed_logins[std::string{user_id}];
        // Failures older than the whole window do not count toward the threshold:
        // a slow trickle over days must not eventually lock a real user out.
        if (record.count == 0U || (now - record.first_failure) > failed_login_window)
        {
            record.count = 0U;
            record.first_failure = now;
        }
        ++record.count;
        record.last_failure = now;
    }

    auto clear_failed_logins(HomeserverRuntime& runtime, std::string_view user_id) -> void
    {
        auto guard = std::lock_guard{runtime.mutex};
        std::ignore = runtime.failed_logins.erase(std::string{user_id});
    }

    constexpr auto token_secret_bytes = std::size_t{32U};

    [[nodiscard]] auto issue_token_hash(HomeserverRuntime const& runtime, std::string_view token)
        -> std::optional<std::string>
    {
        // Prefer the master-key-derived v4 hash when a master key is configured.
        if (auto const key = token_hmac_key_v4(runtime); key.has_value())
        {
            if (auto const v4 = auth::hash_access_token_v4(token, *key); v4.has_value())
            {
                return v4;
            }
        }
        // No master key: fall back to the master-key-derived v3 hash for
        // backwards compatibility.
        if (auto const key = token_hmac_key_v3(runtime); key.has_value())
        {
            if (auto const v3 = auth::hash_access_token_v3(token, *key); v3.has_value())
            {
                return v3;
            }
        }
        // Signing key and master key both unavailable: fall back to the unkeyed
        // v2 hash so local operations still work. Federation will fail separately
        // if keys are broken; login should not be collateral damage.
        // #436: v2 is an unkeyed crypto_generichash — a DB leak lets an
        // attacker build an offline rainbow table and recover token
        // plaintexts. Warn loudly so operators notice the server is
        // running in this weaker degraded mode (fixable by configuring a
        // master key file) rather than discovering it silently in a
        // post-breach audit.
        log_diagnostic("token.unkeyed_hash_fallback",
                       {
                           {"reason", "no master key or signing key configured", false}
        },
                       observability::LogEventSeverity::warning);
        return auth::hash_access_token_v2(token);
    }

    [[nodiscard]] auto lookup_token_hashes(HomeserverRuntime const& runtime, std::string_view token)
        -> std::vector<std::string>
    {
        auto hashes = std::vector<std::string>{};
        if (auto const key = token_hmac_key_v4(runtime); key.has_value())
        {
            if (auto const v4 = auth::hash_access_token_v4(token, *key); v4.has_value())
            {
                hashes.push_back(*v4);
            }
        }
        if (auto const key = token_hmac_key_v3(runtime); key.has_value())
        {
            if (auto const v3 = auth::hash_access_token_v3(token, *key); v3.has_value())
            {
                hashes.push_back(*v3);
            }
        }
        if (auto const v2 = auth::hash_access_token_v2(token); v2.has_value())
        {
            hashes.push_back(*v2);
        }
        return hashes;
    }

    [[nodiscard]] auto token_hash_matches(std::string_view left, std::string_view right) noexcept -> bool
    {
        auto const same_version = (token_hash_is_v2(left) && token_hash_is_v2(right)) ||
                                  (token_hash_is_v3(left) && token_hash_is_v3(right)) ||
                                  (token_hash_is_v4(left) && token_hash_is_v4(right));
        return same_version && left.size() == right.size() && crypto::constant_time_equal(left, right);
    }

    [[nodiscard]] auto issue_token() -> std::optional<std::string>
    {
        auto const random_hex = crypto::secure_random_hex(token_secret_bytes);
        if (!random_hex.has_value())
        {
            return std::nullopt;
        }
        return "mvs_" + *random_hex;
    }

    [[nodiscard]] auto find_user(LocalDatabase& database, std::string_view user_id) -> LocalUser*
    {
        auto const iterator = std::ranges::find_if(database.users, [user_id](LocalUser const& user) {
            return user.user_id == user_id;
        });
        return iterator == database.users.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto find_user(LocalDatabase const& database, std::string_view user_id) -> LocalUser const*
    {
        auto const iterator = std::ranges::find_if(database.users, [user_id](LocalUser const& user) {
            return user.user_id == user_id;
        });
        return iterator == database.users.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto matches_any_token_hash(std::string_view stored_hash,
                                              std::vector<std::string> const& token_hashes) -> bool
    {
        return std::ranges::any_of(token_hashes, [stored_hash](std::string const& candidate) {
            return token_hash_matches(stored_hash, candidate);
        });
    }

    // SSO redirectUrl allowlist check (docs/threat-model.md, "open redirect
    // via SSO redirectUrl"): a prefix match against each operator-configured
    // HTTPS allowlist entry, terminated at a URL delimiter. Prefix (rather
    // than exact) matching lets an operator scope the allowlist down to a
    // specific path under a trusted origin when they want to; an entry that
    // names a bare origin still behaves as an origin allowlist.
    //
    // 0.12.5 audit, finding 15: the match used to be a bare starts_with(),
    // with no boundary. An entry naming a bare origin --
    // "https://client.example.com", the natural way to write "this whole
    // origin" -- therefore also matched
    // "https://client.example.com.evil.test/callback", and an attacker who
    // registered that domain received a freshly minted m.login.token.
    // Requiring the next character to be a URL delimiter closes it: `/` ends
    // the authority, `?` and `#` end the path, and end-of-string is the bare
    // origin itself. An entry that already ends in a delimiter (e.g. a
    // trailing `/`) has consumed its own boundary and needs no further check.
    [[nodiscard]] auto redirect_url_boundary_is_valid(std::string_view allowed, std::string_view redirect_url) noexcept
        -> bool
    {
        constexpr auto delimiters = std::string_view{"/?#"};
        if (!allowed.empty() && delimiters.find(allowed.back()) != std::string_view::npos)
        {
            return true;
        }
        if (redirect_url.size() == allowed.size())
        {
            return true;
        }
        return delimiters.find(redirect_url[allowed.size()]) != std::string_view::npos;
    }

    [[nodiscard]] auto redirect_url_is_allowed(config::SsoConfig const& sso, std::string_view redirect_url) noexcept
        -> bool
    {
        if (redirect_url.empty())
        {
            return false;
        }
        return std::ranges::any_of(sso.redirect_url_allowlist, [redirect_url](std::string const& allowed) {
            return !allowed.empty() && redirect_url.starts_with(allowed) &&
                   redirect_url_boundary_is_valid(allowed, redirect_url);
        });
    }

    [[nodiscard]] auto find_identity_provider(config::SsoConfig const& sso, std::string_view idp_id)
        -> config::SsoIdentityProvider const*
    {
        auto const it = std::ranges::find_if(sso.identity_providers, [idp_id](config::SsoIdentityProvider const& idp) {
            return idp.id == idp_id;
        });
        return it == sso.identity_providers.end() ? nullptr : &(*it);
    }

    [[nodiscard]] auto append_query_param(std::string url, std::string_view key, std::string_view value) -> std::string
    {
        url.push_back(url.find('?') == std::string::npos ? '?' : '&');
        url += key;
        url.push_back('=');
        url += core::percent_encode_path_component(value);
        return url;
    }

    // Strips every existing `loginToken` query parameter from `redirect_url`
    // before a new one is appended (spec step 4: "If it already includes one
    // or more loginToken parameters, they should be removed before adding
    // the new one"). Only the query string is touched; the path and any
    // fragment (there should not be one on a redirectUrl) are left intact.
    [[nodiscard]] auto strip_login_token_params(std::string_view redirect_url) -> std::string
    {
        auto const query_start = redirect_url.find('?');
        if (query_start == std::string_view::npos)
        {
            return std::string{redirect_url};
        }
        auto result = std::string{redirect_url.substr(0U, query_start)};
        auto kept = std::vector<std::string_view>{};
        auto query = redirect_url.substr(query_start + 1U);
        while (!query.empty())
        {
            auto const amp = query.find('&');
            auto const pair = query.substr(0U, amp);
            if (!pair.starts_with("loginToken="))
            {
                kept.push_back(pair);
            }
            if (amp == std::string_view::npos)
            {
                break;
            }
            query = query.substr(amp + 1U);
        }
        for (auto index = std::size_t{0U}; index < kept.size(); ++index)
        {
            result.push_back(index == 0U ? '?' : '&');
            result += kept[index];
        }
        return result;
    }

    // A session is expired when it has a finite expires_at that is now in the
    // past. nullopt means no expiry (legacy or explicitly non-expiring). Mirrors
    // the canonical policy in `auth::session::session_is_active` (src/auth/session.cpp).
    [[nodiscard]] auto is_expired(std::optional<std::chrono::system_clock::time_point> const& expires_at,
                                  std::chrono::system_clock::time_point now) noexcept -> bool
    {
        return expires_at.has_value() && *expires_at <= now;
    }

    // Computes the expiry timestamp for a freshly issued token from its
    // configured lifetime in milliseconds. A non-positive lifetime disables
    // expiry for that token kind (returns nullopt), matching the config doc.
    [[nodiscard]] auto token_expires_at(std::int64_t lifetime_ms) noexcept
        -> std::optional<std::chrono::system_clock::time_point>
    {
        if (lifetime_ms <= 0)
        {
            return std::nullopt;
        }
        return std::chrono::system_clock::now() + std::chrono::milliseconds{lifetime_ms};
    }

    [[nodiscard]] auto find_session(LocalDatabase const& database, std::vector<std::string> const& token_hashes,
                                    std::chrono::system_clock::time_point now) -> LocalSession const*
    {
        auto const iterator =
            std::ranges::find_if(database.sessions, [&token_hashes, now](LocalSession const& session) {
                return matches_any_token_hash(session.access_token_hash, token_hashes) && !session.revoked &&
                       !is_expired(session.expires_at, now);
            });
        return iterator == database.sessions.end() ? nullptr : &(*iterator);
    }

    // Disambiguates a find_session miss for audit reporting: returns true when a
    // session matching the token hash exists, is not revoked, but is expired —
    // i.e. the rejection reason is expiry rather than "no session". Distinct
    // reason strings keep the audit log actionable for #275.
    [[nodiscard]] auto session_expired_for_token(LocalDatabase const& database,
                                                 std::vector<std::string> const& token_hashes,
                                                 std::chrono::system_clock::time_point now) -> bool
    {
        auto const now_value = now;
        auto const iterator =
            std::ranges::find_if(database.sessions, [&token_hashes, now_value](LocalSession const& session) {
                return matches_any_token_hash(session.access_token_hash, token_hashes) && !session.revoked &&
                       is_expired(session.expires_at, now_value);
            });
        return iterator != database.sessions.end();
    }

    // One-shot migration of a v3 access token to the master-key-derived v4 hash.
    // Called after a presented token successfully authenticates against a stored
    // v3 hash. The old v3 row is revoked and a new v4 row is inserted, and the
    // in-memory session is updated so subsequent requests use the v4 hash. If the
    // persistence step fails, the in-memory session is left on v3 and the next
    // successful auth will retry.
    auto upgrade_v3_access_token_to_v4(HomeserverRuntime& runtime, std::string_view token,
                                       std::string_view matched_v3_hash) -> void
    {
        if (!token_hash_is_v3(matched_v3_hash))
        {
            return;
        }
        auto const key = token_hmac_key_v4(runtime);
        if (!key.has_value())
        {
            return;
        }
        auto const v4_hash = auth::hash_access_token_v4(token, *key);
        if (!v4_hash.has_value())
        {
            return;
        }

        auto upgraded_any = false;
        auto user_id = std::string{};
        auto device_id = std::string{};
        auto expires_at = std::optional<std::chrono::system_clock::time_point>{};
        for (auto& session : runtime.database.sessions)
        {
            if (!session.revoked && token_hash_matches(session.access_token_hash, matched_v3_hash))
            {
                session.access_token_hash = *v4_hash;
                user_id = session.user_id;
                device_id = session.device_id;
                expires_at = session.expires_at;
                upgraded_any = true;
            }
        }
        if (!upgraded_any)
        {
            return;
        }

        if (database::revoke_access_token(runtime.database.persistent_store, matched_v3_hash) == 0U)
        {
            return;
        }
        auto const new_row = database::PersistentAccessToken{user_id, device_id, *v4_hash, false, expires_at};
        std::ignore = database::store_access_token(runtime.database.persistent_store, new_row);
    }

    auto trim_line_ending(std::span<std::uint8_t>& token) -> void
    {
        while (!token.empty() &&
               (token.back() == static_cast<std::uint8_t>('\n') || token.back() == static_cast<std::uint8_t>('\r')))
        {
            token = token.subspan(0U, token.size() - 1U);
        }
    }

    [[nodiscard]] auto read_registration_token_file(std::string const& path) -> std::optional<core::SecretBuffer>
    {
        auto constexpr max_token_bytes = std::size_t{4096U};

        auto fd = core::FileDescriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
        if (!fd.valid())
        {
            return std::nullopt;
        }

        struct stat stat_buf{};
        if (::fstat(fd.get(), &stat_buf) != 0)
        {
            return std::nullopt;
        }
        if (!S_ISREG(stat_buf.st_mode))
        {
            return std::nullopt;
        }

        auto const file_size = static_cast<std::size_t>(stat_buf.st_size);
        if (file_size == 0U || file_size > max_token_bytes)
        {
            return std::nullopt;
        }

        auto secret = core::SecretBuffer{file_size};
        if (!secret.is_locked())
        {
            // Fail closed: if we cannot pin the plaintext into RAM we must not
            // load it at all (issue #406).
            return std::nullopt;
        }

        auto token = secret.bytes();
        auto total_read = std::size_t{0U};
        while (total_read < file_size)
        {
            auto const remaining = file_size - total_read;
            auto const n = ::read(fd.get(), token.data() + total_read, remaining);
            if (n == 0)
            {
                break;
            }
            if (n < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                return std::nullopt;
            }
            total_read += static_cast<std::size_t>(n);
        }
        if (total_read == 0U)
        {
            return std::nullopt;
        }

        token = token.subspan(0U, total_read);
        trim_line_ending(token);
        if (token.empty())
        {
            return std::nullopt;
        }

        return secret;
    }

    [[nodiscard]] auto make_user(HomeserverRuntime& runtime, std::string_view localpart, std::string_view password,
                                 bool admin, std::string_view audit_outcome, bool enforce_password_policy = true)
        -> OperationResult
    {
        auto const user_id = user_id_from_localpart(runtime.config.server().server_name, localpart);
        if (!auth::user_id_is_valid(user_id))
        {
            return make_operation_result(false, {}, "invalid user id");
        }
        // Application Service API registrations (register_appservice_user)
        // pass enforce_password_policy=false: the generated credential is a
        // random secret the appservice never sees and password login is
        // never the intended auth path for that account (masquerade/
        // m.login.application_service only), so the human-facing
        // upper/lower/digit/symbol complexity policy in
        // auth::password_is_acceptable does not apply — it exists to push
        // back on weak choices a HUMAN makes, not to gate an
        // internally-generated placeholder.
        if (enforce_password_policy && !auth::password_is_acceptable(password))
        {
            return make_operation_result(false, {}, "password rejected");
        }
        if (find_user(runtime.database, user_id) != nullptr)
        {
            return make_operation_result(false, {}, "user already exists");
        }

        auto const password_hash = auth::hash_password(password);
        if (!password_hash.has_value())
        {
            return make_operation_result(false, {}, "password hashing failed");
        }
        if (!database::store_user(runtime.database.persistent_store, {user_id, *password_hash, false, false, admin}))
        {
            return make_operation_result(false, {}, "user persistence failed", 500U);
        }
        runtime.database.users.push_back({user_id, *password_hash, false, false, admin});
        // Create empty profile so GET /profile returns real data from first login.
        std::ignore = database::store_profile(runtime.database.persistent_store, {user_id, {}, {}});
        append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.user_registered", user_id,
                           user_id, audit_outcome);
        log_diagnostic("registration.accepted",
                       {
                           {"user_id", user_id,                    false},
                           {"outcome", std::string{audit_outcome}, false}
        },
                       observability::LogEventSeverity::info);
        return make_operation_result(true, user_id);
    }

    // Shared tail of login_local_user() and login_appservice_user(): device
    // validation, account-state (locked/suspended) policy, token issuance,
    // and session persistence. The two callers differ only in how they got
    // to a validated `user` — one via password verification, the other via
    // as_token + namespace verification — everything after that point is
    // identical, so it lives here once rather than being duplicated.
    // NOLINTBEGIN(bugprone-easily-swappable-parameters)
    [[nodiscard]] auto complete_login(HomeserverRuntime& runtime, LocalUser& user, std::string_view device_id,
                                      bool with_ttl) -> OperationResult
    {
        if (!auth::device_id_is_valid(device_id))
        {
            log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                                 {
                                     {"user_id",   user.user_id,           false},
                                     {"device_id", std::string{device_id}, false},
                                     {"reason",    "invalid device id",    false}
            },
                                 observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                                 "login.rejected", user.user_id, std::string{device_id}, "invalid device id");
            return make_operation_result(false, {}, "invalid device id");
        }

        // A deactivated account can never log in again (spec: POST
        // /account/deactivate, "removing all ability for the user to login
        // again"). Checked before the reversible locked/suspended states because
        // it outranks them and is permanent.
        if (user.deactivated)
        {
            log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                                 {
                                     {"user_id",   user.user_id,           false},
                                     {"device_id", std::string{device_id}, false},
                                     {"reason",    "account deactivated",  false}
            },
                                 observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                                 "login.rejected", user.user_id, std::string{device_id}, "403:account deactivated");
            return make_operation_result(false, {}, "account deactivated", 403U);
        }

        auto state = auth::AccountState::active;
        if (user.locked)
        {
            state = auth::AccountState::locked;
        }
        if (user.suspended)
        {
            state = auth::AccountState::suspended;
        }
        auto const login = auth::login_policy({user.user_id, state});
        if (!login.allowed)
        {
            // Account locked or suspended: still a 403, not a 400.
            log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                                 {
                                     {"user_id",   user.user_id,           false},
                                     {"device_id", std::string{device_id}, false},
                                     {"status",    "403",                  false},
                                     {"reason",    login.reason,           false}
            },
                                 observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                                 "login.rejected", user.user_id, std::string{device_id}, "403:" + login.reason);
            return make_operation_result(false, {}, "invalid login", 403U);
        }

        auto const token = issue_token();
        if (!token.has_value())
        {
            log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                                 {
                                     {"user_id",   user.user_id,              false},
                                     {"device_id", std::string{device_id},    false},
                                     {"reason",    "token generation failed", false}
            },
                                 observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                                 "login.rejected", user.user_id, std::string{device_id}, "token generation failed");
            return make_operation_result(false, {}, "token generation failed");
        }
        auto const token_hash = issue_token_hash(runtime, *token);
        if (!token_hash.has_value())
        {
            log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                                 {
                                     {"user_id",   user.user_id,           false},
                                     {"device_id", std::string{device_id}, false},
                                     {"reason",    "token hashing failed", false}
            },
                                 observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                                 "login.rejected", user.user_id, std::string{device_id}, "token hashing failed");
            return make_operation_result(false, {}, "token hashing failed");
        }
        auto const device_exists = std::ranges::any_of(
            runtime.database.persistent_store.devices, [&user, device_id](database::PersistentDevice const& device) {
                return device.user_id == user.user_id && device.device_id == device_id;
            });
        auto device = std::optional<database::PersistentDevice>{};
        if (!device_exists)
        {
            device = database::PersistentDevice{user.user_id, std::string{device_id}, std::string{device_id}};
        }
        // Only honour the configured TTL when the client opted into refresh tokens.
        // Spec §5.6.2: servers SHOULD NOT expire tokens without co-issuing a refresh token.
        auto const access_expires_at =
            token_expires_at(with_ttl ? runtime.config.security().access_token_lifetime_ms : 0LL);
        if (!database::store_device_and_access_token(
                runtime.database.persistent_store, std::move(device),
                {user.user_id, std::string{device_id}, *token_hash, false, access_expires_at}))
        {
            log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                                 {
                                     {"user_id",   user.user_id,               false},
                                     {"device_id", std::string{device_id},     false},
                                     {"status",    "500",                      false},
                                     {"reason",    "login persistence failed", false}
            },
                                 observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                                 "login.rejected", user.user_id, std::string{device_id},
                                 "500:login persistence failed");
            return make_operation_result(false, {}, "login persistence failed", 500U);
        }
        ++runtime.database.next_session_id;
        runtime.database.sessions.push_back(
            {user.user_id, std::string{device_id}, *token_hash, false, access_expires_at});
        append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.login", user.user_id,
                           std::string{device_id}, "accepted");
        log_diagnostic("login.accepted",
                       {
                           {"user_id",   user.user_id,           false},
                           {"device_id", std::string{device_id}, false}
        },
                       observability::LogEventSeverity::info);
        return make_operation_result(true, *token);
    }
    // NOLINTEND(bugprone-easily-swappable-parameters)

} // namespace

namespace
{

    // Identifies a particular *version* of a file on disk. The registration
    // token hash is cached because Argon2id on every registration would be a
    // self-inflicted DoS, but caching by path alone made the cache outlive the
    // secret it summarised: an operator who rotated the token kept serving the
    // old one until the next restart, which is precisely the failure that
    // credential rotation exists to prevent.
    //
    // Sub-second mtime and size are both included because a rotation is
    // typically a same-second rewrite, which an mtime-seconds check alone would
    // miss; device and inode catch an atomic replace-by-rename.
    struct RegistrationTokenFileIdentity final
    {
        std::uint64_t device{0U};
        std::uint64_t inode{0U};
        std::int64_t modified_seconds{0};
        std::int64_t modified_nanoseconds{0};
        std::uint64_t size{0U};

        [[nodiscard]] auto operator==(RegistrationTokenFileIdentity const&) const noexcept -> bool = default;
    };

    [[nodiscard]] auto registration_token_file_identity(std::string const& path)
        -> std::optional<RegistrationTokenFileIdentity>
    {
        struct ::stat info{};
        if (::stat(path.c_str(), &info) != 0)
        {
            return std::nullopt;
        }
        return RegistrationTokenFileIdentity{
            static_cast<std::uint64_t>(info.st_dev), static_cast<std::uint64_t>(info.st_ino),
            static_cast<std::int64_t>(info.st_mtim.tv_sec), static_cast<std::int64_t>(info.st_mtim.tv_nsec),
            static_cast<std::uint64_t>(info.st_size)};
    }

    struct CachedRegistrationToken final
    {
        RegistrationTokenFileIdentity identity{};
        std::string hash{};
    };

} // namespace

// Load the registration token from disk, hash it with Argon2id, and cache the
// hash against the identity of the file version it was derived from.  The
// plaintext token is zeroised after hashing so it does not remain in server
// memory.  Exposed in auth_service.hpp so the registration-token validity
// endpoint compares via the hash rather than holding the plaintext token on the
// request path.
//
// A stat() per call is the price of honouring rotation; the Argon2id hash is
// what the cache is actually protecting.
[[nodiscard]] auto load_hashed_registration_token(config::RegistrationSecurityConfig const& registration)
    -> std::optional<std::string>
{
    if (registration.token_file.empty())
    {
        return std::nullopt;
    }

    static auto mutex = std::mutex{};
    static auto cache = std::unordered_map<std::string, CachedRegistrationToken>{};

    auto const identity_before = registration_token_file_identity(registration.token_file);

    auto lock = std::lock_guard<std::mutex>{mutex};
    auto const it = cache.find(registration.token_file);
    if (it != cache.end() && identity_before.has_value() && it->second.identity == *identity_before)
    {
        return it->second.hash;
    }

    auto secret = read_registration_token_file(registration.token_file);
    if (!secret.has_value())
    {
        return std::nullopt;
    }

    auto token = secret->bytes();
    trim_line_ending(token);
    auto hash = auth::hash_registration_token(token);

    // The SecretBuffer destructor zeroises the plaintext token and releases the
    // mlock when `secret` goes out of scope.  We never keep the plaintext in an
    // unpinned std::string.

    if (!hash.has_value())
    {
        return std::nullopt;
    }

    // Only cache when the file did not change under us between the two stats.
    // Caching a hash against an identity it was not derived from would pin a
    // stale token permanently — worse than not caching at all.
    auto const identity_after = registration_token_file_identity(registration.token_file);
    if (identity_before.has_value() && identity_after.has_value() && *identity_before == *identity_after)
    {
        cache.insert_or_assign(registration.token_file, CachedRegistrationToken{*identity_after, *hash});
    }
    else
    {
        cache.erase(registration.token_file);
    }
    return hash;
}

auto register_local_user(HomeserverRuntime& runtime, std::string_view localpart, std::string_view password,
                         std::string_view registration_token) -> OperationResult
{
    auto const user_id = user_id_from_localpart(runtime.config.server().server_name, localpart);
    auto const& registration = runtime.config.security().registration;
    auto const policy =
        auth::registration_policy({registration.enabled, registration.require_token, !registration_token.empty()});
    if (!policy.allowed)
    {
        auto const status = policy.reason == "registration token required" ? 403U : 400U;
        auto const reason = policy.reason == "registration disabled" ? "registration_disabled" : policy.reason;
        return make_operation_result(false, {}, reason, static_cast<std::uint16_t>(status));
    }

    auto const local_rule = find_policy_rule(runtime, "registration", user_id);
    auto const blocked_by_local_policy = local_rule.has_value() && local_rule->action != "allow";
    auto const decision = trust_safety::evaluate_registration_policy(
        {user_id, "127.0.0.1", runtime.config.security().registration.enabled, blocked_by_local_policy,
         resolve_policy_server_hook(runtime, trust_safety::PolicySurface::registration, user_id)});
    if (!decision.allowed)
    {
        return make_operation_result(false, {}, decision.reason.code, 403U);
    }

    if (registration.require_token)
    {
        // AUTH-4: registration-token verification is Argon2id and must respect
        // the same admission cap as /login. Shed load with 429 before doing any
        // hash work.
        auto const argon_slot = runtime.argon2id_admission->try_acquire();
        if (!argon_slot)
        {
            auto throttled = make_operation_result(false, {}, "too many concurrent authentication attempts", 429U);
            throttled.retry_after_ms = 1000U;
            return throttled;
        }
        auto const expected_hash = load_hashed_registration_token(registration);
        auto const token_ok = [expected_hash = expected_hash.value_or(std::string{}), registration_token]() {
            // AUTH-4: registration-token verification is also Argon2id; release
            // the runtime mutex while it runs.
            auto const released = merovingian::homeserver::RuntimeLockRelease{};
            return !expected_hash.empty() && auth::registration_token_matches(expected_hash, registration_token);
        }();
        if (!token_ok)
        {
            return make_operation_result(false, {}, "registration token rejected", 403U);
        }
    }

    return make_user(runtime, localpart, password, false, "created");
}

auto bootstrap_admin_user(HomeserverRuntime& runtime, std::string_view localpart, std::string_view password)
    -> OperationResult
{
    return make_user(runtime, localpart, password, true, "bootstrapped_admin");
}

// Application Service API (Matrix v1.19) §"Server admin style permissions":
// `POST /register` with `type: m.login.application_service` bypasses the
// ordinary registration flow entirely (no registration-token UIA, no
// trust-safety registration policy hook, no captcha) — "This involves
// bypassing the registration flows entirely." The caller (client_server.cpp)
// has already verified the presented as_token and that `localpart` falls
// within the appservice's namespace (or is its own sender_localpart) before
// calling this.
//
// Passwordless per spec ("have a 'passwordless' user"): the account is
// created with a freshly generated random password that is immediately
// discarded and never returned to the caller, so `m.login.password` can
// never succeed for it by chance — the appservice authenticates as this
// user exclusively via its as_token (masquerade) or m.login.application_service.
auto register_appservice_user(HomeserverRuntime& runtime, std::string_view localpart) -> OperationResult
{
    auto const user_id = user_id_from_localpart(runtime.config.server().server_name, localpart);
    if (find_user(runtime.database, user_id) != nullptr)
    {
        return make_operation_result(false, {}, "user already exists");
    }
    auto const random_password = crypto::secure_random_hex(32U);
    if (!random_password.has_value())
    {
        return make_operation_result(false, {}, "password hashing failed");
    }
    return make_user(runtime, localpart, *random_password, false, "created_by_appservice",
                     /*enforce_password_policy=*/false);
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
auto login_local_user(HomeserverRuntime& runtime, std::string_view user_id, std::string_view password,
                      std::string_view device_id, bool with_ttl) -> OperationResult
{
    log_diagnostic("login.started",
                   {
                       {"user_id",   std::string{user_id},   false},
                       {"device_id", std::string{device_id}, false}
    });

    // #487: /login was throttled per source IP only. The per-user rate-limit tier
    // is keyed on the authenticated user, which pre-login is nobody, so guesses
    // against one account spread across many source IPs accumulated nowhere.
    if (auto const retry_after_ms = failed_login_lockout_remaining_ms(runtime, user_id); retry_after_ms > 0U)
    {
        log_diagnostic_audit(runtime.database, "auth", "login.throttled",
                             {
                                 {"user_id",        std::string{user_id},           false},
                                 {"device_id",      std::string{device_id},         false},
                                 {"retry_after_ms", std::to_string(retry_after_ms), false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "login.throttled", std::string{user_id}, std::string{device_id},
                             "429:too many failed login attempts");
        auto throttled = make_operation_result(false, {}, "too many failed login attempts", 429U);
        // Carry the delay already computed above so the caller can render the
        // Matrix-standard M_LIMIT_EXCEEDED with retry_after_ms rather than a
        // 429 a compliant client cannot schedule a retry from.
        throttled.retry_after_ms = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(retry_after_ms, std::numeric_limits<std::uint32_t>::max()));
        return throttled;
    }

    // Snapshot the claimed identity and the hash to verify against. The user
    // pointer itself must not outlive the RuntimeLockRelease below: the vector
    // may be reallocated while runtime.mutex is dropped around Argon2id.
    auto const verified_user_id = std::string{user_id};
    auto* initial_user = find_user(runtime.database, verified_user_id);
    auto const password_hash =
        std::string{initial_user != nullptr ? initial_user->password_hash : *dummy_password_hash()};
    // AUTH-4: bound concurrent Argon2id work before it can start. Shedding load
    // here returns 429/M_LIMIT_EXCEEDED and never counts as a failed login, so
    // an admission-saturated pile-on does not also exhaust the lockout budget.
    auto const argon_slot = runtime.argon2id_admission->try_acquire();
    if (!argon_slot)
    {
        auto throttled = make_operation_result(false, {}, "too many concurrent authentication attempts", 429U);
        throttled.retry_after_ms = 1000U;
        return throttled;
    }
    // AUTH-4: release the runtime mutex around Argon2id verification so a pile
    // of login attempts cannot serialise every other request. Snapshot the hash
    // by value first; then verify outside the lock.
    auto password_valid = false;
    {
        auto const released = merovingian::homeserver::RuntimeLockRelease{};
        password_valid = auth::password_matches(password_hash, password);
    }
    // RuntimeLockRelease has re-acquired the lock. Re-find the user and insist
    // the stored password hash is still the one we just verified. A concurrent
    // password change (or account deletion) during Argon2id must not issue a
    // session against the old credentials.
    auto* user = find_user(runtime.database, verified_user_id);
    if (user == nullptr || user->password_hash != password_hash || !password_valid)
    {
        // Counted against the *claimed* user_id whether or not it exists, so the
        // lockout cannot be used to probe which accounts are real.
        record_failed_login(runtime, verified_user_id);
        auto const audit_reason = user == nullptr ? "unknown user" : "bad credentials";
        // Matrix spec §5.7.2: login failures must be 403 M_FORBIDDEN.
        log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                             {
                                 {"user_id",   std::string{user_id},   false},
                                 {"device_id", std::string{device_id}, false},
                                 {"status",    "403",                  false},
                                 {"reason",    audit_reason,           false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "login.rejected", std::string{user_id}, std::string{device_id},
                             std::string{"403:"} + audit_reason);
        return make_operation_result(false, {}, "invalid login", 403U);
    }
    // A correct password clears the account's failure history, so an interrupted
    // legitimate login attempt cannot accumulate toward a lockout.
    clear_failed_logins(runtime, user->user_id);
    return login_local_user_by_id(runtime, user->user_id, device_id, with_ttl);
}
// NOLINTEND(bugprone-easily-swappable-parameters)

// Grants a session for an already-authenticated `user_id`: device-id
// validation, the account lock/suspend gate, token issuance/persistence,
// and session bookkeeping. This is the second half of login_local_user
// (everything after its password check), factored out so the SSO
// login-token exchange (redeem_login_token has already established the
// caller's identity) can share it instead of duplicating the account-state
// gate and token-issuance plumbing. Neither caller re-checks a credential
// here -- this function trusts that `user_id` is already verified and only
// answers "should this account be allowed a new session, and if so, issue
// one."
auto login_local_user_by_id(HomeserverRuntime& runtime, std::string_view user_id, std::string_view device_id,
                            bool with_ttl) -> OperationResult
{
    auto* user = find_user(runtime.database, user_id);
    if (user == nullptr)
    {
        log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                             {
                                 {"user_id",   std::string{user_id},   false},
                                 {"device_id", std::string{device_id}, false},
                                 {"reason",    "unknown user",         false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "login.rejected", std::string{user_id}, std::string{device_id}, "403:unknown user");
        return make_operation_result(false, {}, "invalid login", 403U);
    }
    if (!auth::device_id_is_valid(device_id))
    {
        log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                             {
                                 {"user_id",   std::string{user_id},   false},
                                 {"device_id", std::string{device_id}, false},
                                 {"reason",    "invalid device id",    false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "login.rejected", std::string{user_id}, std::string{device_id}, "invalid device id");
        return make_operation_result(false, {}, "invalid device id");
    }

    // See the deactivation gate in the shared helper above: permanent and
    // outranking the reversible moderation states.
    if (user->deactivated)
    {
        log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                             {
                                 {"user_id",   std::string{user_id},   false},
                                 {"device_id", std::string{device_id}, false},
                                 {"reason",    "account deactivated",  false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "login.rejected", std::string{user_id}, std::string{device_id}, "403:account deactivated");
        return make_operation_result(false, {}, "account deactivated", 403U);
    }

    auto state = auth::AccountState::active;
    if (user->locked)
    {
        state = auth::AccountState::locked;
    }
    if (user->suspended)
    {
        state = auth::AccountState::suspended;
    }
    auto const login = auth::login_policy({user->user_id, state});
    if (!login.allowed)
    {
        // Account locked or suspended: still a 403, not a 400.
        log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                             {
                                 {"user_id",   user->user_id,          false},
                                 {"device_id", std::string{device_id}, false},
                                 {"status",    "403",                  false},
                                 {"reason",    login.reason,           false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "login.rejected", user->user_id, std::string{device_id}, "403:" + login.reason);
        return make_operation_result(false, {}, "invalid login", 403U);
    }

    auto const token = issue_token();
    if (!token.has_value())
    {
        log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                             {
                                 {"user_id",   user->user_id,             false},
                                 {"device_id", std::string{device_id},    false},
                                 {"reason",    "token generation failed", false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "login.rejected", user->user_id, std::string{device_id}, "token generation failed");
        return make_operation_result(false, {}, "token generation failed");
    }
    auto const token_hash = issue_token_hash(runtime, *token);
    if (!token_hash.has_value())
    {
        log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                             {
                                 {"user_id",   user->user_id,          false},
                                 {"device_id", std::string{device_id}, false},
                                 {"reason",    "token hashing failed", false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "login.rejected", user->user_id, std::string{device_id}, "token hashing failed");
        return make_operation_result(false, {}, "token hashing failed");
    }
    auto const device_exists = std::ranges::any_of(
        runtime.database.persistent_store.devices, [user, device_id](database::PersistentDevice const& device) {
            return device.user_id == user->user_id && device.device_id == device_id;
        });
    auto device = std::optional<database::PersistentDevice>{};
    if (!device_exists)
    {
        device = database::PersistentDevice{user->user_id, std::string{device_id}, std::string{device_id}};
    }
    // Only honour the configured TTL when the client opted into refresh tokens.
    // Spec §5.6.2: servers SHOULD NOT expire tokens without co-issuing a refresh token.
    auto const access_expires_at =
        token_expires_at(with_ttl ? runtime.config.security().access_token_lifetime_ms : 0LL);
    if (!database::store_device_and_access_token(
            runtime.database.persistent_store, std::move(device),
            {user->user_id, std::string{device_id}, *token_hash, false, access_expires_at}))
    {
        log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                             {
                                 {"user_id",   user->user_id,              false},
                                 {"device_id", std::string{device_id},     false},
                                 {"status",    "500",                      false},
                                 {"reason",    "login persistence failed", false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "login.rejected", user->user_id, std::string{device_id}, "500:login persistence failed");
        return make_operation_result(false, {}, "login persistence failed", 500U);
    }
    ++runtime.database.next_session_id;
    runtime.database.sessions.push_back({user->user_id, std::string{device_id}, *token_hash, false, access_expires_at});
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.login", user->user_id,
                       std::string{device_id}, "accepted");
    log_diagnostic("login.accepted",
                   {
                       {"user_id",   user->user_id,          false},
                       {"device_id", std::string{device_id}, false}
    },
                   observability::LogEventSeverity::info);
    return make_operation_result(true, *token);
}
// NOLINTEND(bugprone-easily-swappable-parameters)

// Application Service API (Matrix v1.19) §"Server admin style permissions":
// logs in as `user_id` WITHOUT a password check, for a `POST /login` call
// authenticated with an appservice's `as_token` and
// `type: m.login.application_service`. The caller (client_server.cpp) is
// responsible for verifying the as_token and that `user_id` falls within
// the appservice's namespace (or is its own sender_localpart) before
// calling this — the same division of responsibility as
// register_appservice_user below. Locked/suspended accounts are still
// rejected: masquerading does not bypass account-state moderation.
auto login_appservice_user(HomeserverRuntime& runtime, std::string_view user_id, std::string_view device_id)
    -> OperationResult
{
    log_diagnostic("login.appservice.started",
                   {
                       {"user_id",   std::string{user_id},   false},
                       {"device_id", std::string{device_id}, false}
    });
    auto* user = find_user(runtime.database, user_id);
    if (user == nullptr)
    {
        log_diagnostic_audit(runtime.database, "auth", "login.rejected",
                             {
                                 {"user_id",   std::string{user_id},   false},
                                 {"device_id", std::string{device_id}, false},
                                 {"status",    "403",                  false},
                                 {"reason",    "unknown user",         false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "login.rejected", std::string{user_id}, std::string{device_id}, "403:unknown user");
        return make_operation_result(false, {}, "invalid login", 403U);
    }
    return complete_login(runtime, *user, device_id, false);
}

auto issue_refresh_token_for_session(HomeserverRuntime& runtime, std::string_view user_id, std::string_view device_id)
    -> OperationResult
{
    if (find_user(runtime.database, user_id) == nullptr || !auth::device_id_is_valid(device_id))
    {
        return make_operation_result(false, {}, "invalid refresh subject", 400U);
    }
    auto const refresh_token = issue_token();
    if (!refresh_token.has_value())
    {
        return make_operation_result(false, {}, "refresh token generation failed", 500U);
    }
    auto const refresh_hash = issue_token_hash(runtime, *refresh_token);
    if (!refresh_hash.has_value())
    {
        return make_operation_result(false, {}, "refresh token hashing failed", 500U);
    }
    auto const refresh_expires_at = token_expires_at(runtime.config.security().refresh_token_lifetime_ms);
    if (!database::store_refresh_token(runtime.database.persistent_store, {std::string{user_id}, std::string{device_id},
                                                                           *refresh_hash, false, refresh_expires_at}))
    {
        return make_operation_result(false, {}, "refresh token persistence failed", 500U);
    }
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.refresh.issue", std::string{user_id},
                       std::string{device_id}, "issued");
    return make_operation_result(true, *refresh_token);
}

auto refresh_local_session(HomeserverRuntime& runtime, std::string_view refresh_token) -> SessionRefreshResult
{
    auto const refresh_hashes = lookup_token_hashes(runtime, refresh_token);
    if (refresh_hashes.empty())
    {
        return {false, 401U, {}, {}, {}, {}, "unauthenticated"};
    }

    auto const now = std::chrono::system_clock::now();
    auto const refresh = std::ranges::find_if(runtime.database.persistent_store.refresh_tokens,
                                              [&refresh_hashes](database::PersistentRefreshToken const& row) {
                                                  return matches_any_token_hash(row.token_hash, refresh_hashes);
                                              });
    if (refresh == runtime.database.persistent_store.refresh_tokens.end() || is_expired(refresh->expires_at, now))
    {
        return {false, 401U, {}, {}, {}, {}, "refresh token rejected"};
    }

    auto const user_id = refresh->user_id;
    auto const device_id = refresh->device_id;
    // Copied now: storing the new tokens below may reallocate the vector.
    auto const presented_hash = refresh->token_hash;
    auto const predecessor_hash = refresh->predecessor_hash;

    // ADR-0074 (Matrix v1.19 CS API, refresh tokens): "The homeserver SHOULD
    // consider that the session is compromised if an old, invalidated refresh
    // token is used, and SHOULD revoke the session." A refresh token is
    // invalidated once the pair minted from it has been used, by logout, or by
    // a password change, so presenting one ends the device's session.
    if (refresh->revoked)
    {
        std::ignore = database::revoke_access_tokens_for_device(runtime.database.persistent_store, user_id, device_id);
        std::ignore = database::revoke_refresh_tokens_for_device(runtime.database.persistent_store, user_id, device_id);
        for (auto& session : runtime.database.sessions)
        {
            if (session.user_id == user_id && session.device_id == device_id)
            {
                session.revoked = true;
            }
        }
        append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.refresh.reuse_detected", user_id,
                           device_id, "retired refresh token presented; session revoked");
        return {false, 401U, {}, {}, {}, {}, "refresh token rejected"};
    }
    auto const* refresh_user = find_user(runtime.database, user_id);
    if (refresh_user == nullptr || !auth::device_id_is_valid(device_id))
    {
        return {false, 401U, {}, {}, {}, {}, "refresh subject rejected"};
    }
    // A deactivated account must never mint a new credential, whatever state its
    // stored rows are in. Checking only that the user still exists made a single
    // failed revocation during deactivation directly exploitable; this is the
    // second, independent gate that makes that failure non-exploitable rather
    // than merely unlikely.
    if (refresh_user->deactivated)
    {
        return {false, 401U, {}, {}, {}, {}, "account deactivated"};
    }
    // Spec §Account locking: a locked account MUST receive 401 M_USER_LOCKED
    // with soft_logout on every Client-Server API except POST /logout and
    // POST /logout/all, and §Soft logout is explicit that such a client
    // "cannot obtain a new access token until the account has been unlocked".
    // The dispatcher's moderation gate authenticates with an access token, so
    // it never sees /refresh — without this check a locked account keeps
    // minting access tokens indefinitely and the lock is defeated everywhere.
    //
    // Suspension is deliberately not a refusal. The spec leaves a suspended
    // account's permitted actions to the implementation but SHOULD-lists
    // logging in, creating further sessions, and reading through /sync and
    // /messages; this server's own suspension allowlist already permits
    // POST /login, which mints unlimited fresh access tokens. Refusing a
    // rotation while permitting a fresh login would deny the reads the spec
    // asks servers to preserve and buy nothing.
    if (refresh_user->locked)
    {
        append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.refresh.rejected", user_id,
                           device_id, "account locked");
        return {false, 401U, {}, {}, {}, {}, "This account has been locked", "M_USER_LOCKED", true};
    }
    // A refresh token must name a device that still exists. The token lifecycle
    // binds every credential to a device row; a token that outlives its row can
    // only have got there through a failure (a partial deactivation, a
    // revocation race, a leak), and honouring it would resurrect a session for
    // a device the user believes is gone. Fail closed rather than recreate it.
    auto const device_exists = std::ranges::any_of(
        runtime.database.persistent_store.devices, [&user_id, &device_id](database::PersistentDevice const& device) {
            return device.user_id == user_id && device.device_id == device_id;
        });
    if (!device_exists)
    {
        append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.refresh.rejected", user_id,
                           device_id, "device no longer exists");
        return {false, 401U, {}, {}, {}, {}, "refresh device rejected"};
    }
    // ADR-0074: "The old refresh token remains valid until the new access token
    // or refresh token is used, at which point the old refresh token is
    // revoked." So the presented token is not revoked here: the client may not
    // receive this response and must be able to retry. Instead:
    //   - using this token completes the rotation that minted it, so its own
    //     predecessor is revoked now;
    //   - a pair minted from this same token by an earlier request whose
    //     response was lost is superseded by the pair minted below.
    if (!predecessor_hash.empty())
    {
        std::ignore = database::revoke_refresh_token(runtime.database.persistent_store, predecessor_hash);
    }
    std::ignore = database::revoke_refresh_tokens_with_predecessor(runtime.database.persistent_store, presented_hash);
    // The device's earlier access tokens may be revoked at once (the spec
    // leaves this to the server); that includes a lost earlier pair's token.
    std::ignore = database::revoke_access_tokens_for_device(runtime.database.persistent_store, user_id, device_id);
    for (auto& session : runtime.database.sessions)
    {
        if (session.user_id == user_id && session.device_id == device_id)
        {
            session.revoked = true;
        }
    }

    auto const access_token = issue_token();
    auto const new_refresh_token = issue_token();
    if (!access_token.has_value() || !new_refresh_token.has_value())
    {
        return {false, 500U, {}, {}, {}, {}, "token generation failed"};
    }
    auto const access_hash = issue_token_hash(runtime, *access_token);
    auto const new_refresh_hash = issue_token_hash(runtime, *new_refresh_token);
    if (!access_hash.has_value() || !new_refresh_hash.has_value())
    {
        return {false, 500U, {}, {}, {}, {}, "token hashing failed"};
    }
    auto const new_access_expires_at = token_expires_at(runtime.config.security().access_token_lifetime_ms);
    auto const new_refresh_expires_at = token_expires_at(runtime.config.security().refresh_token_lifetime_ms);
    if (!database::store_access_token(runtime.database.persistent_store, {user_id, device_id, *access_hash, false,
                                                                          new_access_expires_at, presented_hash}) ||
        !database::store_refresh_token(runtime.database.persistent_store, {user_id, device_id, *new_refresh_hash, false,
                                                                           new_refresh_expires_at, presented_hash}))
    {
        return {false, 500U, {}, {}, {}, {}, "refreshed token persistence failed"};
    }

    ++runtime.database.next_session_id;
    runtime.database.sessions.push_back(
        {user_id, device_id, *access_hash, false, new_access_expires_at, presented_hash});
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.refresh", user_id, device_id,
                       "rotated");
    return {true, 200U, *access_token, *new_refresh_token, user_id, device_id, {}};
}

auto authenticated_user(HomeserverRuntime& runtime, std::string_view access_token) -> std::optional<std::string>
{
    // Application Service API (Matrix v1.19) identity-assertion masquerade.
    // client_server.cpp's dispatch entry point synthesizes this internal
    // token shape exactly once per request, only after verifying the
    // presented as_token via constant-time comparison against the registry
    // and validating the asserted user_id against the appservice's
    // namespaces — see appservice/masquerade_token.hpp's doc comment for why
    // a raw externally-supplied token in this shape can never reach here.
    // Re-validated here anyway (appservice still registered, user_id still
    // within its namespace) as defense in depth against a stale token
    // surviving a config reload that removed/changed the appservice.
    if (auto const identity = appservice::decode_masquerade_token(access_token); identity.has_value())
    {
        auto const* registration = runtime.appservices.find_by_id(identity->appservice_id);
        if (registration == nullptr ||
            !appservice::appservice_owns_user(*registration, runtime.config.server().server_name, identity->user_id))
        {
            return std::nullopt;
        }
        return identity->user_id;
    }

    auto const token_hashes = lookup_token_hashes(runtime, access_token);
    if (token_hashes.empty())
    {
        // Security: never pass the raw bearer token to the audit log.
        // When hashing itself fails we have no identity to report — use "<unknown>".
        log_diagnostic_audit(runtime.database, "auth", "access_token.rejected",
                             {
                                 {"reason", "token hashing failed", false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "access_token.rejected", "<unknown>", "<unknown>", "token hashing failed");
        return std::nullopt;
    }
    auto const now = std::chrono::system_clock::now();
    auto const* session = find_session(runtime.database, token_hashes, now);
    if (session == nullptr)
    {
        // Security: no live session for this token hash — report without leaking the raw token.
        // Distinguish an expired (but otherwise valid) token from a genuinely unknown one so
        // the audit log is actionable for #275 server-side token expiry.
        auto const rejection_reason = session_expired_for_token(runtime.database, token_hashes, now)
                                          ? std::string{"token expired"}
                                          : std::string{"session not found"};
        log_diagnostic_audit(runtime.database, "auth", "access_token.rejected",
                             {
                                 {"reason", rejection_reason, false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "access_token.rejected", "<unknown>", "<unknown>", rejection_reason);
        return std::nullopt;
    }
    // If the session still uses a v3 hash, opportunistically rehash to the
    // master-key-derived v4 hash on successful use. Post-#322 the v3 key is
    // itself master-key-derived (no longer the Ed25519 seed); legacy seed-derived
    // v3 hashes fail closed earlier and force a re-login. This path migrates any
    // remaining v3 sessions (e.g. v3 hashes created under the new key) to v4.
    upgrade_v3_access_token_to_v4(runtime, access_token, session->access_token_hash);
    if (find_user(runtime.database, session->user_id) == nullptr)
    {
        // Security: session exists but the owning user record is gone — use the
        // user_id from the session record, not the raw bearer token.
        log_diagnostic_audit(runtime.database, "auth", "access_token.rejected",
                             {
                                 {"reason", "user not found", false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "access_token.rejected", session->user_id, session->user_id, "user not found");
        return std::nullopt;
    }
    // ADR-0074: the first use of an access token minted by POST /refresh
    // completes that rotation, so the refresh token it replaced is revoked
    // ("The old refresh token remains valid until the new access token or
    // refresh token is used"). Every authenticated route passes through here.
    if (!session->predecessor_refresh_hash.empty())
    {
        auto const hash = session->access_token_hash;
        std::ignore =
            database::revoke_refresh_token(runtime.database.persistent_store, session->predecessor_refresh_hash);
        // Cleared in place (no reallocation, so `session` stays valid); after a
        // restart hydration restores the field and the idempotent revocation
        // runs once more.
        for (auto& live : runtime.database.sessions)
        {
            if (live.access_token_hash == hash)
            {
                live.predecessor_refresh_hash.clear();
            }
        }
    }
    log_diagnostic("access_token.accepted",
                   {
                       {"user_id",   session->user_id,   false},
                       {"device_id", session->device_id, false}
    });
    return session->user_id;
}

auto authenticated_session(HomeserverRuntime const& runtime, std::string_view access_token)
    -> std::optional<LocalSession>
{
    // See authenticated_user() above for why this branch is safe.
    if (auto const identity = appservice::decode_masquerade_token(access_token); identity.has_value())
    {
        auto const* registration = runtime.appservices.find_by_id(identity->appservice_id);
        if (registration == nullptr ||
            !appservice::appservice_owns_user(*registration, runtime.config.server().server_name, identity->user_id))
        {
            return std::nullopt;
        }
        // No DB-backed access-token hash exists for a masquerade identity —
        // it is not a real session row. access_token_hash is left empty;
        // callers of authenticated_session must not treat it as a lookup
        // key back into the session store.
        return LocalSession{identity->user_id, identity->device_id, {}, false, std::nullopt};
    }

    auto const token_hashes = lookup_token_hashes(runtime, access_token);
    if (token_hashes.empty())
    {
        return std::nullopt;
    }
    auto const* session = find_session(runtime.database, token_hashes, std::chrono::system_clock::now());
    if (session == nullptr || find_user(runtime.database, session->user_id) == nullptr)
    {
        return std::nullopt;
    }
    return *session;
}

auto authenticated_admin_user(HomeserverRuntime const& runtime, std::string_view access_token)
    -> std::optional<std::string>
{
    // `authenticated_user` is non-const because the audit-routing helper
    // (0.5.0) writes a row to audit_log on token rejection. The admin
    // path holds the runtime mutex; the const cast is safe because
    // `audit_log` is an append-only log that does not race with the
    // admin lookup.
    auto const user_id = authenticated_user(const_cast<HomeserverRuntime&>(runtime), access_token);
    auto const* user = user_id.has_value() ? find_user(runtime.database, *user_id) : nullptr;
    if (user == nullptr || !user->admin)
    {
        return std::nullopt;
    }
    return user->user_id;
}

auto require_admin(HomeserverRuntime& runtime, std::string_view access_token) -> AdminAuthResult
{
    // Two-step gate so /_merovingian/admin/* routes return 401 for a
    // missing/expired/unknown token and 403 for a valid token whose user is
    // not an admin — matching the /_matrix/client/v3/admin/* convention.
    // authenticated_user already emits the access_token.rejected audit event
    // for the missing-token case, so no duplicate logging here.
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return {std::nullopt, AdminAuthResult::Denial::missing_token};
    }
    auto const* user = find_user(runtime.database, *user_id);
    if (user == nullptr || !user->admin)
    {
        return {std::nullopt, AdminAuthResult::Denial::not_admin};
    }
    return {user->user_id, AdminAuthResult::Denial::none};
}

auto logout_local_user(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult
{
    auto const token_hashes = lookup_token_hashes(runtime, access_token);
    if (token_hashes.empty())
    {
        return make_operation_result(false, {}, "unauthenticated");
    }
    auto user_id = std::string{};
    auto device_id = std::string{};
    auto persisted_hash = std::string{};
    auto revoked_any = false;

    for (auto& session : runtime.database.sessions)
    {
        if (matches_any_token_hash(session.access_token_hash, token_hashes) && !session.revoked)
        {
            if (user_id.empty())
            {
                user_id = session.user_id;
                device_id = session.device_id;
                persisted_hash = session.access_token_hash;
            }
            session.revoked = true;
            revoked_any = true;
        }
    }
    if (!revoked_any)
    {
        return make_operation_result(false, {}, "unauthenticated");
    }

    if (database::revoke_access_token(runtime.database.persistent_store, persisted_hash) == 0U)
    {
        return make_operation_result(false, {}, "token revocation persistence failed", 500U);
    }
    // M-04: revoke the device's refresh token too. Revoking only the access
    // token left the paired refresh token valid, and refresh_local_session()
    // admits any refresh row that is merely unrevoked — so a logged-out client
    // (or anyone holding a stolen refresh token) could mint a fresh access token
    // immediately after logout, making logout cosmetic. logout_all, device
    // deletion, and password change all already revoke refresh tokens; this was
    // the one path that did not.
    //
    // Spec: docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3logout
    // — the device's access token and refresh token are both invalidated.
    std::ignore = database::revoke_refresh_tokens_for_device(runtime.database.persistent_store, user_id, device_id);
    for (auto& session : runtime.database.sessions)
    {
        if (matches_any_token_hash(session.access_token_hash, token_hashes))
        {
            session.revoked = true;
        }
    }
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.logout", user_id, device_id,
                       "revoked");
    log_diagnostic("logout.accepted",
                   {
                       {"user_id",   user_id,   false},
                       {"device_id", device_id, false}
    },
                   observability::LogEventSeverity::info);
    return make_operation_result(true, user_id);
}

auto logout_all_local_user(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult
{
    auto const session = authenticated_session(runtime, access_token);
    if (!session.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    auto const access_revoked =
        database::revoke_access_tokens_for_user(runtime.database.persistent_store, session->user_id);
    auto const refresh_revoked =
        database::revoke_refresh_tokens_for_user(runtime.database.persistent_store, session->user_id);
    if (access_revoked == 0U && refresh_revoked == 0U)
    {
        return make_operation_result(false, {}, "session revocation persistence failed", 500U);
    }
    for (auto& candidate : runtime.database.sessions)
    {
        if (candidate.user_id == session->user_id)
        {
            candidate.revoked = true;
        }
    }
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.logout_all", session->user_id,
                       session->device_id, "revoked");
    log_diagnostic("logout_all.accepted",
                   {
                       {"user_id",   session->user_id,   false},
                       {"device_id", session->device_id, false}
    },
                   observability::LogEventSeverity::info);
    return make_operation_result(true, session->user_id);
}

// Permanently deactivates the caller's account (spec: POST
// /_matrix/client/v3/account/deactivate). Irreversible by design.
//
// The caller (client_server.cpp) is responsible for the UIA password
// re-authentication; by the time this runs, ownership of the account is proven.
//
// The localpart is never reissued: the users row is retained with
// deactivated = true, so make_user's existing duplicate check keeps rejecting
// a re-registration of the same user_id.
auto deactivate_local_user(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult
{
    auto const session = authenticated_session(runtime, access_token);
    if (!session.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    auto* user = find_user(runtime.database, session->user_id);
    if (user == nullptr)
    {
        return make_operation_result(false, {}, "unknown user", 404U);
    }
    if (!database::set_user_deactivated(runtime.database.persistent_store, session->user_id))
    {
        return make_operation_result(false, {}, "deactivation persistence failed", 500U);
    }
    user->deactivated = true;

    // Every credential dies with the account, including the caller's own -- unlike
    // a password change, there is no session to preserve.
    //
    // These results are checked, not discarded. A failed refresh-token update is
    // immediately exploitable: refresh_local_session accepts any unrevoked row,
    // so a held refresh token could still mint fresh access and refresh tokens
    // for an account the endpoint had just reported closed. A failed access-token
    // update restores the token on the next restart, when the persistent rows are
    // rehydrated over the in-memory revocations below. Reporting 200 while either
    // is true tells the user their account is closed when it is not.
    //
    // revoke_*_for_user return the number of rows changed, so zero is the normal
    // answer for an account with no tokens of that kind and is not a failure.
    // What must not pass is a persistence failure, which store_* surfaces by
    // leaving the row unchanged; both calls are re-checked below against the
    // store to make the outcome, not the return count, the thing that decides.
    std::ignore = database::revoke_access_tokens_for_user(runtime.database.persistent_store, session->user_id);
    std::ignore = database::revoke_refresh_tokens_for_user(runtime.database.persistent_store, session->user_id);
    auto const credentials_remain = std::ranges::any_of(runtime.database.persistent_store.access_tokens,
                                                        [&session](database::PersistentAccessToken const& token) {
                                                            return token.user_id == session->user_id && !token.revoked;
                                                        }) ||
                                    std::ranges::any_of(runtime.database.persistent_store.refresh_tokens,
                                                        [&session](database::PersistentRefreshToken const& token) {
                                                            return token.user_id == session->user_id && !token.revoked;
                                                        });
    if (credentials_remain)
    {
        return make_operation_result(false, {}, "token revocation failed during deactivation", 500U);
    }
    for (auto& candidate : runtime.database.sessions)
    {
        if (candidate.user_id == session->user_id)
        {
            candidate.revoked = true;
        }
    }
    // The password hash is replaced with a value no password can produce, so a
    // credential leak predating deactivation cannot be replayed even if a future
    // change were to soften the login gate.
    std::ignore = database::update_user_password(runtime.database.persistent_store, session->user_id, "!deactivated");
    user->password_hash = "!deactivated";

    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.account_deactivated",
                       session->user_id, session->device_id, "deactivated");
    log_diagnostic("account.deactivated",
                   {
                       {"user_id",   session->user_id,   false},
                       {"device_id", session->device_id, false}
    },
                   observability::LogEventSeverity::info);
    return make_operation_result(true, session->user_id);
}

auto delete_local_device(HomeserverRuntime& runtime, std::string_view user_id, std::string_view device_id)
    -> OperationResult
{
    if (!auth::user_id_is_valid(user_id) || !auth::device_id_is_valid(device_id))
    {
        return make_operation_result(false, {}, "invalid device", 400U);
    }
    if (!database::delete_device(runtime.database.persistent_store, user_id, device_id))
    {
        return make_operation_result(false, {}, "device not found", 404U);
    }
    std::ignore = database::revoke_access_tokens_for_device(runtime.database.persistent_store, user_id, device_id);
    std::ignore = database::revoke_refresh_tokens_for_device(runtime.database.persistent_store, user_id, device_id);
    for (auto& session : runtime.database.sessions)
    {
        if (session.user_id == user_id && session.device_id == device_id)
        {
            session.revoked = true;
        }
    }
    append_local_audit(runtime.database, observability::AuditCategory::auth, "device.deleted", user_id, device_id,
                       "deleted");
    return make_operation_result(true, std::string{device_id});
}

auto change_local_user_password(HomeserverRuntime& runtime, std::string_view access_token,
                                std::string_view new_password, bool logout_devices) -> OperationResult
{
    auto const session = authenticated_session(runtime, access_token);
    if (!session.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    auto const& user_id = session->user_id;
    if (!auth::password_is_acceptable(new_password))
    {
        return make_operation_result(false, {}, "password rejected", 400U);
    }
    auto const new_hash = auth::hash_password(new_password);
    if (!new_hash.has_value())
    {
        return make_operation_result(false, {}, "password hashing failed", 500U);
    }
    if (!database::update_user_password(runtime.database.persistent_store, user_id, *new_hash))
    {
        return make_operation_result(false, {}, "password update failed", 500U);
    }
    // Mirror the change into the in-memory LocalUser so subsequent logins see the new hash.
    auto const it = std::ranges::find_if(runtime.database.users, [&](LocalUser const& u) {
        return u.user_id == user_id;
    });
    if (it != runtime.database.users.end())
    {
        it->password_hash = *new_hash;
    }
    if (logout_devices)
    {
        // Spec §5.5 (POST /account/password, logout_devices defaults to true): the
        // server MUST revoke the access tokens of all the user's OTHER devices. A
        // token stolen from another device must not survive a password change.
        //
        // M-05: revoke the other devices directly rather than revoking everything
        // and restoring this one. The restore step could not distinguish tokens it
        // had just revoked from tokens revoked earlier — by a logout, an admin
        // action, or a previous password change — so it un-revoked those too. A
        // password change is the action a user takes *after* a compromise, and it
        // was handing the attacker's revoked token back. This call never touches
        // the caller's device, so no revoked credential is ever reinstated.
        std::ignore = database::revoke_tokens_for_user_except_device(runtime.database.persistent_store, user_id,
                                                                     session->device_id);
        for (auto& candidate : runtime.database.sessions)
        {
            if (candidate.user_id == user_id && candidate.device_id != session->device_id)
            {
                candidate.revoked = true;
            }
        }
    }
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.password_changed", user_id,
                       session->device_id, logout_devices ? "changed; revoked other devices" : "changed");
    return make_operation_result(true, std::string{user_id});
}

auto verify_local_user_password(HomeserverRuntime& runtime, std::string_view access_token, std::string_view password)
    -> PasswordVerificationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return {false, 0U};
    }
    auto const* user = find_user(runtime.database, *user_id);
    if (user == nullptr)
    {
        return {false, 0U};
    }

    // M-02: re-authentication (UIA) password checks share the /login failed-login
    // counter. An attacker with a stolen access token but not the password gets
    // the same guessing budget as a direct /login attacker, not a separate,
    // unbounded one.
    if (auto const retry_after_ms = failed_login_lockout_remaining_ms(runtime, *user_id); retry_after_ms > 0U)
    {
        return {false, retry_after_ms};
    }

    auto const valid = auth::password_matches(user->password_hash, password);
    if (!valid)
    {
        record_failed_login(runtime, *user_id);
        return {false, 0U};
    }

    clear_failed_logins(runtime, *user_id);
    return {true, 0U};
}

auto account_state_for_user(HomeserverRuntime const& runtime, std::string_view user_id)
    -> std::optional<auth::AccountState>
{
    auto const* user = find_user(runtime.database, user_id);
    if (user == nullptr)
    {
        return std::nullopt;
    }
    // Locked takes precedence over suspended: a locked account is fully gated
    // (M_USER_LOCKED on all but logout), whereas a suspended account keeps a
    // spec-defined allowlist of permitted actions.
    if (user->locked)
    {
        return auth::AccountState::locked;
    }
    if (user->suspended)
    {
        return auth::AccountState::suspended;
    }
    return auth::AccountState::active;
}

auto access_token_is_soft_logout(HomeserverRuntime& runtime, std::string_view access_token) -> bool
{
    if (access_token.empty())
    {
        return false;
    }
    auto const token_hashes = lookup_token_hashes(runtime, access_token);
    if (token_hashes.empty())
    {
        return false;
    }
    auto const now = std::chrono::system_clock::now();
    return session_expired_for_token(runtime.database, token_hashes, now);
}

auto request_openid_token(HomeserverRuntime& runtime, std::string_view user_id) -> OpenidTokenIssueResult
{
    log_diagnostic("openid.request_token.started", {
                                                       {"user_id", std::string{user_id}, false}
    });
    auto const token = issue_token();
    if (!token.has_value())
    {
        log_diagnostic("openid.request_token.rejected",
                       {
                           {"user_id", std::string{user_id},      false},
                           {"reason",  "token generation failed", false}
        },
                       observability::LogEventSeverity::warning);
        return {false, 500U, {}, {}, 0U, "token generation failed"};
    }
    // Reuses the same keyed-hash machinery access tokens use (issue_token_hash
    // prefers the master-key-derived v4 HMAC, falling back to v3/v2) -- the
    // hash function itself is not what separates OpenID tokens from access
    // tokens; the *table* they land in and the *lookup path* that consults
    // that table are. This row only ever goes into openid_tokens, and only
    // federation_openid_userinfo below ever reads that table.
    auto const token_hash = issue_token_hash(runtime, *token);
    if (!token_hash.has_value())
    {
        log_diagnostic("openid.request_token.rejected",
                       {
                           {"user_id", std::string{user_id},   false},
                           {"reason",  "token hashing failed", false}
        },
                       observability::LogEventSeverity::warning);
        return {false, 500U, {}, {}, 0U, "token hashing failed"};
    }
    // Matrix v1.19 SS API §OpenID: the token is a narrow, short-lived
    // credential good only for GET /openid/userinfo. One hour mirrors the
    // default access_token_lifetime_ms and the spec's own `expires_in`
    // example; there is no operator config knob for it because -- unlike an
    // access token -- a longer-lived OpenID token still cannot reach the
    // ordinary client-server surface, so the usual "shorten this to reduce
    // blast radius" tradeoff does not apply the same way.
    constexpr auto openid_token_lifetime = std::chrono::seconds{3600};
    auto const expires_at = std::chrono::system_clock::now() + openid_token_lifetime;
    if (!database::store_openid_token(runtime.database.persistent_store,
                                      {std::string{user_id}, *token_hash, expires_at}))
    {
        log_diagnostic("openid.request_token.rejected",
                       {
                           {"user_id", std::string{user_id},       false},
                           {"reason",  "token persistence failed", false}
        },
                       observability::LogEventSeverity::warning);
        return {false, 500U, {}, {}, 0U, "token persistence failed"};
    }
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.openid.request_token",
                       std::string{user_id}, {}, "issued");
    log_diagnostic("openid.request_token.accepted",
                   {
                       {"user_id", std::string{user_id}, false}
    },
                   observability::LogEventSeverity::info);
    return {true,
            200U,
            *token,
            runtime.config.server().server_name,
            static_cast<std::uint64_t>(openid_token_lifetime.count()),
            {}};
}

auto federation_openid_userinfo(HomeserverRuntime const& runtime, std::string_view openid_access_token)
    -> std::optional<std::string>
{
    if (openid_access_token.empty())
    {
        return std::nullopt;
    }
    // Deliberately independent of authenticated_user/find_session: those
    // consult database.sessions / persistent_store.access_tokens, and an
    // OpenID token must never authenticate as one (docs/threat-model.md,
    // "OpenID token confusion"). Only persistent_store.openid_tokens is
    // consulted below. lookup_token_hashes/matches_any_token_hash are reused
    // purely for their hashing/constant-time-compare properties, not as a
    // shared trust boundary with access tokens.
    auto const candidate_hashes = lookup_token_hashes(runtime, openid_access_token);
    if (candidate_hashes.empty())
    {
        return std::nullopt;
    }
    auto const now = std::chrono::system_clock::now();
    for (auto const& row : runtime.database.persistent_store.openid_tokens)
    {
        // A match on an expired row still falls through to nullopt below --
        // "unknown token" and "expired token" are indistinguishable to the
        // caller, so a probing third party cannot tell a token merely lapsed
        // from one that was never valid (Matrix v1.19 SS API §OpenID: both
        // are the same 401 response).
        if (matches_any_token_hash(row.token_hash, candidate_hashes) && row.expires_at > now)
        {
            return row.user_id;
        }
    }
    return std::nullopt;
}

auto sso_is_configured(config::SsoConfig const& sso) noexcept -> bool
{
    return sso.enabled && !sso.authorization_url.empty() && !sso.redirect_url_allowlist.empty();
}

auto sso_redirect_target(HomeserverRuntime const& runtime, std::string_view idp_id, std::string_view redirect_url,
                         std::string_view action) -> SsoRedirectResult
{
    auto const& sso = runtime.config.server().sso;
    // Fail closed: an unconfigured or disabled SSO setup behaves exactly
    // like the route does not exist, matching what GET /login already
    // advertises (no m.login.sso flow) rather than half-serving the flow.
    if (!sso_is_configured(sso))
    {
        return {false, 404U, {}, "M_UNRECOGNIZED", "SSO not supported"};
    }
    if (!idp_id.empty() && find_identity_provider(sso, idp_id) == nullptr)
    {
        // Spec: "404 The IdP ID was not recognized by the server."
        return {false, 404U, {}, "M_NOT_FOUND", "unknown identity provider"};
    }
    if (!redirect_url_is_allowed(sso, redirect_url))
    {
        log_diagnostic("sso.redirect.rejected",
                       {
                           {"reason", "redirectUrl not allowlisted", false}
        },
                       observability::LogEventSeverity::warning);
        return {false, 400U, {}, "M_INVALID_PARAM", "redirectUrl is not an allowed destination"};
    }

    auto location = sso.authorization_url;
    if (!idp_id.empty())
    {
        location = append_query_param(std::move(location), "idp", idp_id);
    }
    if (!action.empty())
    {
        location = append_query_param(std::move(location), "action", action);
    }
    // The validated redirectUrl is threaded through so the operator's
    // external SSO adapter knows where to send the browser once it calls
    // back into complete_sso_login below.
    location = append_query_param(std::move(location), "redirectUrl", redirect_url);
    return {true, 302U, std::move(location), {}, {}};
}

auto complete_sso_login(HomeserverRuntime& runtime, std::string_view user_id, std::string_view redirect_url)
    -> OperationResult
{
    auto const& sso = runtime.config.server().sso;
    if (!sso_is_configured(sso))
    {
        return make_operation_result(false, {}, "SSO not supported", 404U);
    }
    // Never trust a redirectUrl across an integration boundary without
    // re-checking it -- the caller here is the operator's external SSO
    // adapter, not the original browser request, so re-validate exactly as
    // sso_redirect_target did before minting anything.
    if (!redirect_url_is_allowed(sso, redirect_url))
    {
        return make_operation_result(false, {}, "redirectUrl is not an allowed destination", 400U);
    }
    if (find_user(runtime.database, user_id) == nullptr)
    {
        return make_operation_result(false, {}, "unknown user", 400U);
    }

    auto const token = issue_token();
    if (!token.has_value())
    {
        return make_operation_result(false, {}, "token generation failed", 500U);
    }
    auto const token_hash = issue_token_hash(runtime, *token);
    if (!token_hash.has_value())
    {
        return make_operation_result(false, {}, "token hashing failed", 500U);
    }
    // Matrix v1.19 CS API §"Client login via SSO": "The lifetime of this
    // token SHOULD be limited to around five seconds." A short, fixed
    // lifetime (not operator-configurable, like the OpenID token lifetime
    // above) keeps the exposure window tight regardless of how quickly the
    // client's browser redirect completes the round trip.
    constexpr auto login_token_lifetime = std::chrono::seconds{30};
    auto const expires_at = std::chrono::system_clock::now() + login_token_lifetime;
    if (!database::store_login_token(runtime.database.persistent_store,
                                     {std::string{user_id}, *token_hash, expires_at, false}))
    {
        return make_operation_result(false, {}, "login token persistence failed", 500U);
    }
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.sso.login_token.issued",
                       std::string{user_id}, {}, "issued");
    log_diagnostic("sso.login_token.issued",
                   {
                       {"user_id", std::string{user_id}, false}
    },
                   observability::LogEventSeverity::info);

    auto const location = append_query_param(strip_login_token_params(redirect_url), "loginToken", *token);
    return make_operation_result(true, location);
}

auto redeem_login_token(HomeserverRuntime& runtime, std::string_view login_token) -> std::optional<std::string>
{
    if (login_token.empty())
    {
        return std::nullopt;
    }
    // Deliberately independent of authenticated_user/find_session, exactly
    // like federation_openid_userinfo above: a login token must never
    // authenticate as an ordinary access token, so only login_tokens is
    // ever consulted here.
    auto const candidate_hashes = lookup_token_hashes(runtime, login_token);
    if (candidate_hashes.empty())
    {
        return std::nullopt;
    }
    auto const user_id = database::consume_login_token(runtime.database.persistent_store, candidate_hashes);
    if (!user_id.has_value())
    {
        return std::nullopt;
    }
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.sso.login_token.redeemed", *user_id,
                       {}, "redeemed");
    return user_id;
}

} // namespace merovingian::homeserver
