// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/auth_service.hpp"

#include "merovingian/appservice/masquerade_token.hpp"
#include "merovingian/auth/identity.hpp"
#include "merovingian/auth/password.hpp"
#include "merovingian/auth/session.hpp"
#include "merovingian/auth/token.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/constant_time.hpp"
#include "merovingian/crypto/master_key.hpp"
#include "merovingian/crypto/random.hpp"
#include "merovingian/crypto/token_key.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
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
    [[nodiscard]] auto token_hmac_key_v3(HomeserverRuntime const& runtime) -> std::optional<crypto::TokenHmacKey>
    {
        auto const material = crypto::load_master_key_material(runtime.config.security().secrets.master_key_file);
        if (!material.has_value())
        {
            return std::nullopt;
        }
        return crypto::derive_token_hmac_key_v3(material->bytes());
    }

    // v4 HMAC key: derived from the operator's master key file, completely
    // independent from the Ed25519 signing secret. If no master key is configured,
    // v4 hashing is unavailable and the code falls back to v3/v2.
    [[nodiscard]] auto token_hmac_key_v4(HomeserverRuntime const& runtime) -> std::optional<crypto::TokenHmacKey>
    {
        auto const material = crypto::load_master_key_material(runtime.config.security().secrets.master_key_file);
        if (!material.has_value())
        {
            return std::nullopt;
        }
        return crypto::derive_token_hmac_key(material->bytes());
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
                                 bool admin, std::string_view audit_outcome) -> OperationResult
    {
        auto const user_id = user_id_from_localpart(runtime.config.server().server_name, localpart);
        if (!auth::user_id_is_valid(user_id))
        {
            return make_operation_result(false, {}, "invalid user id");
        }
        if (!auth::password_is_acceptable(password))
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

// Load the registration token from disk once, hash it with Argon2id, and cache
// only the hash keyed by the file path.  The plaintext token is zeroised after
// hashing so it does not remain in server memory.  Exposed in auth_service.hpp so
// the registration-token validity endpoint compares via the hash rather than
// holding the plaintext token on the request path.
[[nodiscard]] auto load_hashed_registration_token(config::RegistrationSecurityConfig const& registration)
    -> std::optional<std::string>
{
    if (registration.token_file.empty())
    {
        return std::nullopt;
    }

    static auto mutex = std::mutex{};
    static auto cache = std::unordered_map<std::string, std::string>{};

    auto lock = std::lock_guard<std::mutex>{mutex};
    auto const it = cache.find(registration.token_file);
    if (it != cache.end())
    {
        return it->second;
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

    auto const [inserted, ok] = cache.emplace(registration.token_file, std::move(*hash));
    std::ignore = ok;
    return inserted->second;
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
        auto const expected_hash = load_hashed_registration_token(registration);
        if (!expected_hash.has_value() || !auth::registration_token_matches(*expected_hash, registration_token))
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
    return make_user(runtime, localpart, *random_password, false, "created_by_appservice");
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
    auto* user = find_user(runtime.database, user_id);
    auto const* password_hash = user != nullptr ? &user->password_hash : dummy_password_hash();
    auto const password_valid = password_hash != nullptr && auth::password_matches(*password_hash, password);
    if (user == nullptr || !password_valid)
    {
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
    return complete_login(runtime, *user, device_id, with_ttl);
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
                                              [&refresh_hashes, now](database::PersistentRefreshToken const& row) {
                                                  return matches_any_token_hash(row.token_hash, refresh_hashes) &&
                                                         !row.revoked && !is_expired(row.expires_at, now);
                                              });
    if (refresh == runtime.database.persistent_store.refresh_tokens.end())
    {
        return {false, 401U, {}, {}, {}, {}, "refresh token rejected"};
    }

    auto const user_id = refresh->user_id;
    auto const device_id = refresh->device_id;
    if (find_user(runtime.database, user_id) == nullptr || !auth::device_id_is_valid(device_id))
    {
        return {false, 401U, {}, {}, {}, {}, "refresh subject rejected"};
    }
    if (database::revoke_refresh_token(runtime.database.persistent_store, refresh->token_hash) == 0U)
    {
        return {false, 500U, {}, {}, {}, {}, "refresh token revocation failed"};
    }
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
    if (!database::store_access_token(runtime.database.persistent_store,
                                      {user_id, device_id, *access_hash, false, new_access_expires_at}) ||
        !database::store_refresh_token(runtime.database.persistent_store,
                                       {user_id, device_id, *new_refresh_hash, false, new_refresh_expires_at}))
    {
        return {false, 500U, {}, {}, {}, {}, "refreshed token persistence failed"};
    }

    ++runtime.database.next_session_id;
    runtime.database.sessions.push_back({user_id, device_id, *access_hash, false, new_access_expires_at});
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
        // Revoke every token for the user, then restore the caller's own device so
        // its session survives, and flip the in-memory sessions of the other devices.
        std::ignore = database::revoke_access_tokens_for_user(runtime.database.persistent_store, user_id);
        std::ignore = database::revoke_refresh_tokens_for_user(runtime.database.persistent_store, user_id);
        std::ignore =
            database::restore_tokens_for_device(runtime.database.persistent_store, user_id, session->device_id);
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
    -> bool
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return false;
    }
    auto const* user = find_user(runtime.database, *user_id);
    if (user == nullptr)
    {
        return false;
    }
    return auth::password_matches(user->password_hash, password);
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

} // namespace merovingian::homeserver
