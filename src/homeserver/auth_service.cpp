// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/auth_service.hpp"

#include "merovingian/auth/identity.hpp"
#include "merovingian/auth/session.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

#include <sodium.h>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("auth", event, std::move(fields)));
    }

    auto constexpr token_secret_bytes = std::size_t{32U};
    auto constexpr token_hash_bytes = std::size_t{crypto_generichash_BYTES};

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

    [[nodiscard]] auto to_hex(unsigned char const* bytes, std::size_t size) -> std::string
    {
        auto output = std::string((size * 2U) + 1U, '\0');
        std::ignore = sodium_bin2hex(output.data(), output.size(), bytes, size);
        output.pop_back();
        return output;
    }

    [[nodiscard]] auto password_hash_is_v2(std::string_view password_hash) noexcept -> bool
    {
        return password_hash.starts_with("password-hash:v2:");
    }

    [[nodiscard]] auto token_hash_is_v2(std::string_view token_hash) noexcept -> bool
    {
        return token_hash.starts_with("token-hash:v2:");
    }

    [[nodiscard]] auto token_hash_is_v3(std::string_view token_hash) noexcept -> bool
    {
        return token_hash.starts_with("token-hash:v3:");
    }

    [[nodiscard]] auto password_hash_payload(std::string_view password_hash) noexcept -> std::string_view
    {
        auto constexpr prefix = std::string_view{"password-hash:v2:"};
        return password_hash_is_v2(password_hash) ? password_hash.substr(prefix.size()) : std::string_view{};
    }

    [[nodiscard]] auto hash_password(std::string_view password) -> std::optional<std::string>
    {
        if (!sodium_is_ready())
        {
            return std::nullopt;
        }
        auto output = std::array<char, crypto_pwhash_STRBYTES>{};
        if (crypto_pwhash_str(output.data(), password.data(), static_cast<unsigned long long>(password.size()),
                              crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
        {
            return std::nullopt;
        }
        return "password-hash:v2:" + std::string{output.data()};
    }

    [[nodiscard]] auto dummy_password_hash() -> std::string const*
    {
        static auto const dummy = hash_password("merovingian-invalid-login-dummy");
        return dummy.has_value() ? &(*dummy) : nullptr;
    }

    [[nodiscard]] auto password_matches(std::string_view password_hash, std::string_view password) noexcept -> bool
    {
        if (!sodium_is_ready())
        {
            return false;
        }
        auto const payload = password_hash_payload(password_hash);
        if (payload.empty())
        {
            return false;
        }
        return crypto_pwhash_str_verify(payload.data(), password.data(),
                                        static_cast<unsigned long long>(password.size())) == 0;
    }

    [[nodiscard]] auto user_id_from_localpart(std::string_view server_name, std::string_view localpart) -> std::string
    {
        return "@" + std::string{localpart} + ":" + std::string{server_name};
    }

    [[nodiscard]] auto hash_token_v2(std::string_view token) -> std::optional<std::string>
    {
        if (!sodium_is_ready())
        {
            return std::nullopt;
        }
        auto digest = std::array<unsigned char, token_hash_bytes>{};
        auto token_bytes = std::vector<unsigned char>{};
        token_bytes.reserve(token.size());
        for (auto const character : token)
        {
            token_bytes.push_back(static_cast<unsigned char>(character));
        }
        if (crypto_generichash(digest.data(), digest.size(), token_bytes.data(), token_bytes.size(), nullptr, 0U) != 0)
        {
            return std::nullopt;
        }
        return "token-hash:v2:" + to_hex(digest.data(), digest.size());
    }

    [[nodiscard]] auto token_hash_key(HomeserverRuntime const& runtime)
        -> std::optional<std::array<unsigned char, crypto_generichash_KEYBYTES>>
    {
        if (!sodium_is_ready() || runtime.database.signing_secret_key.size() < crypto_generichash_KEYBYTES)
        {
            return std::nullopt;
        }
        auto key = std::array<unsigned char, crypto_generichash_KEYBYTES>{};
        std::copy_n(runtime.database.signing_secret_key.begin(), crypto_generichash_KEYBYTES, key.begin());
        return key;
    }

    [[nodiscard]] auto hash_token_v3(HomeserverRuntime const& runtime, std::string_view token)
        -> std::optional<std::string>
    {
        auto const key = token_hash_key(runtime);
        if (!key.has_value())
        {
            return std::nullopt;
        }
        auto digest = std::array<unsigned char, token_hash_bytes>{};
        auto token_bytes = std::vector<unsigned char>{};
        token_bytes.reserve(token.size());
        for (auto const character : token)
        {
            token_bytes.push_back(static_cast<unsigned char>(character));
        }
        if (crypto_generichash(digest.data(), digest.size(), token_bytes.data(), token_bytes.size(), key->data(),
                               key->size()) != 0)
        {
            return std::nullopt;
        }
        return "token-hash:v3:" + to_hex(digest.data(), digest.size());
    }

    [[nodiscard]] auto issue_token_hash(HomeserverRuntime const& runtime, std::string_view token)
        -> std::optional<std::string>
    {
        if (auto const v3 = hash_token_v3(runtime, token); v3.has_value())
        {
            return v3;
        }
        // Signing key unavailable (e.g. corrupted or not yet initialised): fall
        // back to the unkeyed v2 SHA-256 hash so local operations (login, logout,
        // session lookup) still work.  Federation will fail separately if the
        // signing key is broken; login should not be collateral damage.
        return hash_token_v2(token);
    }

    [[nodiscard]] auto lookup_token_hashes(HomeserverRuntime const& runtime, std::string_view token)
        -> std::vector<std::string>
    {
        auto hashes = std::vector<std::string>{};
        if (auto const v3 = hash_token_v3(runtime, token); v3.has_value())
        {
            hashes.push_back(*v3);
        }
        if (auto const v2 = hash_token_v2(token); v2.has_value())
        {
            hashes.push_back(*v2);
        }
        return hashes;
    }

    [[nodiscard]] auto token_hash_matches(std::string_view left, std::string_view right) noexcept -> bool
    {
        auto const same_version =
            (token_hash_is_v2(left) && token_hash_is_v2(right)) || (token_hash_is_v3(left) && token_hash_is_v3(right));
        return same_version && left.size() == right.size() &&
               sodium_memcmp(left.data(), right.data(), left.size()) == 0;
    }

    [[nodiscard]] auto issue_token() -> std::optional<std::string>
    {
        if (!sodium_is_ready())
        {
            return std::nullopt;
        }
        auto bytes = std::array<unsigned char, token_secret_bytes>{};
        randombytes_buf(bytes.data(), bytes.size());
        return "mvs_" + to_hex(bytes.data(), bytes.size());
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

    [[nodiscard]] auto find_session(LocalDatabase const& database, std::vector<std::string> const& token_hashes)
        -> LocalSession const*
    {
        auto const iterator = std::ranges::find_if(database.sessions, [&token_hashes](LocalSession const& session) {
            return matches_any_token_hash(session.access_token_hash, token_hashes) && !session.revoked;
        });
        return iterator == database.sessions.end() ? nullptr : &(*iterator);
    }

    auto trim_line_ending(std::string& value) -> void
    {
        while (!value.empty() && (value.back() == '\n' || value.back() == '\r'))
        {
            value.pop_back();
        }
    }

    // Hash a registration token with Argon2id using libsodium's recommended
    // interactive limits.  The resulting string is safe to keep in memory and to
    // compare with crypto_pwhash_str_verify.
    [[nodiscard]] auto hash_registration_token(std::string_view token) -> std::optional<std::string>
    {
        if (!sodium_is_ready() || token.empty())
        {
            return std::nullopt;
        }
        auto output = std::array<char, crypto_pwhash_STRBYTES>{};
        if (crypto_pwhash_str(output.data(), token.data(), static_cast<unsigned long long>(token.size()),
                              crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE)
            != 0)
        {
            return std::nullopt;
        }
        return std::string{output.data()};
    }

    // Load the registration token from disk once, hash it with Argon2id, and cache
    // only the hash keyed by the file path.  The plaintext token is zeroised after
    // hashing so it does not remain in server memory.
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

        auto input = std::ifstream{registration.token_file};
        if (!input)
        {
            return std::nullopt;
        }

        auto token = std::string{};
        std::getline(input, token);
        trim_line_ending(token);
        if (token.empty())
        {
            return std::nullopt;
        }

        auto hash = hash_registration_token(token);
        // Best-effort memory clearing of the plaintext token after hashing.  This
        // reduces the window in which a memory disclosure would reveal the raw secret.
        std::ignore = sodium_mlock(token.data(), token.size());
        std::fill(token.begin(), token.end(), '\0');
        sodium_munlock(token.data(), token.size());

        if (!hash.has_value())
        {
            return std::nullopt;
        }

        auto const [inserted, ok] = cache.emplace(registration.token_file, std::move(*hash));
        std::ignore = ok;
        return inserted->second;
    }

    [[nodiscard]] auto registration_token_matches(std::string_view expected_hash, std::string_view presented) noexcept
        -> bool
    {
        if (!sodium_is_ready() || expected_hash.empty() || presented.empty())
        {
            return false;
        }
        return crypto_pwhash_str_verify(expected_hash.data(), presented.data(),
                                        static_cast<unsigned long long>(presented.size()))
               == 0;
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

        auto const password_hash = hash_password(password);
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
        return make_operation_result(true, user_id);
    }

} // namespace

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
        if (!expected_hash.has_value() || !registration_token_matches(*expected_hash, registration_token))
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

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
auto login_local_user(HomeserverRuntime& runtime, std::string_view user_id, std::string_view password,
                      std::string_view device_id) -> OperationResult
{
    log_diagnostic("login.started",
                   {
                       {"user_id",   std::string{user_id},   false},
                       {"device_id", std::string{device_id}, false}
    });
    auto* user = find_user(runtime.database, user_id);
    auto const* password_hash = user != nullptr ? &user->password_hash : dummy_password_hash();
    auto const password_valid = password_hash != nullptr && password_matches(*password_hash, password);
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
    if (!database::store_device_and_access_token(runtime.database.persistent_store, std::move(device),
                                                 {user->user_id, std::string{device_id}, *token_hash, false}))
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
    runtime.database.sessions.push_back({user->user_id, std::string{device_id}, *token_hash, false});
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.login", user->user_id,
                       std::string{device_id}, "accepted");
    log_diagnostic("login.accepted",
                   {
                       {"user_id",   user->user_id,          false},
                       {"device_id", std::string{device_id}, false}
    });
    return make_operation_result(true, *token);
}
// NOLINTEND(bugprone-easily-swappable-parameters)

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
    if (!database::store_refresh_token(runtime.database.persistent_store,
                                       {std::string{user_id}, std::string{device_id}, *refresh_hash, false}))
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

    auto const refresh =
        std::ranges::find_if(runtime.database.persistent_store.refresh_tokens,
                             [&refresh_hashes](database::PersistentRefreshToken const& row) {
                                 return matches_any_token_hash(row.token_hash, refresh_hashes) && !row.revoked;
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
    if (!database::store_access_token(runtime.database.persistent_store, {user_id, device_id, *access_hash, false}) ||
        !database::store_refresh_token(runtime.database.persistent_store,
                                       {user_id, device_id, *new_refresh_hash, false}))
    {
        return {false, 500U, {}, {}, {}, {}, "refreshed token persistence failed"};
    }

    ++runtime.database.next_session_id;
    runtime.database.sessions.push_back({user_id, device_id, *access_hash, false});
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.refresh", user_id, device_id,
                       "rotated");
    return {true, 200U, *access_token, *new_refresh_token, user_id, device_id, {}};
}

auto authenticated_user(HomeserverRuntime& runtime, std::string_view access_token) -> std::optional<std::string>
{
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
    auto const* session = find_session(runtime.database, token_hashes);
    if (session == nullptr)
    {
        // Security: no session for this token hash — report without leaking the raw token.
        log_diagnostic_audit(runtime.database, "auth", "access_token.rejected",
                             {
                                 {"reason", "session not found", false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                             "access_token.rejected", "<unknown>", "<unknown>", "session not found");
        return std::nullopt;
    }
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
    auto const token_hashes = lookup_token_hashes(runtime, access_token);
    if (token_hashes.empty())
    {
        return std::nullopt;
    }
    auto const* session = find_session(runtime.database, token_hashes);
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
                                std::string_view new_password) -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    if (!auth::password_is_acceptable(new_password))
    {
        return make_operation_result(false, {}, "password rejected", 400U);
    }
    auto const new_hash = hash_password(new_password);
    if (!new_hash.has_value())
    {
        return make_operation_result(false, {}, "password hashing failed", 500U);
    }
    if (!database::update_user_password(runtime.database.persistent_store, *user_id, *new_hash))
    {
        return make_operation_result(false, {}, "password update failed", 500U);
    }
    // Mirror the change into the in-memory LocalUser so subsequent logins see the new hash.
    auto const it = std::ranges::find_if(runtime.database.users, [&](LocalUser const& u) {
        return u.user_id == *user_id;
    });
    if (it != runtime.database.users.end())
    {
        it->password_hash = *new_hash;
    }
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.password_changed", *user_id, {},
                       "changed");
    return make_operation_result(true, *user_id);
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
    return password_matches(user->password_hash, password);
}

} // namespace merovingian::homeserver
