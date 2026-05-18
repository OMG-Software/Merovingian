// SPDX-License-Identifier: GPL-3.0-or-later

#include "local_services.hpp"
#include "merovingian/auth/identity.hpp"
#include "merovingian/homeserver/vertical_slice.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <sodium.h>

namespace merovingian::homeserver
{
namespace
{

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
        static_cast<void>(sodium_bin2hex(output.data(), output.size(), bytes, size));
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

    [[nodiscard]] auto hash_token(std::string_view token) -> std::optional<std::string>
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

    [[nodiscard]] auto token_hash_matches(std::string_view left, std::string_view right) noexcept -> bool
    {
        return token_hash_is_v2(left) && token_hash_is_v2(right) && left.size() == right.size() &&
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

    [[nodiscard]] auto find_session(LocalDatabase const& database, std::string_view token_hash) -> LocalSession const*
    {
        auto const iterator = std::ranges::find_if(database.sessions, [token_hash](LocalSession const& session) {
            return token_hash_matches(session.access_token_hash, token_hash) && !session.revoked;
        });
        return iterator == database.sessions.end() ? nullptr : &(*iterator);
    }

} // namespace

auto register_local_user(HomeserverRuntime& runtime, std::string_view localpart, std::string_view password)
    -> OperationResult
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

    auto const decision = trust_safety::evaluate_registration_policy(
        {user_id, "127.0.0.1", runtime.config.security().registration.enabled, false, {}});
    if (!decision.allowed)
    {
        return make_operation_result(false, {}, decision.reason.code);
    }

    auto const first_user_is_admin = runtime.database.users.empty();
    auto const password_hash = hash_password(password);
    if (!password_hash.has_value())
    {
        return make_operation_result(false, {}, "password hashing failed");
    }
    if (!database::store_user(runtime.database.persistent_store,
                              {user_id, *password_hash, false, false, first_user_is_admin}))
    {
        return make_operation_result(false, {}, "user persistence failed", 500U);
    }
    runtime.database.users.push_back({user_id, *password_hash, false, false, first_user_is_admin});
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.user_registered", user_id, user_id,
                       first_user_is_admin ? "created_admin" : "created");
    return make_operation_result(true, user_id);
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
auto login_local_user(HomeserverRuntime& runtime, std::string_view user_id, std::string_view password,
                      std::string_view device_id) -> OperationResult
{
    auto* user = find_user(runtime.database, user_id);
    if (user == nullptr)
    {
        return make_operation_result(false, {}, "unknown user");
    }
    if (!password_matches(user->password_hash, password))
    {
        return make_operation_result(false, {}, "bad credentials");
    }
    if (!auth::device_id_is_valid(device_id))
    {
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
        return make_operation_result(false, {}, login.reason);
    }

    auto const token = issue_token();
    if (!token.has_value())
    {
        return make_operation_result(false, {}, "token generation failed");
    }
    auto const token_hash = hash_token(*token);
    if (!token_hash.has_value())
    {
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
        return make_operation_result(false, {}, "login persistence failed", 500U);
    }
    ++runtime.database.next_session_id;
    runtime.database.sessions.push_back({user->user_id, std::string{device_id}, *token_hash, false});
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.login", user->user_id,
                       std::string{device_id}, "accepted");
    return make_operation_result(true, *token);
}
// NOLINTEND(bugprone-easily-swappable-parameters)

auto authenticated_user(HomeserverRuntime const& runtime, std::string_view access_token) -> std::optional<std::string>
{
    auto const token_hash = hash_token(access_token);
    if (!token_hash.has_value())
    {
        return std::nullopt;
    }
    auto const* session = find_session(runtime.database, *token_hash);
    if (session == nullptr || find_user(runtime.database, session->user_id) == nullptr)
    {
        return std::nullopt;
    }
    return session->user_id;
}

auto authenticated_session(HomeserverRuntime const& runtime, std::string_view access_token)
    -> std::optional<LocalSession>
{
    auto const token_hash = hash_token(access_token);
    if (!token_hash.has_value())
    {
        return std::nullopt;
    }
    auto const* session = find_session(runtime.database, *token_hash);
    if (session == nullptr || find_user(runtime.database, session->user_id) == nullptr)
    {
        return std::nullopt;
    }
    return *session;
}

auto authenticated_admin_user(HomeserverRuntime const& runtime, std::string_view access_token)
    -> std::optional<std::string>
{
    auto const user_id = authenticated_user(runtime, access_token);
    auto const* user = user_id.has_value() ? find_user(runtime.database, *user_id) : nullptr;
    if (user == nullptr || !user->admin)
    {
        return std::nullopt;
    }
    return user->user_id;
}

auto logout_local_user(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult
{
    auto const token_hash = hash_token(access_token);
    if (!token_hash.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated");
    }
    auto user_id = std::string{};
    auto device_id = std::string{};
    auto revoked_any = false;

    for (auto& session : runtime.database.sessions)
    {
        if (token_hash_matches(session.access_token_hash, *token_hash) && !session.revoked)
        {
            if (user_id.empty())
            {
                user_id = session.user_id;
                device_id = session.device_id;
            }
            session.revoked = true;
            revoked_any = true;
        }
    }
    if (!revoked_any)
    {
        return make_operation_result(false, {}, "unauthenticated");
    }

    if (database::revoke_access_token(runtime.database.persistent_store, *token_hash) == 0U)
    {
        return make_operation_result(false, {}, "token revocation persistence failed", 500U);
    }
    for (auto& session : runtime.database.sessions)
    {
        if (token_hash_matches(session.access_token_hash, *token_hash))
        {
            session.revoked = true;
        }
    }
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.logout", user_id, device_id,
                       "revoked");
    return make_operation_result(true, user_id);
}

} // namespace merovingian::homeserver
