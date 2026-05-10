// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/homeserver/vertical_slice.hpp>

#include "local_services.hpp"

#include <merovingian/auth/identity.hpp>
#include <merovingian/trust_safety/policy_engine.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{
namespace
{

auto constexpr fnv_offset = std::uint64_t{1469598103934665603ULL};
auto constexpr fnv_prime = std::uint64_t{1099511628211ULL};

[[nodiscard]] auto stable_hash(std::string_view value) noexcept -> std::uint64_t
{
    auto hash = fnv_offset;
    for (auto const character : value)
    {
        hash ^= static_cast<unsigned char>(character);
        hash *= fnv_prime;
    }
    return hash;
}

[[nodiscard]] auto user_id_from_localpart(std::string_view server_name, std::string_view localpart) -> std::string
{
    return "@" + std::string{localpart} + ":" + std::string{server_name};
}

[[nodiscard]] auto hash_password(std::string_view password) -> std::string
{
    return "password-hash:v1:" + std::to_string(stable_hash(password));
}

[[nodiscard]] auto hash_token(std::string_view token) -> std::string
{
    return "token-hash:v1:" + std::to_string(stable_hash(token));
}

[[nodiscard]] auto issue_token(std::string_view user_id, std::string_view device_id, std::uint64_t session_id) -> std::string
{
    auto const material = std::string{user_id} + '|' + std::string{device_id} + '|' + std::to_string(session_id);
    return "mvs_" + std::to_string(session_id) + '_' + std::to_string(stable_hash(material));
}

[[nodiscard]] auto find_user(LocalDatabase& database, std::string_view user_id) -> LocalUser*
{
    auto const iterator = std::ranges::find_if(database.users, [user_id](LocalUser const& user) { return user.user_id == user_id; });
    return iterator == database.users.end() ? nullptr : &(*iterator);
}

[[nodiscard]] auto find_user(LocalDatabase const& database, std::string_view user_id) -> LocalUser const*
{
    auto const iterator = std::ranges::find_if(database.users, [user_id](LocalUser const& user) { return user.user_id == user_id; });
    return iterator == database.users.end() ? nullptr : &(*iterator);
}

[[nodiscard]] auto find_session(LocalDatabase const& database, std::string_view token_hash) -> LocalSession const*
{
    auto const iterator = std::ranges::find_if(database.sessions, [token_hash](LocalSession const& session) {
        return session.access_token_hash == token_hash && !session.revoked;
    });
    return iterator == database.sessions.end() ? nullptr : &(*iterator);
}

} // namespace

auto register_local_user(HomeserverRuntime& runtime, std::string_view localpart, std::string_view password) -> OperationResult
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

    auto const decision = trust_safety::evaluate_registration_policy({user_id, "127.0.0.1", runtime.config.security().registration.enabled, false, {}});
    if (!decision.allowed)
    {
        return make_operation_result(false, {}, decision.reason.code);
    }

    auto const first_user_is_admin = runtime.database.users.empty();
    auto const password_hash = hash_password(password);
    runtime.database.users.push_back({user_id, password_hash, false, false, first_user_is_admin});
    (void)database::store_user(runtime.database.persistent_store, {user_id, password_hash, false, false, first_user_is_admin});
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.user_registered", user_id, user_id, first_user_is_admin ? "created_admin" : "created");
    return make_operation_result(true, user_id);
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
auto login_local_user(HomeserverRuntime& runtime, std::string_view user_id, std::string_view password, std::string_view device_id) -> OperationResult
{
    auto* user = find_user(runtime.database, user_id);
    if (user == nullptr)
    {
        return make_operation_result(false, {}, "unknown user");
    }
    if (user->password_hash != hash_password(password))
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

    auto const session_id = runtime.database.next_session_id++;
    auto const token = issue_token(user->user_id, device_id, session_id);
    auto const token_hash = hash_token(token);
    runtime.database.sessions.push_back({user->user_id, std::string{device_id}, token_hash, false});
    (void)database::store_device(runtime.database.persistent_store, {user->user_id, std::string{device_id}, std::string{device_id}});
    (void)database::store_access_token(runtime.database.persistent_store, {user->user_id, std::string{device_id}, token_hash, false});
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.login", user->user_id, std::string{device_id}, "accepted");
    return make_operation_result(true, token);
}
// NOLINTEND(bugprone-easily-swappable-parameters)

auto authenticated_user(HomeserverRuntime const& runtime, std::string_view access_token) -> std::optional<std::string>
{
    auto const* session = find_session(runtime.database, hash_token(access_token));
    if (session == nullptr || find_user(runtime.database, session->user_id) == nullptr)
    {
        return std::nullopt;
    }
    return session->user_id;
}

auto authenticated_admin_user(HomeserverRuntime const& runtime, std::string_view access_token) -> std::optional<std::string>
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
    auto user_id = std::string{};
    auto device_id = std::string{};
    auto revoked_any = false;

    for (auto& session : runtime.database.sessions)
    {
        if (session.access_token_hash == token_hash && !session.revoked)
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

    (void)database::revoke_access_token(runtime.database.persistent_store, token_hash);
    append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.logout", user_id, device_id, "revoked");
    return make_operation_result(true, user_id);
}

} // namespace merovingian::homeserver
