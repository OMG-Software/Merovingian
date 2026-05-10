// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/homeserver/vertical_slice.hpp>

#include <merovingian/auth/identity.hpp>
#include <merovingian/auth/token.hpp>
#include <merovingian/database/schema.hpp>
#include <merovingian/observability/observability.hpp>
#include <merovingian/platform/hardening_self_check.hpp>
#include <merovingian/trust_safety/policy_engine.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

auto constexpr schema_version = std::uint32_t{1U};

[[nodiscard]] auto make_result(bool ok, std::string value, std::string reason = {}) -> OperationResult
{
    return {ok, std::move(value), std::move(reason)};
}

[[nodiscard]] auto user_id_from_localpart(std::string_view server_name, std::string_view localpart) -> std::string
{
    return "@" + std::string{localpart} + ":" + std::string{server_name};
}

[[nodiscard]] auto hash_password(std::string_view password) -> std::string
{
    return "password-hash:length=" + std::to_string(password.size());
}

[[nodiscard]] auto hash_token(std::string_view token) -> std::string
{
    return "token-hash:length=" + std::to_string(token.size()) + ":" + std::string{token.substr(0U, token.empty() ? 0U : 1U)};
}

[[nodiscard]] auto issue_token(std::string_view user_id, std::string_view device_id) -> std::string
{
    return "mvs_" + std::to_string(user_id.size()) + "_" + std::to_string(device_id.size()) + "_local_token";
}

[[nodiscard]] auto audit(
    observability::AuditCategory category,
    std::string_view event_type,
    std::string_view actor,
    std::string_view target,
    std::string_view reason
) -> observability::AuditLogEvent
{
    return observability::make_audit_event(category, event_type, actor, target, reason, "local-vertical-slice");
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

[[nodiscard]] auto find_session(LocalDatabase& database, std::string_view token_hash) -> LocalSession*
{
    auto const iterator = std::ranges::find_if(database.sessions, [token_hash](LocalSession const& session) {
        return session.access_token_hash == token_hash && !session.revoked;
    });
    return iterator == database.sessions.end() ? nullptr : &(*iterator);
}

[[nodiscard]] auto find_session(LocalDatabase const& database, std::string_view token_hash) -> LocalSession const*
{
    auto const iterator = std::ranges::find_if(database.sessions, [token_hash](LocalSession const& session) {
        return session.access_token_hash == token_hash && !session.revoked;
    });
    return iterator == database.sessions.end() ? nullptr : &(*iterator);
}

[[nodiscard]] auto find_room(LocalDatabase& database, std::string_view room_id) -> LocalRoom*
{
    auto const iterator = std::ranges::find_if(database.rooms, [room_id](LocalRoom const& room) {
        return room.room_id == room_id;
    });
    return iterator == database.rooms.end() ? nullptr : &(*iterator);
}

[[nodiscard]] auto find_room(LocalDatabase const& database, std::string_view room_id) -> LocalRoom const*
{
    auto const iterator = std::ranges::find_if(database.rooms, [room_id](LocalRoom const& room) {
        return room.room_id == room_id;
    });
    return iterator == database.rooms.end() ? nullptr : &(*iterator);
}

[[nodiscard]] auto room_has_member(LocalRoom const& room, std::string_view user_id) noexcept -> bool
{
    return std::ranges::any_of(room.members, [user_id](std::string const& member) {
        return member == user_id;
    });
}

[[nodiscard]] auto authenticate(HomeserverRuntime const& runtime, std::string_view access_token)
    -> std::optional<std::string>
{
    auto const token_hash = hash_token(access_token);
    auto const* session = find_session(runtime.database, token_hash);
    if (session == nullptr)
    {
        return std::nullopt;
    }
    if (find_user(runtime.database, session->user_id) == nullptr)
    {
        return std::nullopt;
    }
    return session->user_id;
}

} // namespace

auto bootstrap_local_database(config::Config const&) -> LocalDatabase
{
    auto database = LocalDatabase{};
    database.opened = true;
    database.schema_validated = true;
    database.schema_version = schema_version;
    for (auto const table : database::initial_schema_tables())
    {
        database.tables.emplace_back(table);
    }
    return database;
}

auto database_has_table(LocalDatabase const& database, std::string_view table_name) noexcept -> bool
{
    return std::ranges::any_of(database.tables, [table_name](std::string const& table) {
        return table == table_name;
    });
}

auto start_runtime(config::Config const& config) -> RuntimeStartResult
{
    if (!config::is_valid(config))
    {
        return {false, "configuration is invalid", {}};
    }

    auto runtime = HomeserverRuntime{};
    runtime.config = config;
    runtime.listeners = net::make_runtime_listeners(config);
    if (runtime.listeners.empty())
    {
        return {false, "no runtime listeners configured", {}};
    }

    runtime.database = bootstrap_local_database(config);
    if (!runtime.database.opened || !runtime.database.schema_validated || !database_has_table(runtime.database, "users")
        || !database_has_table(runtime.database, "rooms") || !database_has_table(runtime.database, "events")
        || !database_has_table(runtime.database, "audit_log"))
    {
        return {false, "database schema validation failed", {}};
    }

    runtime.hardening = platform::run_startup_hardening_self_check();
    runtime.database.audit_events.push_back(audit(
        observability::AuditCategory::admin,
        "runtime.started",
        "server",
        "homeserver",
        "startup"
    ));
    runtime.started = true;
    return {true, {}, std::move(runtime)};
}

auto admin_health(HomeserverRuntime const& runtime) -> observability::HealthCheckSnapshot
{
    auto snapshot = observability::HealthCheckSnapshot{};
    snapshot.components = {
        {"runtime", runtime.started ? observability::HealthStatus::ok : observability::HealthStatus::failed, "started"},
        {"listeners", runtime.listeners.empty() ? observability::HealthStatus::failed : observability::HealthStatus::ok, "configured"},
        {"database", runtime.database.schema_validated ? observability::HealthStatus::ok : observability::HealthStatus::failed, "schema_validated"},
        {"hardening", runtime.hardening.count() > 0U ? observability::HealthStatus::ok : observability::HealthStatus::degraded, "self_check"},
    };
    for (auto const& component : snapshot.components)
    {
        if (component.status == observability::HealthStatus::failed)
        {
            snapshot.status = observability::HealthStatus::failed;
            return snapshot;
        }
        if (component.status == observability::HealthStatus::degraded)
        {
            snapshot.status = observability::HealthStatus::degraded;
        }
    }
    return snapshot;
}

auto admin_health_summary(HomeserverRuntime const& runtime) -> std::string
{
    auto const health = admin_health(runtime);
    return observability::health_snapshot_summary(health);
}

auto register_local_user(HomeserverRuntime& runtime, std::string_view localpart, std::string_view password)
    -> OperationResult
{
    auto const user_id = user_id_from_localpart(runtime.config.server().server_name, localpart);
    if (!auth::user_id_is_valid(user_id))
    {
        return make_result(false, {}, "invalid user id");
    }
    if (!auth::password_is_acceptable(password))
    {
        return make_result(false, {}, "password rejected");
    }
    if (find_user(runtime.database, user_id) != nullptr)
    {
        return make_result(false, {}, "user already exists");
    }

    auto const decision = trust_safety::evaluate_registration_policy({user_id, "127.0.0.1", true, false, {}});
    if (!decision.allowed)
    {
        return make_result(false, {}, decision.reason.code);
    }

    runtime.database.users.push_back({user_id, hash_password(password), false, false});
    runtime.database.audit_events.push_back(audit(
        observability::AuditCategory::auth,
        "auth.user_registered",
        user_id,
        user_id,
        "created"
    ));
    return make_result(true, user_id);
}

auto login_local_user(
    HomeserverRuntime& runtime,
    std::string_view user_id,
    std::string_view password,
    std::string_view device_id
) -> OperationResult
{
    auto* user = find_user(runtime.database, user_id);
    if (user == nullptr)
    {
        return make_result(false, {}, "unknown user");
    }
    if (user->password_hash != hash_password(password))
    {
        return make_result(false, {}, "bad credentials");
    }
    if (!auth::device_id_is_valid(device_id))
    {
        return make_result(false, {}, "invalid device id");
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
        return make_result(false, {}, login.reason);
    }

    auto const token = issue_token(user->user_id, device_id);
    runtime.database.sessions.push_back({user->user_id, std::string{device_id}, hash_token(token), false});
    runtime.database.audit_events.push_back(audit(
        observability::AuditCategory::auth,
        "auth.login",
        user->user_id,
        std::string{device_id},
        "accepted"
    ));
    return make_result(true, token);
}

auto authenticated_user(HomeserverRuntime const& runtime, std::string_view access_token)
    -> std::optional<std::string>
{
    return authenticate(runtime, access_token);
}

auto logout_local_user(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult
{
    auto const token_hash = hash_token(access_token);
    auto* session = find_session(runtime.database, token_hash);
    if (session == nullptr)
    {
        return make_result(false, {}, "unauthenticated");
    }

    auto const user_id = session->user_id;
    session->revoked = true;
    runtime.database.audit_events.push_back(audit(
        observability::AuditCategory::auth,
        "auth.logout",
        user_id,
        session->device_id,
        "revoked"
    ));
    return make_result(true, user_id);
}

auto create_room(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult
{
    auto const user_id = authenticate(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_result(false, {}, "unauthenticated");
    }

    auto const room_id = "!room" + std::to_string(runtime.database.rooms.size() + 1U) + ":"
        + runtime.config.server().server_name;
    auto const room_decision = trust_safety::evaluate_room_policy({room_id, false, false, {}});
    if (!room_decision.allowed)
    {
        return make_result(false, {}, room_decision.reason.code);
    }

    runtime.database.rooms.push_back({room_id, *user_id, {*user_id}, {}});
    runtime.database.audit_events.push_back(audit(
        observability::AuditCategory::admin,
        "room.created",
        *user_id,
        room_id,
        "created"
    ));
    return make_result(true, room_id);
}

auto join_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id)
    -> OperationResult
{
    auto const user_id = authenticate(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_result(false, {}, "unauthenticated");
    }
    auto* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_result(false, {}, "unknown room");
    }
    if (!room_has_member(*room, *user_id))
    {
        room->members.push_back(*user_id);
    }
    runtime.database.audit_events.push_back(audit(
        observability::AuditCategory::admin,
        "room.joined",
        *user_id,
        room_id,
        "joined"
    ));
    return make_result(true, std::string{room_id});
}

auto send_event(
    HomeserverRuntime& runtime,
    std::string_view access_token,
    std::string_view room_id,
    std::string_view event_json
) -> OperationResult
{
    auto const user_id = authenticate(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_result(false, {}, "unauthenticated");
    }
    auto* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_result(false, {}, "unknown room");
    }
    if (!room_has_member(*room, *user_id))
    {
        return make_result(false, {}, "not joined");
    }
    if (event_json.empty())
    {
        return make_result(false, {}, "empty event");
    }

    auto const event_id = "$event" + std::to_string(room->events.size() + 1U) + ":"
        + runtime.config.server().server_name;
    room->events.push_back(std::string{event_json});
    runtime.database.audit_events.push_back(audit(
        observability::AuditCategory::admin,
        "room.event_sent",
        *user_id,
        room_id,
        "stored"
    ));
    return make_result(true, event_id);
}

auto fetch_room_state(
    HomeserverRuntime const& runtime,
    std::string_view access_token,
    std::string_view room_id
) -> OperationResult
{
    auto const user_id = authenticate(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_result(false, {}, "unauthenticated");
    }
    auto const* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_result(false, {}, "unknown room");
    }
    if (!room_has_member(*room, *user_id))
    {
        return make_result(false, {}, "not joined");
    }

    auto summary = "room_id=" + room->room_id + " members=" + std::to_string(room->members.size())
        + " events=" + std::to_string(room->events.size());
    return make_result(true, std::move(summary));
}

auto audit_event_count(HomeserverRuntime const& runtime) noexcept -> std::size_t
{
    return runtime.database.audit_events.size();
}

auto run_local_vertical_slice(config::Config const& config) -> OperationResult
{
    auto started = start_runtime(config);
    if (!started.started)
    {
        return make_result(false, {}, started.reason);
    }

    auto& runtime = started.runtime;
    auto user = register_local_user(runtime, "alice", "CorrectHorse7!");
    if (!user.ok)
    {
        return user;
    }
    auto login = login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
    if (!login.ok)
    {
        return login;
    }
    if (!authenticated_user(runtime, login.value).has_value())
    {
        return make_result(false, {}, "authenticated request failed");
    }
    auto room = create_room(runtime, login.value);
    if (!room.ok)
    {
        return room;
    }
    auto join = join_room(runtime, login.value, room.value);
    if (!join.ok)
    {
        return join;
    }
    auto event = send_event(runtime, login.value, room.value, R"({"type":"m.room.message","content":{"msgtype":"m.text"}})");
    if (!event.ok)
    {
        return event;
    }
    auto state = fetch_room_state(runtime, login.value, room.value);
    if (!state.ok)
    {
        return state;
    }
    auto logout = logout_local_user(runtime, login.value);
    if (!logout.ok)
    {
        return logout;
    }
    if (authenticated_user(runtime, login.value).has_value())
    {
        return make_result(false, {}, "logout did not revoke session");
    }
    if (audit_event_count(runtime) < 6U)
    {
        return make_result(false, {}, "audit log did not record vertical slice");
    }

    return make_result(true, state.value);
}

} // namespace merovingian::homeserver
