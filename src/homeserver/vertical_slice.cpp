// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/homeserver/vertical_slice.hpp>

#include <merovingian/auth/identity.hpp>
#include <merovingian/database/schema.hpp>
#include <merovingian/observability/observability.hpp>
#include <merovingian/platform/hardening_self_check.hpp>
#include <merovingian/trust_safety/policy_engine.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
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
auto constexpr fnv_offset = std::uint64_t{1469598103934665603ULL};
auto constexpr fnv_prime = std::uint64_t{1099511628211ULL};

[[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
{
    return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
}

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

[[nodiscard]] auto make_result(bool ok, std::string value, std::string reason = {}) -> OperationResult
{
    return {ok, std::move(value), std::move(reason)};
}

[[nodiscard]] auto response(std::uint16_t status, std::string body) -> LocalHttpResponse
{
    return {status, std::move(body)};
}

[[nodiscard]] auto response_from_operation(OperationResult const& result, std::uint16_t ok_status = 200U)
    -> LocalHttpResponse
{
    return result.ok ? response(ok_status, result.value) : response(400U, result.reason);
}

[[nodiscard]] auto split_pipe_2(std::string_view body) -> std::optional<std::array<std::string_view, 2U>>
{
    auto const first = body.find('|');
    if (first == std::string_view::npos || first == 0U || first + 1U >= body.size())
    {
        return std::nullopt;
    }
    return std::array<std::string_view, 2U>{body.substr(0U, first), body.substr(first + 1U)};
}

[[nodiscard]] auto split_pipe_3(std::string_view body) -> std::optional<std::array<std::string_view, 3U>>
{
    auto const first = body.find('|');
    if (first == std::string_view::npos || first == 0U)
    {
        return std::nullopt;
    }
    auto const second = body.find('|', first + 1U);
    if (second == std::string_view::npos || second == first + 1U || second + 1U >= body.size())
    {
        return std::nullopt;
    }
    return std::array<std::string_view, 3U>{
        body.substr(0U, first),
        body.substr(first + 1U, second - first - 1U),
        body.substr(second + 1U),
    };
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

[[nodiscard]] auto issue_token(std::string_view user_id, std::string_view device_id, std::uint64_t session_id)
    -> std::string
{
    auto const material = std::string{user_id} + '|' + std::string{device_id} + '|' + std::to_string(session_id);
    return "mvs_" + std::to_string(session_id) + '_' + std::to_string(stable_hash(material));
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
    if (session == nullptr || find_user(runtime.database, session->user_id) == nullptr)
    {
        return std::nullopt;
    }
    return session->user_id;
}

[[nodiscard]] auto admin_token_is_valid(HomeserverRuntime const& runtime, std::string_view access_token) -> bool
{
    auto const user_id = authenticate(runtime, access_token);
    if (!user_id.has_value())
    {
        return false;
    }
    auto const* user = find_user(runtime.database, *user_id);
    return user != nullptr && user->admin;
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

auto handle_local_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse
{
    if (!runtime.started)
    {
        return response(503U, "runtime not started");
    }
    if (request.method == "GET" && request.target == "/_merovingian/admin/health")
    {
        if (!admin_token_is_valid(runtime, request.access_token))
        {
            return response(401U, "admin authentication required");
        }
        return response(200U, admin_health_summary(runtime));
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/register")
    {
        auto const fields = split_pipe_2(request.body);
        if (!fields.has_value())
        {
            return response(400U, "registration body must be localpart|password");
        }
        return response_from_operation(register_local_user(runtime, (*fields)[0], (*fields)[1]), 200U);
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/login")
    {
        auto const fields = split_pipe_3(request.body);
        if (!fields.has_value())
        {
            return response(400U, "login body must be user_id|password|device_id");
        }
        return response_from_operation(login_local_user(runtime, (*fields)[0], (*fields)[1], (*fields)[2]), 200U);
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/logout")
    {
        auto result = logout_local_user(runtime, request.access_token);
        return result.ok ? response(200U, "logged out") : response(401U, result.reason);
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/createRoom")
    {
        auto result = create_room(runtime, request.access_token);
        return result.ok ? response(200U, result.value) : response(401U, result.reason);
    }

    auto constexpr rooms_prefix = std::string_view{"/_matrix/client/v3/rooms/"};
    if (!starts_with(request.target, rooms_prefix))
    {
        return response(404U, "route not found");
    }

    auto const suffix = std::string_view{request.target}.substr(rooms_prefix.size());
    auto constexpr join_suffix = std::string_view{"/join"};
    auto constexpr send_suffix = std::string_view{"/send"};
    auto constexpr state_suffix = std::string_view{"/state"};

    if (request.method == "POST" && suffix.size() > join_suffix.size()
        && suffix.substr(suffix.size() - join_suffix.size()) == join_suffix)
    {
        auto const room_id = suffix.substr(0U, suffix.size() - join_suffix.size());
        auto result = join_room(runtime, request.access_token, room_id);
        return result.ok ? response(200U, result.value) : response(401U, result.reason);
    }
    if (request.method == "POST" && suffix.size() > send_suffix.size()
        && suffix.substr(suffix.size() - send_suffix.size()) == send_suffix)
    {
        auto const room_id = suffix.substr(0U, suffix.size() - send_suffix.size());
        auto result = send_event(runtime, request.access_token, room_id, request.body);
        return result.ok ? response(200U, result.value) : response(401U, result.reason);
    }
    if (request.method == "GET" && suffix.size() > state_suffix.size()
        && suffix.substr(suffix.size() - state_suffix.size()) == state_suffix)
    {
        auto const room_id = suffix.substr(0U, suffix.size() - state_suffix.size());
        auto result = fetch_room_state(runtime, request.access_token, room_id);
        return result.ok ? response(200U, result.value) : response(401U, result.reason);
    }

    return response(404U, "route not found");
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

    auto const decision = trust_safety::evaluate_registration_policy(
        {user_id, "127.0.0.1", runtime.config.security().registration.enabled, false, {}}
    );
    if (!decision.allowed)
    {
        return make_result(false, {}, decision.reason.code);
    }

    auto const first_user_is_admin = runtime.database.users.empty();
    runtime.database.users.push_back({user_id, hash_password(password), false, false, first_user_is_admin});
    runtime.database.audit_events.push_back(audit(
        observability::AuditCategory::auth,
        "auth.user_registered",
        user_id,
        user_id,
        first_user_is_admin ? "created_admin" : "created"
    ));
    return make_result(true, user_id);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
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

    auto const session_id = runtime.database.next_session_id++;
    auto const token = issue_token(user->user_id, device_id, session_id);
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
        return make_result(false, {}, "unauthenticated");
    }

    runtime.database.audit_events.push_back(audit(
        observability::AuditCategory::auth,
        "auth.logout",
        user_id,
        device_id,
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

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
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
    auto user = handle_local_http_request(runtime, {"POST", "/_matrix/client/v3/register", {}, "alice|CorrectHorse7!"});
    if (user.status != 200U)
    {
        return make_result(false, {}, user.body);
    }
    auto login = handle_local_http_request(runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
    if (login.status != 200U)
    {
        return make_result(false, {}, login.body);
    }
    auto health = handle_local_http_request(runtime, {"GET", "/_merovingian/admin/health", login.body, {}});
    if (health.status != 200U)
    {
        return make_result(false, {}, health.body);
    }
    auto room = handle_local_http_request(runtime, {"POST", "/_matrix/client/v3/createRoom", login.body, {}});
    if (room.status != 200U)
    {
        return make_result(false, {}, room.body);
    }
    auto join = handle_local_http_request(runtime, {"POST", "/_matrix/client/v3/rooms/" + room.body + "/join", login.body, {}});
    if (join.status != 200U)
    {
        return make_result(false, {}, join.body);
    }
    auto event = handle_local_http_request(runtime, {"POST", "/_matrix/client/v3/rooms/" + room.body + "/send", login.body, R"({"type":"m.room.message","content":{"msgtype":"m.text"}})"});
    if (event.status != 200U)
    {
        return make_result(false, {}, event.body);
    }
    auto state = handle_local_http_request(runtime, {"GET", "/_matrix/client/v3/rooms/" + room.body + "/state", login.body, {}});
    if (state.status != 200U)
    {
        return make_result(false, {}, state.body);
    }
    auto logout = handle_local_http_request(runtime, {"POST", "/_matrix/client/v3/logout", login.body, {}});
    if (logout.status != 200U)
    {
        return make_result(false, {}, logout.body);
    }
    if (authenticated_user(runtime, login.body).has_value())
    {
        return make_result(false, {}, "logout did not revoke session");
    }
    if (audit_event_count(runtime) < 6U)
    {
        return make_result(false, {}, "audit log did not record vertical slice");
    }

    return make_result(true, state.body);
}

} // namespace merovingian::homeserver
