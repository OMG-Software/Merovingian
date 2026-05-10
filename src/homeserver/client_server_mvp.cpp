// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/homeserver/client_server_mvp.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace merovingian::homeserver
{
namespace
{

[[nodiscard]] auto starts_with(std::string_view v, std::string_view p) noexcept -> bool
{
    return v.size() >= p.size() && v.substr(0U, p.size()) == p;
}

[[nodiscard]] auto resp(std::uint16_t status, std::string body) -> LocalHttpResponse
{
    return {status, std::move(body)};
}

[[nodiscard]] auto err(std::uint16_t status, std::string_view code, std::string_view message) -> LocalHttpResponse
{
    return resp(status, matrix_error(code, message));
}

[[nodiscard]] auto parse3(std::string_view body) -> std::optional<std::tuple<std::string_view, std::string_view, std::string_view>>
{
    auto const a = body.find('|');
    if (a == std::string_view::npos || a == 0U)
    {
        return std::nullopt;
    }
    auto const b = body.find('|', a + 1U);
    if (b == std::string_view::npos || b == a + 1U || b + 1U >= body.size())
    {
        return std::nullopt;
    }
    return std::tuple{body.substr(0U, a), body.substr(a + 1U, b - a - 1U), body.substr(b + 1U)};
}

[[nodiscard]] auto json_value(std::string_view body, std::string_view key) -> std::string
{
    auto const start = body.find(key);
    if (start == std::string_view::npos)
    {
        return {};
    }
    auto const value_start = start + key.size();
    auto const value_end = body.find('"', value_start);
    if (value_end == std::string_view::npos)
    {
        return {};
    }
    return std::string{body.substr(value_start, value_end - value_start)};
}

[[nodiscard]] auto auth(ClientServerMvpRuntime const& rt, std::string_view token) -> std::optional<std::string>
{
    return authenticated_user(rt.homeserver, token);
}

[[nodiscard]] auto allow(ClientServerMvpRuntime& rt, LocalHttpRequest const& req) -> bool
{
    auto const bucket = req.method + ' ' + req.target;
    auto const it = std::ranges::find_if(rt.rate_limits, [&bucket](MvpRateLimitCounter const& c) {
        return c.bucket == bucket;
    });
    if (it == rt.rate_limits.end())
    {
        rt.rate_limits.push_back({bucket, 1U});
        return true;
    }
    if (it->count >= rt.limits.max_requests_per_bucket)
    {
        return false;
    }
    ++it->count;
    return true;
}

[[nodiscard]] auto find_device(ClientServerMvpRuntime& rt, std::string_view user, std::string_view device) -> MvpDevice*
{
    auto const it = std::ranges::find_if(rt.devices, [user, device](MvpDevice const& d) {
        return d.user_id == user && d.device_id == device;
    });
    return it == rt.devices.end() ? nullptr : &(*it);
}

[[nodiscard]] auto devices_json(ClientServerMvpRuntime const& rt, std::string_view user) -> std::string
{
    auto out = std::string{"{\"devices\":["};
    auto first = true;
    for (auto const& d : rt.devices)
    {
        if (d.user_id != user)
        {
            continue;
        }
        out += first ? "" : ",";
        first = false;
        out += "{\"device_id\":\"" + d.device_id + "\",\"display_name\":\"" + d.display_name + "\"}";
    }
    return out + "]}";
}

[[nodiscard]] auto joined(ClientServerMvpRuntime const& rt, LocalRoom const& room, std::string_view user) -> bool
{
    return std::ranges::any_of(room.members, [user](std::string const& member) { return member == user; });
}

[[nodiscard]] auto joined_rooms_json(ClientServerMvpRuntime const& rt, std::string_view user) -> std::string
{
    auto out = std::string{"{\"joined_rooms\":["};
    auto first = true;
    auto count = std::size_t{0U};
    for (auto const& room : rt.homeserver.database.rooms)
    {
        if (count >= rt.limits.max_sync_rooms || !joined(rt, room, user))
        {
            continue;
        }
        out += first ? "" : ",";
        first = false;
        ++count;
        out += "\"" + room.room_id + "\"";
    }
    return out + "]}";
}

[[nodiscard]] auto sync_json(ClientServerMvpRuntime const& rt, std::string_view user) -> std::string
{
    auto out = std::string{"{\"next_batch\":\"mvp-1\",\"rooms\":{\"join\":{"};
    auto first = true;
    auto count = std::size_t{0U};
    for (auto const& room : rt.homeserver.database.rooms)
    {
        if (count >= rt.limits.max_sync_rooms || !joined(rt, room, user))
        {
            continue;
        }
        out += first ? "" : ",";
        first = false;
        ++count;
        auto const event_count = std::min(room.events.size(), rt.limits.max_sync_events_per_room);
        out += "\"" + room.room_id + "\":{\"timeline\":{\"limited\":";
        out += room.events.size() > event_count ? "true" : "false";
        out += ",\"event_count\":" + std::to_string(event_count) + "},\"state\":{\"member_count\":" + std::to_string(room.members.size()) + "}}";
    }
    return out + "}}}";
}

[[nodiscard]] auto wrap(LocalHttpResponse const& r, std::string_view key) -> LocalHttpResponse
{
    if (r.status != 200U)
    {
        return err(r.status, "M_FORBIDDEN", r.body);
    }
    return resp(200U, "{\"" + std::string{key} + "\":\"" + r.body + "\"}");
}

} // namespace

auto start_client_server_mvp(config::Config const& config) -> ClientServerMvpStartResult
{
    auto started = start_runtime(config);
    if (!started.started)
    {
        return {false, started.reason, {}};
    }
    auto rt = ClientServerMvpRuntime{};
    rt.homeserver = std::move(started.runtime);
    return {true, {}, std::move(rt)};
}

auto matrix_error(std::string_view errcode, std::string_view message) -> std::string
{
    return "{\"errcode\":\"" + std::string{errcode} + "\",\"error\":\"" + std::string{message} + "\"}";
}

auto is_matrix_error_response(LocalHttpResponse const& r) noexcept -> bool
{
    return r.status >= 400U && starts_with(r.body, "{\"errcode\":\"");
}

auto handle_client_server_request(ClientServerMvpRuntime& rt, LocalHttpRequest const& req) -> LocalHttpResponse
{
    if (!rt.homeserver.started)
    {
        return err(503U, "M_UNAVAILABLE", "runtime not started");
    }
    if (req.body.size() > rt.limits.max_body_bytes)
    {
        return err(413U, "M_TOO_LARGE", "request body too large");
    }
    if (!allow(rt, req))
    {
        return err(429U, "M_LIMIT_EXCEEDED", "rate limit exceeded");
    }

    if (req.method == "POST" && req.target == "/_matrix/client/v3/register")
    {
        auto const r = handle_local_http_request(rt.homeserver, req);
        return r.status == 200U ? resp(200U, "{\"user_id\":\"" + r.body + "\"}") : err(r.status, "M_FORBIDDEN", r.body);
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/login")
    {
        auto const fields = parse3(req.body);
        if (!fields.has_value())
        {
            return err(400U, "M_BAD_JSON", "login body must be user_id|password|device_id");
        }
        auto const [user, password, device] = *fields;
        auto const r = handle_local_http_request(rt.homeserver, req);
        if (r.status != 200U)
        {
            return err(r.status, "M_FORBIDDEN", r.body);
        }
        if (find_device(rt, user, device) == nullptr)
        {
            rt.devices.push_back({std::string{user}, std::string{device}, std::string{device}});
        }
        return resp(200U, "{\"access_token\":\"" + r.body + "\",\"user_id\":\"" + std::string{user} + "\",\"device_id\":\"" + std::string{device} + "\"}");
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/logout")
    {
        auto const r = handle_local_http_request(rt.homeserver, req);
        return r.status == 200U ? resp(200U, "{}") : err(401U, "M_UNKNOWN_TOKEN", r.body);
    }

    auto const user = auth(rt, req.access_token);
    if (!user.has_value())
    {
        return err(401U, "M_UNKNOWN_TOKEN", "unauthenticated");
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/account/whoami")
    {
        return resp(200U, "{\"user_id\":\"" + *user + "\"}");
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/devices")
    {
        return resp(200U, devices_json(rt, *user));
    }
    auto constexpr dev_prefix = std::string_view{"/_matrix/client/v3/devices/"};
    if (req.method == "PUT" && starts_with(req.target, dev_prefix))
    {
        auto const device_id = std::string_view{req.target}.substr(dev_prefix.size());
        auto* device = find_device(rt, *user, device_id);
        if (device == nullptr)
        {
            return err(404U, "M_NOT_FOUND", "device not found");
        }
        device->display_name = req.body.empty() ? device->device_id : req.body;
        rt.homeserver.database.audit_events.push_back(observability::make_audit_event(observability::AuditCategory::auth, "device.updated", *user, device->device_id, "display_name_updated", "client-server-mvp"));
        return resp(200U, "{}");
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/createRoom")
    {
        return wrap(handle_local_http_request(rt.homeserver, req), "room_id");
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/joined_rooms")
    {
        return resp(200U, joined_rooms_json(rt, *user));
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/sync")
    {
        return resp(200U, sync_json(rt, *user));
    }

    auto constexpr room_prefix = std::string_view{"/_matrix/client/v3/rooms/"};
    if (starts_with(req.target, room_prefix))
    {
        auto constexpr join_s = std::string_view{"/join"};
        auto constexpr send_s = std::string_view{"/send"};
        auto constexpr state_s = std::string_view{"/state"};
        auto const suffix = std::string_view{req.target}.substr(room_prefix.size());
        if (req.method == "POST" && suffix.size() > join_s.size() && suffix.substr(suffix.size() - join_s.size()) == join_s)
        {
            return wrap(handle_local_http_request(rt.homeserver, req), "room_id");
        }
        if (req.method == "POST" && suffix.size() > send_s.size() && suffix.substr(suffix.size() - send_s.size()) == send_s)
        {
            return wrap(handle_local_http_request(rt.homeserver, req), "event_id");
        }
        if (req.method == "GET" && suffix.size() > state_s.size() && suffix.substr(suffix.size() - state_s.size()) == state_s)
        {
            return wrap(handle_local_http_request(rt.homeserver, req), "state");
        }
    }
    return err(404U, "M_UNRECOGNIZED", "route not found");
}

auto device_count(ClientServerMvpRuntime const& rt, std::string_view user) noexcept -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(rt.devices, [user](MvpDevice const& d) { return d.user_id == user; }));
}

auto joined_room_count(ClientServerMvpRuntime const& rt, std::string_view user) noexcept -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(rt.homeserver.database.rooms, [&rt, user](LocalRoom const& room) { return joined(rt, room, user); }));
}

auto run_client_server_mvp_flow(config::Config const& config) -> OperationResult
{
    auto started = start_client_server_mvp(config);
    if (!started.started)
    {
        return {false, {}, started.reason};
    }
    auto& rt = started.runtime;
    auto reg = handle_client_server_request(rt, {"POST", "/_matrix/client/v3/register", {}, "alice|CorrectHorse7!"});
    auto login = handle_client_server_request(rt, {"POST", "/_matrix/client/v3/login", {}, "@alice:example.org|CorrectHorse7!|DEVICE1"});
    auto const token = json_value(login.body, "\"access_token\":\"");
    auto whoami = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/account/whoami", token, {}});
    auto room = handle_client_server_request(rt, {"POST", "/_matrix/client/v3/createRoom", token, {}});
    auto const room_id = json_value(room.body, "\"room_id\":\"");
    auto send = handle_client_server_request(rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/send", token, R"({"type":"m.room.encrypted","content":"secret"})"});
    auto state = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/state", token, {}});
    auto joined_r = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/joined_rooms", token, {}});
    auto devices = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/devices", token, {}});
    auto sync = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/sync", token, {}});
    if (reg.status != 200U || login.status != 200U || whoami.status != 200U || room.status != 200U || send.status != 200U || state.status != 200U || joined_r.status != 200U || devices.status != 200U || sync.status != 200U)
    {
        return {false, {}, "client-server MVP flow failed"};
    }
    if (sync.body.find("secret") != std::string::npos || sync.body.find("m.room.encrypted") != std::string::npos)
    {
        return {false, {}, "sync leaked plaintext event content"};
    }
    return {true, sync.body, {}};
}

} // namespace merovingian::homeserver
