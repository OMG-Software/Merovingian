// SPDX-License-Identifier: GPL-3.0-or-later

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <merovingian/canonicaljson/parser.hpp>
#include <merovingian/canonicaljson/value.hpp>
#include <merovingian/homeserver/client_server.hpp>
#include <merovingian/http/request.hpp>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto starts_with(std::string_view v, std::string_view p) noexcept -> bool
    {
        return v.size() >= p.size() && v.substr(0U, p.size()) == p;
    }

    [[nodiscard]] auto ends_with(std::string_view v, std::string_view suffix) noexcept -> bool
    {
        return v.size() >= suffix.size() && v.substr(v.size() - suffix.size()) == suffix;
    }

    [[nodiscard]] auto json_escape(std::string_view value) -> std::string
    {
        auto out = std::string{};
        for (auto const ch : value)
        {
            switch (ch)
            {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                out += ch;
                break;
            }
        }
        return out;
    }

    [[nodiscard]] auto resp(std::uint16_t status, std::string body) -> LocalHttpResponse
    {
        return {status, std::move(body)};
    }

    [[nodiscard]] auto err(std::uint16_t status, std::string_view code, std::string_view message) -> LocalHttpResponse
    {
        return resp(status, matrix_error(code, message));
    }

    [[nodiscard]] auto bad_http_request(std::uint16_t status, std::string_view message) -> LocalHttpResponse
    {
        return err(status, "M_BAD_REQUEST", message);
    }

    struct MatrixRegisterBody final
    {
        std::string localpart{};
        std::string password{};
    };

    struct MatrixLoginBody final
    {
        std::string user_id{};
        std::string password{};
        std::string device_id{};
    };

    struct MatrixDeviceUpdateBody final
    {
        std::string display_name{};
    };

    [[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto ascii_equal_case_insensitive(std::string_view left, std::string_view right) noexcept -> bool
    {
        if (left.size() != right.size())
        {
            return false;
        }
        for (auto index = std::size_t{0U}; index < left.size(); ++index)
        {
            auto left_char = left[index];
            auto right_char = right[index];
            if (left_char >= 'A' && left_char <= 'Z')
            {
                left_char = static_cast<char>(left_char - 'A' + 'a');
            }
            if (right_char >= 'A' && right_char <= 'Z')
            {
                right_char = static_cast<char>(right_char - 'A' + 'a');
            }
            if (left_char != right_char)
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto bearer_access_token(std::vector<http::Header> const& headers) -> std::string
    {
        auto constexpr bearer_prefix = std::string_view{"Bearer "};
        for (auto const& header : headers)
        {
            if (!ascii_equal_case_insensitive(header.name, "authorization"))
            {
                continue;
            }
            if (!starts_with(header.value, bearer_prefix) || header.value.size() == bearer_prefix.size())
            {
                return {};
            }
            return std::string{std::string_view{header.value}.substr(bearer_prefix.size())};
        }
        return {};
    }

    [[nodiscard]] auto object_member_as_object(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<canonicaljson::Object>(&value->storage());
    }

    [[nodiscard]] auto parsed_json_object(std::string_view body) -> std::optional<canonicaljson::Object>
    {
        auto parsed = canonicaljson::parse_lossless(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        return *object;
    }

    [[nodiscard]] auto parse_register_body(std::string_view body) -> std::optional<MatrixRegisterBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* username = string_member(*object, "username");
        if (username == nullptr)
        {
            username = string_member(*object, "user");
        }
        auto const* password = string_member(*object, "password");
        if (username == nullptr || password == nullptr)
        {
            return std::nullopt;
        }
        return MatrixRegisterBody{*username, *password};
    }

    [[nodiscard]] auto matrix_user_id(std::string_view server_name, std::string_view user) -> std::string
    {
        if (user.starts_with("@"))
        {
            return std::string{user};
        }
        return "@" + std::string{user} + ":" + std::string{server_name};
    }

    [[nodiscard]] auto parse_login_body(std::string_view body, std::string_view server_name)
        -> std::optional<MatrixLoginBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* type = string_member(*object, "type");
        if (type != nullptr && *type != "m.login.password")
        {
            return std::nullopt;
        }
        auto const* password = string_member(*object, "password");
        auto const* user = string_member(*object, "user");
        if (auto const* identifier = object_member_as_object(*object, "identifier"); identifier != nullptr)
        {
            auto const* identifier_type = string_member(*identifier, "type");
            if (identifier_type != nullptr && *identifier_type != "m.id.user")
            {
                return std::nullopt;
            }
            user = string_member(*identifier, "user");
        }
        if (password == nullptr || user == nullptr)
        {
            return std::nullopt;
        }
        auto const* device_id = string_member(*object, "device_id");
        return MatrixLoginBody{matrix_user_id(server_name, *user), *password,
                               device_id == nullptr ? "MEROVINGIAN" : *device_id};
    }

    [[nodiscard]] auto parse_device_update_body(std::string_view body) -> std::optional<MatrixDeviceUpdateBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* display_name = string_member(*object, "display_name");
        if (display_name == nullptr)
        {
            return std::nullopt;
        }
        return MatrixDeviceUpdateBody{*display_name};
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

    [[nodiscard]] auto auth(ClientServerRuntime const& rt, std::string_view token) -> std::optional<std::string>
    {
        return authenticated_user(rt.homeserver, token);
    }

    [[nodiscard]] auto normalized_bucket(LocalHttpRequest const& req) -> std::string
    {
        auto constexpr room_prefix = std::string_view{"/_matrix/client/v3/rooms/"};
        auto constexpr device_prefix = std::string_view{"/_matrix/client/v3/devices/"};
        auto target = std::string_view{req.target};
        if (starts_with(target, room_prefix) && ends_with(target, "/join"))
        {
            return req.method + " /_matrix/client/v3/rooms/{roomId}/join";
        }
        if (starts_with(target, room_prefix) && ends_with(target, "/send"))
        {
            return req.method + " /_matrix/client/v3/rooms/{roomId}/send";
        }
        if (starts_with(target, room_prefix) && ends_with(target, "/state"))
        {
            return req.method + " /_matrix/client/v3/rooms/{roomId}/state";
        }
        if (starts_with(target, device_prefix))
        {
            return req.method + " /_matrix/client/v3/devices/{deviceId}";
        }
        return req.method + ' ' + req.target;
    }

    [[nodiscard]] auto allow(ClientServerRuntime& rt, LocalHttpRequest const& req) -> bool
    {
        ++rt.request_clock;
        auto const bucket = normalized_bucket(req);
        auto const it = std::ranges::find_if(rt.rate_limits, [&bucket](ClientRateLimitCounter const& c) {
            return c.bucket == bucket;
        });
        if (it == rt.rate_limits.end())
        {
            rt.rate_limits.push_back({bucket, 1U, rt.request_clock});
            return true;
        }
        if (rt.request_clock - it->window_start_request >= rt.limits.rate_limit_window_requests)
        {
            it->count = 0U;
            it->window_start_request = rt.request_clock;
        }
        if (it->count >= rt.limits.max_requests_per_bucket)
        {
            return false;
        }
        ++it->count;
        return true;
    }

    [[nodiscard]] auto find_device(ClientServerRuntime& rt, std::string_view user, std::string_view device)
        -> ClientDevice*
    {
        auto const it = std::ranges::find_if(rt.devices, [user, device](ClientDevice const& d) {
            return d.user_id == user && d.device_id == device;
        });
        return it == rt.devices.end() ? nullptr : &(*it);
    }

    [[nodiscard]] auto devices_json(ClientServerRuntime const& rt, std::string_view user) -> std::string
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
            out += "{\"device_id\":\"" + json_escape(d.device_id) + "\",\"display_name\":\"" +
                   json_escape(d.display_name) + "\"}";
        }
        return out + "]}";
    }

    [[nodiscard]] auto joined(LocalRoom const& room, std::string_view user) -> bool
    {
        return std::ranges::any_of(room.members, [user](std::string const& member) {
            return member == user;
        });
    }

    [[nodiscard]] auto joined_rooms_json(ClientServerRuntime const& rt, std::string_view user) -> std::string
    {
        auto out = std::string{"{\"joined_rooms\":["};
        auto first = true;
        auto count = std::size_t{0U};
        for (auto const& room : rt.homeserver.database.rooms)
        {
            if (count >= rt.limits.max_sync_rooms || !joined(room, user))
            {
                continue;
            }
            out += first ? "" : ",";
            first = false;
            ++count;
            out += "\"" + json_escape(room.room_id) + "\"";
        }
        return out + "]}";
    }

    [[nodiscard]] auto sync_json(ClientServerRuntime const& rt, std::string_view user) -> std::string
    {
        auto out = std::string{"{\"next_batch\":\"s1\",\"rooms\":{\"join\":{"};
        auto first = true;
        auto count = std::size_t{0U};
        for (auto const& room : rt.homeserver.database.rooms)
        {
            if (count >= rt.limits.max_sync_rooms || !joined(room, user))
            {
                continue;
            }
            out += first ? "" : ",";
            first = false;
            ++count;
            auto const event_count = std::min(room.events.size(), rt.limits.max_sync_events_per_room);
            out += "\"" + json_escape(room.room_id) + "\":{\"timeline\":{\"limited\":";
            out += room.events.size() > event_count ? "true" : "false";
            out += ",\"event_count\":" + std::to_string(event_count) +
                   "},\"state\":{\"member_count\":" + std::to_string(room.members.size()) + "}}";
        }
        return out + "}}}";
    }

    [[nodiscard]] auto wrap(LocalHttpResponse const& r, std::string_view key) -> LocalHttpResponse
    {
        if (r.status != 200U)
        {
            return err(r.status, "M_FORBIDDEN", r.body);
        }
        return resp(200U, "{\"" + std::string{key} + "\":\"" + json_escape(r.body) + "\"}");
    }

} // namespace

auto start_client_server(config::Config const& config) -> ClientServerStartResult
{
    auto started = start_runtime(config);
    if (!started.started)
    {
        return {false, started.reason, {}};
    }
    auto rt = ClientServerRuntime{};
    rt.homeserver = std::move(started.runtime);
    rt.devices.reserve(rt.homeserver.database.persistent_store.devices.size());
    for (auto const& device : rt.homeserver.database.persistent_store.devices)
    {
        rt.devices.push_back({device.user_id, device.device_id, device.display_name});
    }
    return {true, {}, std::move(rt)};
}

auto matrix_error(std::string_view errcode, std::string_view message) -> std::string
{
    return "{\"errcode\":\"" + json_escape(errcode) + "\",\"error\":\"" + json_escape(message) + "\"}";
}

auto is_matrix_error_response(LocalHttpResponse const& r) noexcept -> bool
{
    return r.status >= 400U && starts_with(r.body, "{\"errcode\":\"");
}

auto handle_client_server_http_request(ClientServerRuntime& rt, std::string_view raw_request) -> LocalHttpResponse
{
    auto const head_end = raw_request.find("\r\n\r\n");
    if (head_end == std::string_view::npos)
    {
        return bad_http_request(400U, "incomplete HTTP request head");
    }

    auto const head = raw_request.substr(0U, head_end + std::string_view{"\r\n\r\n"}.size());
    auto const parsed = http::parse_request_head(head);
    if (parsed.error != http::RequestErrorCode::none)
    {
        return bad_http_request(http::request_error_status(parsed.error), http::request_error_name(parsed.error));
    }

    auto const available_body = raw_request.substr(head.size());
    if (!parsed.request.has_content_length)
    {
        if (!available_body.empty())
        {
            return bad_http_request(400U, "request body requires Content-Length");
        }
        return handle_client_server_request(
            rt, {parsed.request.method, parsed.request.target, bearer_access_token(parsed.request.headers), {}});
    }

    if (parsed.request.content_length > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
    {
        return bad_http_request(413U, "request body too large");
    }

    auto const declared_body_size = static_cast<std::size_t>(parsed.request.content_length);
    if (available_body.size() < declared_body_size)
    {
        return bad_http_request(400U, "incomplete request body");
    }
    if (available_body.size() > declared_body_size)
    {
        return bad_http_request(400U, "trailing data after request body");
    }

    return handle_client_server_request(rt, {parsed.request.method, parsed.request.target,
                                             bearer_access_token(parsed.request.headers), std::string{available_body}});
}

auto handle_client_server_request(ClientServerRuntime& rt, LocalHttpRequest const& req) -> LocalHttpResponse
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
        auto const body = parse_register_body(req.body);
        if (!body.has_value())
        {
            return err(400U, "M_BAD_JSON", "registration body must be Matrix JSON");
        }
        auto const result = register_local_user(rt.homeserver, body->localpart, body->password);
        return result.ok ? resp(200U, "{\"user_id\":\"" + json_escape(result.value) + "\"}")
                         : err(result.status, "M_FORBIDDEN", result.reason);
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/login")
    {
        auto const body = parse_login_body(req.body, rt.homeserver.config.server().server_name);
        if (!body.has_value())
        {
            return err(400U, "M_BAD_JSON", "login body must be Matrix password JSON");
        }
        auto const result = login_local_user(rt.homeserver, body->user_id, body->password, body->device_id);
        if (!result.ok)
        {
            return err(result.status, "M_FORBIDDEN", result.reason);
        }
        if (find_device(rt, body->user_id, body->device_id) == nullptr)
        {
            rt.devices.push_back({body->user_id, body->device_id, body->device_id});
        }
        return resp(200U, "{\"access_token\":\"" + json_escape(result.value) + "\",\"user_id\":\"" +
                              json_escape(body->user_id) + "\",\"device_id\":\"" + json_escape(body->device_id) +
                              "\"}");
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
        return resp(200U, "{\"user_id\":\"" + json_escape(*user) + "\"}");
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
        auto const body = parse_device_update_body(req.body);
        if (!body.has_value())
        {
            return err(400U, "M_BAD_JSON", "device update body must be Matrix JSON");
        }
        device->display_name = body->display_name;
        rt.homeserver.database.audit_events.push_back(
            observability::make_audit_event(observability::AuditCategory::auth, "device.updated", *user,
                                            device->device_id, "display_name_updated", "client-server"));
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
        if (req.method == "POST" && suffix.size() > join_s.size() &&
            suffix.substr(suffix.size() - join_s.size()) == join_s)
        {
            return wrap(handle_local_http_request(rt.homeserver, req), "room_id");
        }
        if (req.method == "POST" && suffix.size() > send_s.size() &&
            suffix.substr(suffix.size() - send_s.size()) == send_s)
        {
            return wrap(handle_local_http_request(rt.homeserver, req), "event_id");
        }
        if (req.method == "GET" && suffix.size() > state_s.size() &&
            suffix.substr(suffix.size() - state_s.size()) == state_s)
        {
            return wrap(handle_local_http_request(rt.homeserver, req), "state");
        }
    }
    return err(404U, "M_UNRECOGNIZED", "route not found");
}

auto device_count(ClientServerRuntime const& rt, std::string_view user) noexcept -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(rt.devices, [user](ClientDevice const& d) {
        return d.user_id == user;
    }));
}

auto joined_room_count(ClientServerRuntime const& rt, std::string_view user) noexcept -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(rt.homeserver.database.rooms, [user](LocalRoom const& room) {
        return joined(room, user);
    }));
}

auto run_client_server_flow(config::Config const& config) -> OperationResult
{
    auto started = start_client_server(config);
    if (!started.started)
    {
        return {false, 400U, {}, started.reason};
    }
    auto& rt = started.runtime;
    auto reg = handle_client_server_request(
        rt, {"POST", "/_matrix/client/v3/register", {}, R"({"username":"alice","password":"CorrectHorse7!"})"});
    auto login = handle_client_server_request(
        rt,
        {"POST",
         "/_matrix/client/v3/login",
         {},
         R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
    auto const token = json_value(login.body, "\"access_token\":\"");
    auto whoami = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/account/whoami", token, {}});
    auto room = handle_client_server_request(rt, {"POST", "/_matrix/client/v3/createRoom", token, {}});
    auto const room_id = json_value(room.body, "\"room_id\":\"");
    auto send = handle_client_server_request(rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/send", token,
                                                  R"({"type":"m.room.encrypted","content":"secret"})"});
    auto state = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/state", token, {}});
    auto joined_r = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/joined_rooms", token, {}});
    auto devices = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/devices", token, {}});
    auto sync = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/sync", token, {}});
    if (reg.status != 200U || login.status != 200U || whoami.status != 200U || room.status != 200U ||
        send.status != 200U || state.status != 200U || joined_r.status != 200U || devices.status != 200U ||
        sync.status != 200U)
    {
        return {false, 400U, {}, "client-server flow failed"};
    }
    if (sync.body.find("secret") != std::string::npos || sync.body.find("m.room.encrypted") != std::string::npos)
    {
        return {false, 500U, {}, "sync leaked plaintext event content"};
    }
    return {true, 200U, sync.body, {}};
}

} // namespace merovingian::homeserver
