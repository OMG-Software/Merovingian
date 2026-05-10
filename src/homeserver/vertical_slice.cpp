// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/homeserver/vertical_slice.hpp>

#include "local_services.hpp"

namespace merovingian::homeserver
{

auto run_local_vertical_slice(config::Config const& config) -> OperationResult
{
    auto started = start_runtime(config);
    if (!started.started)
    {
        return make_operation_result(false, {}, started.reason);
    }

    auto& runtime = started.runtime;
    auto user = handle_local_http_request(runtime, {"POST", "/_matrix/client/v3/register", {}, "alice|CorrectHorse7!"});
    auto login = user.status == 200U
        ? handle_local_http_request(runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"})
        : LocalHttpResponse{400U, user.body};
    auto room = login.status == 200U
        ? handle_local_http_request(runtime, {"POST", "/_matrix/client/v3/createRoom", login.body, {}})
        : LocalHttpResponse{400U, login.body};
    auto join = room.status == 200U
        ? handle_local_http_request(runtime, {"POST", "/_matrix/client/v3/rooms/" + room.body + "/join", login.body, {}})
        : LocalHttpResponse{400U, room.body};
    auto event = join.status == 200U
        ? handle_local_http_request(runtime, {"POST", "/_matrix/client/v3/rooms/" + room.body + "/send", login.body, R"({"type":"m.room.message","content":{"msgtype":"m.text"}})"})
        : LocalHttpResponse{400U, join.body};
    auto state = event.status == 200U
        ? handle_local_http_request(runtime, {"GET", "/_matrix/client/v3/rooms/" + room.body + "/state", login.body, {}})
        : LocalHttpResponse{400U, event.body};
    auto logout = state.status == 200U
        ? handle_local_http_request(runtime, {"POST", "/_matrix/client/v3/logout", login.body, {}})
        : LocalHttpResponse{400U, state.body};

    if (logout.status != 200U)
    {
        return make_operation_result(false, {}, logout.body);
    }
    if (authenticated_user(runtime, login.body).has_value())
    {
        return make_operation_result(false, {}, "logout did not revoke session");
    }
    if (audit_event_count(runtime) < 6U)
    {
        return make_operation_result(false, {}, "audit log did not record vertical slice");
    }
    return make_operation_result(true, state.body);
}

} // namespace merovingian::homeserver
