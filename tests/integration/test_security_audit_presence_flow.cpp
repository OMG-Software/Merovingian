// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace
{

class PresenceSqliteFixture final
{
public:
    PresenceSqliteFixture()
    {
        static auto counter = std::uint64_t{0U};
        auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
        directory_ = merovingian::tests::temporary_directory() /
                     ("merovingian-security-audit-presence-" + std::to_string(now) + "-" + std::to_string(counter++));
        std::filesystem::create_directories(directory_);
    }

    ~PresenceSqliteFixture()
    {
        auto ignored = std::error_code{};
        std::filesystem::remove_all(directory_, ignored);
    }

    PresenceSqliteFixture(PresenceSqliteFixture const&) = delete;
    auto operator=(PresenceSqliteFixture const&) -> PresenceSqliteFixture& = delete;

    [[nodiscard]] auto database_path() const -> std::filesystem::path
    {
        return directory_ / "presence.sqlite3";
    }

private:
    std::filesystem::path directory_{};
};

[[nodiscard]] auto presence_test_config(std::filesystem::path const& sqlite_path) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = sqlite_path.string();
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto user_id_for(std::string_view localpart) -> std::string
{
    return std::string{"@"} + std::string{localpart} + ":example.org";
}

[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view localpart,
                                      std::string_view password) -> std::string
{
    auto const user_id = user_id_for(localpart);
    auto const registered = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json(localpart, password)});
    REQUIRE(registered.response.status == 200U);

    auto const login_body =
        std::string{"{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\""} + user_id +
        "\"},\"password\":\"" + std::string{password} + "\",\"device_id\":\"" + std::string{localpart} + "_DEVICE\"}";
    auto const logged_in = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, login_body});
    REQUIRE(logged_in.response.status == 200U);
    auto const response = merovingian::tests::parse_object(logged_in.response.body);
    auto const* token = merovingian::tests::string_member(response, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto create_room(merovingian::homeserver::ClientServerRuntime& runtime,
                               std::string_view token) -> std::string
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", std::string{token}, "{}"});
    REQUIRE(response.response.status == 200U);
    auto const body = merovingian::tests::parse_object(response.response.body);
    auto const* room_id = merovingian::tests::string_member(body, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

auto invite_user(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view owner_token,
                 std::string_view room_id, std::string_view localpart) -> void
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/rooms/" + std::string{room_id} + "/invite", std::string{owner_token},
                  R"({"user_id":")" + user_id_for(localpart) + R"("})"});
    REQUIRE(response.response.status == 200U);
}

auto join_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view token,
               std::string_view room_id) -> void
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/join/" + std::string{room_id}, std::string{token}, "{}"});
    REQUIRE(response.response.status == 200U);
}

auto set_presence(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view localpart,
                  std::string_view token, std::string const& body) -> merovingian::homeserver::LocalHttpResponse
{
    auto const target =
        std::string{"/_matrix/client/v3/presence/%40"} + std::string{localpart} + "%3Aexample.org/status";
    return merovingian::homeserver::handle_client_server_request(runtime, {"PUT", target, std::string{token}, body})
        .response;
}

[[nodiscard]] auto stored_presence(merovingian::database::PersistentStore const& store,
                                   std::string_view user_id) -> std::optional<merovingian::database::PersistentPresence>
{
    auto const found = std::ranges::find_if(store.presence_states, [user_id](auto const& presence) {
        return presence.user_id == user_id;
    });
    if (found == store.presence_states.end())
    {
        return std::nullopt;
    }
    return *found;
}

[[nodiscard]] auto same_presence(merovingian::database::PersistentPresence const& lhs,
                                 merovingian::database::PersistentPresence const& rhs) -> bool
{
    return lhs.stream_id == rhs.stream_id && lhs.user_id == rhs.user_id && lhs.presence == rhs.presence &&
           lhs.status_msg == rhs.status_msg && lhs.last_active_ago == rhs.last_active_ago &&
           lhs.currently_active == rhs.currently_active;
}

[[nodiscard]] auto presence_senders(std::string const& sync_body) -> std::vector<std::string>
{
    auto const body = merovingian::tests::parse_object(sync_body);
    auto const* presence = merovingian::tests::object_member_as_object(body, "presence");
    REQUIRE(presence != nullptr);
    auto const* events = merovingian::tests::object_member_as_array(*presence, "events");
    REQUIRE(events != nullptr);

    auto senders = std::vector<std::string>{};
    for (auto const& value : *events)
    {
        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        REQUIRE(event != nullptr);
        auto const* type = merovingian::tests::string_member(*event, "type");
        if (type == nullptr || *type != "m.presence")
        {
            continue;
        }
        auto const* sender = merovingian::tests::string_member(*event, "sender");
        REQUIRE(sender != nullptr);
        senders.push_back(*sender);
    }
    return senders;
}

[[nodiscard]] auto next_batch(std::string const& sync_body) -> std::string
{
    auto const body = merovingian::tests::parse_object(sync_body);
    auto const* token = merovingian::tests::string_member(body, "next_batch");
    REQUIRE(token != nullptr);
    return *token;
}

} // namespace

// Matrix v1.19 CS API §Presence sends events to interested parties that share
// room membership. The PUT endpoint requires `presence` to be online, offline,
// or unavailable; optional `status_msg` has type string. The 1024-byte cap below
// is this project’s resource policy, not a Matrix limit.
SCENARIO("Sync presence is visible only between users with current shared room membership",
         "[integration][security_audit_presence]")
{
    GIVEN("users with shared, unrelated, invited, left, and banned membership states")
    {
        auto sqlite = PresenceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(presence_test_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice_token = register_and_login(runtime, "alice", "CorrectHorse7!");
        auto const bob_token = register_and_login(runtime, "bob", "CorrectHorse8!");
        auto const carol_token = register_and_login(runtime, "carol", "CorrectHorse9!");
        auto const dave_token = register_and_login(runtime, "dave", "CorrectHorse0!");
        auto const erin_token = register_and_login(runtime, "erin", "CorrectHorse1!");
        auto const frank_token = register_and_login(runtime, "frank", "CorrectHorse2!");
        auto const room_id = create_room(runtime, alice_token);

        invite_user(runtime, alice_token, room_id, "bob");
        join_room(runtime, bob_token, room_id);
        invite_user(runtime, alice_token, room_id, "dave");
        invite_user(runtime, alice_token, room_id, "erin");
        join_room(runtime, erin_token, room_id);
        invite_user(runtime, alice_token, room_id, "frank");
        join_room(runtime, frank_token, room_id);
        auto const left = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", erin_token, "{}"});
        REQUIRE(left.response.status == 200U);
        auto const banned = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/ban", alice_token,
                      R"({"user_id":"@frank:example.org"})"});
        REQUIRE(banned.response.status == 200U);

        for (auto const& [localpart, token] : std::vector<std::pair<std::string_view, std::string_view>>{
                 {"bob",   bob_token  },
                 {"carol", carol_token},
                 {"dave",  dave_token },
                 {"erin",  erin_token },
                 {"frank", frank_token}
        })
        {
            REQUIRE(set_presence(runtime, localpart, token, R"({"presence":"online"})").status == 200U);
        }

        WHEN("Alice performs an initial sync and then an incremental sync after everyone updates presence")
        {
            auto const initial = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync?timeout=0", alice_token, {}});
            REQUIRE(initial.response.status == 200U);
            auto const since = next_batch(initial.response.body);

            REQUIRE(set_presence(runtime, "bob", bob_token, R"({"presence":"unavailable"})").status == 200U);
            REQUIRE(set_presence(runtime, "carol", carol_token, R"({"presence":"unavailable"})").status == 200U);
            REQUIRE(set_presence(runtime, "dave", dave_token, R"({"presence":"unavailable"})").status == 200U);
            REQUIRE(set_presence(runtime, "erin", erin_token, R"({"presence":"unavailable"})").status == 200U);
            REQUIRE(set_presence(runtime, "frank", frank_token, R"({"presence":"unavailable"})").status == 200U);

            auto const incremental = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync?timeout=0&since=" + since, alice_token, {}});

            THEN("both sync responses contain the shared joined member and exclude all other membership states")
            {
                REQUIRE(incremental.response.status == 200U);
                auto const initial_senders = presence_senders(initial.response.body);
                auto const incremental_senders = presence_senders(incremental.response.body);
                REQUIRE(initial_senders == std::vector<std::string>{"@bob:example.org"});
                REQUIRE(incremental_senders == std::vector<std::string>{"@bob:example.org"});
            }
        }
    }
}

SCENARIO("Invalid presence updates preserve stored state and the sync stream watermark",
         "[integration][security_audit_presence]")
{
    GIVEN("a user with a valid persisted presence row")
    {
        auto sqlite = PresenceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(presence_test_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice_token = register_and_login(runtime, "alice", "CorrectHorse7!");
        REQUIRE(set_presence(runtime, "alice", alice_token, R"({"presence":"online","status_msg":"initial status"})")
                    .status == 200U);

        auto const user_id = user_id_for("alice");
        auto const& store = runtime.homeserver.database.persistent_store;
        auto const original = stored_presence(store, user_id);
        REQUIRE(original.has_value());

        WHEN("presence is missing, null, unknown, wrongly typed, or has a null/non-string status message")
        {
            auto const invalid_bodies = std::vector<std::string>{
                "{}",
                R"({"presence":null})",
                R"({"presence":"busy"})",
                R"({"presence":7})",
                R"({"presence":"online","status_msg":null})",
                R"({"presence":"online","status_msg":7})",
            };

            THEN("each request returns 400 without changing the stored row or stream watermark")
            {
                for (auto const& body : invalid_bodies)
                {
                    auto const watermark = store.next_sync_stream_id;
                    auto const response = set_presence(runtime, "alice", alice_token, body);
                    CHECK(response.status == 400U);
                    CHECK(store.next_sync_stream_id == watermark);
                    auto const after = stored_presence(store, user_id);
                    REQUIRE(after.has_value());
                    CHECK(same_presence(*after, *original));
                }
            }
        }
    }
}

SCENARIO("Presence status messages are limited by UTF-8 byte length", "[integration][security_audit_presence]")
{
    GIVEN("an authenticated user updating status messages at the 1024-byte boundary")
    {
        auto sqlite = PresenceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(presence_test_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice_token = register_and_login(runtime, "alice", "CorrectHorse7!");
        auto const at_limit = std::string(1022U, 'a') + "\xC3\xA9"; // 1022 ASCII bytes plus one 2-byte UTF-8 character.
        auto const above_limit = std::string(1023U, 'a') + "\xC3\xA9";
        REQUIRE(at_limit.size() == 1024U);
        REQUIRE(above_limit.size() == 1025U);
        auto const at_limit_body = R"({"presence":"online","status_msg":")" + at_limit + R"("})";
        auto const over_limit_body = R"({"presence":"offline","status_msg":")" + above_limit + R"("})";

        WHEN("the byte limit is met and then exceeded by one UTF-8 byte")
        {
            auto const accepted = set_presence(runtime, "alice", alice_token, at_limit_body);
            auto const accepted_row =
                stored_presence(runtime.homeserver.database.persistent_store, user_id_for("alice"));
            REQUIRE(accepted_row.has_value());
            auto const watermark = runtime.homeserver.database.persistent_store.next_sync_stream_id;
            auto const rejected = set_presence(runtime, "alice", alice_token, over_limit_body);
            auto const row_after_rejection =
                stored_presence(runtime.homeserver.database.persistent_store, user_id_for("alice"));

            THEN("1024 UTF-8 bytes are accepted and 1025 are rejected without changing state")
            {
                REQUIRE(accepted.status == 200U);
                REQUIRE(accepted_row->status_msg == at_limit);
                REQUIRE(rejected.status == 400U);
                REQUIRE(runtime.homeserver.database.persistent_store.next_sync_stream_id == watermark);
                REQUIRE(row_after_rejection.has_value());
                REQUIRE(same_presence(*row_after_rejection, *accepted_row));
            }
        }
    }
}
