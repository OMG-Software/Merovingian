// SPDX-License-Identifier: GPL-3.0-or-later

// DB-4 (29 Sep 2026 audit): a membership event, its current_state row, the
// `membership` row and the invite cleanup are written in one transaction, and
// hydration reconciles the `membership` table from current_state. Matrix v1.19
// CS API "m.room.member": the room's current m.room.member state event is the
// user's membership; a row that disagrees with it is not.

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/database/postgresql_store.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>

#include <libpq-fe.h>
#include <sqlite3.h>

namespace
{

using merovingian::homeserver::ClientServerRuntime;

struct SqliteCloser final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        if (connection != nullptr)
        {
            std::ignore = sqlite3_close(connection);
        }
    }
};

// A second, independent connection to the server's database file: the server
// opens a fresh connection per write, so a trigger installed here applies to
// its next transaction.
class SqliteConnection final
{
public:
    explicit SqliteConnection(std::filesystem::path const& path)
    {
        auto* raw_connection = static_cast<sqlite3*>(nullptr);
        auto const status = sqlite3_open(path.string().c_str(), &raw_connection);
        connection_.reset(raw_connection);
        REQUIRE(status == SQLITE_OK);
        REQUIRE(connection_ != nullptr);
    }

    SqliteConnection(SqliteConnection const&) = delete;
    auto operator=(SqliteConnection const&) -> SqliteConnection& = delete;
    SqliteConnection(SqliteConnection&&) = delete;
    auto operator=(SqliteConnection&&) -> SqliteConnection& = delete;
    ~SqliteConnection() = default;

    [[nodiscard]] auto execute(std::string_view sql) const -> bool
    {
        auto const statement = std::string{sql};
        return sqlite3_exec(connection_.get(), statement.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
    }

private:
    std::unique_ptr<sqlite3, SqliteCloser> connection_{};
};

class MembershipSqliteFixture final
{
public:
    MembershipSqliteFixture()
    {
        static auto counter = std::uint64_t{0U};
        auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
        directory_ = merovingian::tests::temporary_directory() /
                     ("merovingian-db4-membership-" + std::to_string(now) + "-" + std::to_string(counter++));
        std::filesystem::create_directories(directory_);
    }

    ~MembershipSqliteFixture()
    {
        auto ignored = std::error_code{};
        std::filesystem::remove_all(directory_, ignored);
    }

    MembershipSqliteFixture(MembershipSqliteFixture const&) = delete;
    auto operator=(MembershipSqliteFixture const&) -> MembershipSqliteFixture& = delete;
    MembershipSqliteFixture(MembershipSqliteFixture&&) = delete;
    auto operator=(MembershipSqliteFixture&&) -> MembershipSqliteFixture& = delete;

    [[nodiscard]] auto database_path() const -> std::filesystem::path
    {
        return directory_ / "membership.sqlite3";
    }

private:
    std::filesystem::path directory_{};
};

[[nodiscard]] auto sqlite_config(std::filesystem::path const& sqlite_path) -> merovingian::config::Config
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

constexpr auto bob_user_id = std::string_view{"@bob:example.org"};

[[nodiscard]] auto request(ClientServerRuntime& runtime, std::string method, std::string target, std::string_view token,
                           std::string body) -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {std::move(method), std::move(target), std::string{token}, std::move(body)})
        .response;
}

[[nodiscard]] auto register_and_login(ClientServerRuntime& runtime, std::string_view localpart,
                                      std::string_view password) -> std::string
{
    auto const registered = request(runtime, "POST", "/_matrix/client/v3/register", {},
                                    merovingian::tests::registration_json(localpart, password));
    REQUIRE(registered.status == 200U);
    auto const login_body = std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} +
                            std::string{localpart} + R"(:example.org"},"password":")" + std::string{password} +
                            R"(","device_id":")" + std::string{localpart} + R"(_DEVICE"})";
    auto const logged_in = request(runtime, "POST", "/_matrix/client/v3/login", {}, login_body);
    REQUIRE(logged_in.status == 200U);
    auto const response = merovingian::tests::parse_object(logged_in.body);
    auto const* token = merovingian::tests::string_member(response, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto room_path(std::string_view room_id, std::string_view suffix) -> std::string
{
    return "/_matrix/client/v3/rooms/" + std::string{room_id} + std::string{suffix};
}

auto send_text(ClientServerRuntime& runtime, std::string_view token, std::string_view room_id, std::string_view txn,
               std::string_view body) -> void
{
    auto const sent = request(runtime, "PUT", room_path(room_id, "/send/m.room.message/" + std::string{txn}), token,
                              R"({"msgtype":"m.text","body":")" + std::string{body} + R"("})");
    REQUIRE(sent.status == 200U);
}

struct JoinedRoom final
{
    std::string alice_token{};
    std::string bob_token{};
    std::string room_id{};
};

// alice creates a room, invites bob, bob joins, and alice says something.
[[nodiscard]] auto alice_and_bob_in_a_room(ClientServerRuntime& runtime) -> JoinedRoom
{
    auto room = JoinedRoom{};
    room.alice_token = register_and_login(runtime, "alice", "CorrectHorse7!");
    room.bob_token = register_and_login(runtime, "bob", "CorrectHorse8!");
    auto const created = request(runtime, "POST", "/_matrix/client/v3/createRoom", room.alice_token, "{}");
    REQUIRE(created.status == 200U);
    auto const created_body = merovingian::tests::parse_object(created.body);
    auto const* room_id = merovingian::tests::string_member(created_body, "room_id");
    REQUIRE(room_id != nullptr);
    room.room_id = *room_id;
    REQUIRE(request(runtime, "POST", room_path(room.room_id, "/invite"), room.alice_token,
                    R"({"user_id":"@bob:example.org"})")
                .status == 200U);
    REQUIRE(request(runtime, "POST", "/_matrix/client/v3/join/" + room.room_id, room.bob_token, "{}").status == 200U);
    send_text(runtime, room.alice_token, room.room_id, "before", "said-before-the-ban");
    return room;
}

struct DurableMembership final
{
    std::optional<std::string> row{};
    std::string current_member_event_id{};
    std::string current_member_event_json{};
    bool ban_event_stored{false};
};

// What the database file holds for bob, read through a fresh store.
[[nodiscard]] auto durable_membership_of_bob(std::filesystem::path const& path, std::string_view room_id)
    -> DurableMembership
{
    auto opened = merovingian::database::open_sqlite_persistent_store(path.string());
    REQUIRE(opened.ok);
    auto const& store = opened.store;
    auto durable = DurableMembership{};
    auto const row = std::ranges::find_if(store.memberships, [room_id](auto const& membership) {
        return membership.room_id == room_id && membership.user_id == bob_user_id;
    });
    if (row != store.memberships.end())
    {
        durable.row = row->membership;
    }
    auto const state = std::ranges::find_if(store.state, [room_id](auto const& entry) {
        return entry.room_id == room_id && entry.event_type == "m.room.member" && entry.state_key == bob_user_id;
    });
    REQUIRE(state != store.state.end());
    durable.current_member_event_id = state->event_id;
    auto const event = std::ranges::find_if(store.events, [&state](auto const& candidate) {
        return candidate.event_id == state->event_id;
    });
    REQUIRE(event != store.events.end());
    durable.current_member_event_json = event->json;
    durable.ban_event_stored = std::ranges::any_of(store.events, [room_id](auto const& candidate) {
        return candidate.room_id == room_id && candidate.json.find(R"("membership":"ban")") != std::string::npos;
    });
    return durable;
}

[[nodiscard]] auto postgresql_uri_from_environment() -> std::string
{
    auto const* value = std::getenv("MEROVINGIAN_TEST_POSTGRESQL_URI");
    return value == nullptr ? std::string{} : std::string{value};
}

struct PgConnectionCloser final
{
    auto operator()(PGconn* connection) const noexcept -> void
    {
        if (connection != nullptr)
        {
            PQfinish(connection);
        }
    }
};

struct PgResultCloser final
{
    auto operator()(PGresult* result) const noexcept -> void
    {
        if (result != nullptr)
        {
            PQclear(result);
        }
    }
};

// A trigger on the shared test database that refuses every membership write
// for one room, dropped again when this goes out of scope.
class PostgresqlMembershipFault final
{
public:
    PostgresqlMembershipFault(std::string const& uri, std::string const& room_id, std::string const& suffix)
        : connection_{PQconnectdb(uri.c_str())}
        , name_{"db4_reject_membership_" + suffix}
    {
        REQUIRE(connection_ != nullptr);
        REQUIRE(PQstatus(connection_.get()) == CONNECTION_OK);
        REQUIRE(execute("CREATE FUNCTION " + name_ +
                        "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
                        "'injected membership write failure'; END $$"));
        REQUIRE(execute("CREATE TRIGGER " + name_ +
                        " BEFORE INSERT OR UPDATE ON membership FOR EACH ROW WHEN (NEW.room_id = '" + room_id +
                        "') EXECUTE FUNCTION " + name_ + "()"));
    }

    PostgresqlMembershipFault(PostgresqlMembershipFault const&) = delete;
    auto operator=(PostgresqlMembershipFault const&) -> PostgresqlMembershipFault& = delete;
    PostgresqlMembershipFault(PostgresqlMembershipFault&&) = delete;
    auto operator=(PostgresqlMembershipFault&&) -> PostgresqlMembershipFault& = delete;

    ~PostgresqlMembershipFault()
    {
        std::ignore = execute("DROP TRIGGER IF EXISTS " + name_ + " ON membership");
        std::ignore = execute("DROP FUNCTION IF EXISTS " + name_ + "()");
    }

private:
    [[nodiscard]] auto execute(std::string const& sql) const -> bool
    {
        auto const result = std::unique_ptr<PGresult, PgResultCloser>{PQexec(connection_.get(), sql.c_str())};
        return result != nullptr && PQresultStatus(result.get()) == PGRES_COMMAND_OK;
    }

    std::unique_ptr<PGconn, PgConnectionCloser> connection_{};
    std::string name_{};
};

[[nodiscard]] auto unique_postgresql_suffix() -> std::string
{
    static auto counter = std::uint64_t{0U};
    auto const now = std::chrono::system_clock::now().time_since_epoch().count();
    return std::to_string(now) + "_" + std::to_string(counter++);
}

[[nodiscard]] auto pg_member_event(std::string const& event_id, std::string const& room_id, std::string_view user_id,
                                   std::string_view membership, std::uint64_t stream_ordering)
    -> merovingian::database::PersistentEvent
{
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = event_id;
    event.room_id = room_id;
    event.sender_user_id = "@alice:example.org";
    event.json = R"({"content":{"membership":")" + std::string{membership} + R"("},"event_id":")" + event_id +
                 R"(","room_id":")" + room_id + R"(","sender":"@alice:example.org","state_key":")" +
                 std::string{user_id} + R"(","type":"m.room.member"})";
    event.depth = stream_ordering;
    event.stream_ordering = stream_ordering;
    return event;
}

struct PgDurableMembership final
{
    std::optional<std::string> row{};
    std::string current_member_event_id{};
    bool ban_event_stored{false};
};

[[nodiscard]] auto pg_durable_membership_of_bob(std::string const& uri, std::string const& room_id,
                                                std::string const& ban_event_id) -> PgDurableMembership
{
    auto opened = merovingian::database::open_postgresql_persistent_store(uri);
    REQUIRE(opened.ok);
    auto durable = PgDurableMembership{};
    auto const row = std::ranges::find_if(opened.store.memberships, [&room_id](auto const& membership) {
        return membership.room_id == room_id && membership.user_id == bob_user_id;
    });
    if (row != opened.store.memberships.end())
    {
        durable.row = row->membership;
    }
    auto const state = std::ranges::find_if(opened.store.state, [&room_id](auto const& entry) {
        return entry.room_id == room_id && entry.event_type == "m.room.member" && entry.state_key == bob_user_id;
    });
    if (state != opened.store.state.end())
    {
        durable.current_member_event_id = state->event_id;
    }
    durable.ban_event_stored = std::ranges::any_of(opened.store.events, [&ban_event_id](auto const& event) {
        return event.event_id == ban_event_id;
    });
    return durable;
}

} // namespace

SCENARIO("DB-4 a ban whose membership row was left saying join does not return read access after a restart",
         "[db4][integration][database][homeserver]")
{
    GIVEN("a real SQLite store where alice banned bob but bob's membership row still says join")
    {
        auto const fixture = MembershipSqliteFixture{};
        auto const config = sqlite_config(fixture.database_path());
        auto room = JoinedRoom{};
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            room = alice_and_bob_in_a_room(started.runtime);
            REQUIRE(request(started.runtime, "POST", room_path(room.room_id, "/ban"), room.alice_token,
                            R"({"user_id":"@bob:example.org"})")
                        .status == 200U);
        }
        // The state a crash or write fault between the ban event's transaction
        // and the membership row's left behind before DB-4: the ban is current
        // state, the row still grants membership.
        {
            auto const tamper = SqliteConnection{fixture.database_path()};
            REQUIRE(tamper.execute("UPDATE membership SET membership = 'join' WHERE user_id = '@bob:example.org'"));
        }
        auto const before_restart = durable_membership_of_bob(fixture.database_path(), room.room_id);
        REQUIRE(before_restart.row == std::optional<std::string>{"join"});
        REQUIRE(before_restart.current_member_event_json.find(R"("membership":"ban")") != std::string::npos);

        WHEN("the server restarts and alice sends a message")
        {
            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto& runtime = restarted.runtime;
            send_text(runtime, room.alice_token, room.room_id, "after", "said-after-the-restart");

            THEN("bob is not a member: no roster, no history after the ban, and the row is repaired")
            {
                // Spec: /joined_members "only the joined members" to a joined user.
                auto const bob_roster =
                    request(runtime, "GET", room_path(room.room_id, "/joined_members"), room.bob_token, {});
                CHECK(bob_roster.status == 403U);
                auto const alice_roster =
                    request(runtime, "GET", room_path(room.room_id, "/joined_members"), room.alice_token, {});
                REQUIRE(alice_roster.status == 200U);
                CHECK(alice_roster.body.find(bob_user_id) == std::string::npos);
                // Spec: a banned user may read history up to the ban and nothing after it.
                auto const history =
                    request(runtime, "GET", room_path(room.room_id, "/messages?dir=b&limit=100"), room.bob_token, {});
                CHECK(history.body.find("said-after-the-restart") == std::string::npos);
                CHECK(durable_membership_of_bob(fixture.database_path(), room.room_id).row ==
                      std::optional<std::string>{"ban"});
            }
        }
    }
}

SCENARIO("DB-4 a ban whose membership row cannot be written leaves nothing of the ban behind",
         "[db4][integration][database][homeserver]")
{
    GIVEN("alice and bob in a room on a real SQLite store that refuses every write of bob's membership row")
    {
        auto const fixture = MembershipSqliteFixture{};
        auto const config = sqlite_config(fixture.database_path());
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const room = alice_and_bob_in_a_room(runtime);
        auto const before = durable_membership_of_bob(fixture.database_path(), room.room_id);
        REQUIRE(before.row == std::optional<std::string>{"join"});
        {
            auto const trigger = SqliteConnection{fixture.database_path()};
            REQUIRE(trigger.execute("CREATE TRIGGER db4_reject_bob_update BEFORE UPDATE ON membership "
                                    "WHEN NEW.user_id = '@bob:example.org' "
                                    "BEGIN SELECT RAISE(ABORT, 'injected membership write failure'); END;"));
            REQUIRE(trigger.execute("CREATE TRIGGER db4_reject_bob_insert BEFORE INSERT ON membership "
                                    "WHEN NEW.user_id = '@bob:example.org' "
                                    "BEGIN SELECT RAISE(ABORT, 'injected membership write failure'); END;"));
        }

        WHEN("alice bans bob")
        {
            auto const banned = request(runtime, "POST", room_path(room.room_id, "/ban"), room.alice_token,
                                        R"({"user_id":"@bob:example.org"})");

            THEN("the ban fails and neither its event nor its current state is durable")
            {
                CHECK(banned.status == 500U);
                auto const after = durable_membership_of_bob(fixture.database_path(), room.room_id);
                CHECK_FALSE(after.ban_event_stored);
                CHECK(after.current_member_event_id == before.current_member_event_id);
                CHECK(after.row == std::optional<std::string>{"join"});
            }

            THEN("the running server still agrees with the database and the room still works")
            {
                auto const alice_roster =
                    request(runtime, "GET", room_path(room.room_id, "/joined_members"), room.alice_token, {});
                REQUIRE(alice_roster.status == 200U);
                CHECK(alice_roster.body.find(bob_user_id) != std::string::npos);
                send_text(runtime, room.alice_token, room.room_id, "after-failed-ban", "said-after-the-failed-ban");
                {
                    auto const trigger = SqliteConnection{fixture.database_path()};
                    REQUIRE(trigger.execute("DROP TRIGGER db4_reject_bob_update"));
                    REQUIRE(trigger.execute("DROP TRIGGER db4_reject_bob_insert"));
                }
                CHECK(request(runtime, "POST", room_path(room.room_id, "/ban"), room.alice_token,
                              R"({"user_id":"@bob:example.org"})")
                          .status == 200U);
                auto const durable = durable_membership_of_bob(fixture.database_path(), room.room_id);
                CHECK(durable.row == std::optional<std::string>{"ban"});
                CHECK(durable.current_member_event_json.find(R"("membership":"ban")") != std::string::npos);
            }
        }
    }
}

SCENARIO("DB-4 on PostgreSQL a ban commits with its membership row, and stale rows are reconciled",
         "[db4][integration][database][postgresql]")
{
    GIVEN("a PostgreSQL store where bob has joined a room")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = merovingian::database::open_postgresql_persistent_store(uri);
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto const suffix = unique_postgresql_suffix();
        auto const room_id = "!db4-" + suffix + ":example.org";
        auto const join_id = "$db4-join-" + suffix;
        auto const ban_id = "$db4-ban-" + suffix;
        REQUIRE(merovingian::database::store_room(store, {room_id, "@alice:example.org"}));
        REQUIRE(merovingian::database::store_event_with_state(
            store, pg_member_event(join_id, room_id, bob_user_id, "join", 1U),
            merovingian::database::PersistentStateEvent{room_id, "m.room.member", std::string{bob_user_id}, join_id},
            merovingian::database::MembershipProjection{std::string{bob_user_id}, "join", 2U, std::nullopt}));
        auto const ban_state =
            merovingian::database::PersistentStateEvent{room_id, "m.room.member", std::string{bob_user_id}, ban_id};

        WHEN("the database refuses bob's membership write while a ban is stored with its projection")
        {
            auto const stored = [&] {
                auto const fault = PostgresqlMembershipFault{uri, room_id, suffix};
                return merovingian::database::store_event_with_state(
                    store, pg_member_event(ban_id, room_id, bob_user_id, "ban", 3U), ban_state,
                    merovingian::database::MembershipProjection{std::string{bob_user_id}, "ban", 4U, std::nullopt});
            }();

            THEN("nothing of the ban is durable")
            {
                CHECK_FALSE(stored);
                auto const durable = pg_durable_membership_of_bob(uri, room_id, ban_id);
                CHECK_FALSE(durable.ban_event_stored);
                CHECK(durable.current_member_event_id == join_id);
                CHECK(durable.row == std::optional<std::string>{"join"});
            }
        }

        WHEN("a ban was stored without its row, as a fault between two transactions left it, and the store is "
             "reopened and reconciled")
        {
            REQUIRE(merovingian::database::store_event_with_state(
                store, pg_member_event(ban_id, room_id, bob_user_id, "ban", 3U), ban_state));
            auto reopened = merovingian::database::open_postgresql_persistent_store(uri);
            REQUIRE(reopened.ok);
            auto next = std::uint64_t{1000U};
            auto const corrected =
                merovingian::database::reconcile_memberships_with_current_state(reopened.store, [&next] {
                    return next++;
                });

            THEN("bob's row durably says ban")
            {
                CHECK(corrected >= 1U);
                CHECK(pg_durable_membership_of_bob(uri, room_id, ban_id).row == std::optional<std::string>{"ban"});
            }
        }
    }
}
