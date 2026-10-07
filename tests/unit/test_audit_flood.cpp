// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// AUTH-1 (security-audit-report-2026-09-29.md): an unauthenticated client must
// not be able to grow the audit trail without bound or force one synchronous
// durable audit commit per request. These scenarios drive the real client-server
// dispatcher with hostile traffic and assert on the resulting audit state.

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/bounded_text.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/observability/audit_rate_gate.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <streambuf>
#include <string>
#include <string_view>
#include <vector>

#include <sodium.h>

namespace
{

using AuditClock = merovingian::observability::AuditRateGate::Clock;

[[nodiscard]] auto flood_test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

// Every durable audit row ever appended to the store: the retained window plus
// the rows the in-memory cap has already evicted. The database table holds one
// row (one synchronous commit) per append, so this is the commit count.
[[nodiscard]] auto durable_audit_rows(merovingian::database::PersistentStore const& store) -> std::size_t
{
    return store.audit_log.size() + static_cast<std::size_t>(store.audit_log_evicted);
}

[[nodiscard]] auto count_rows(merovingian::database::PersistentStore const& store, std::string_view event_type)
    -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(store.audit_log, [event_type](auto const& event) {
        return event.event_type == event_type;
    }));
}

// Freezes the audit gate's clock so a slow CI machine cannot straddle a window
// boundary in the middle of a scenario.
struct FrozenAuditClock final
{
    AuditClock::time_point now{AuditClock::time_point{} + std::chrono::hours{1}};
};

[[nodiscard]] auto request_with_bad_token(std::string const& token, std::string const& source)
    -> merovingian::homeserver::LocalHttpRequest
{
    return {"GET", "/_matrix/client/v3/account/whoami", token, {}, {}, source};
}

} // namespace

SCENARIO("Ten thousand requests with an unknown bearer token cannot flood the audit trail",
         "[homeserver][audit][flood][security][auth-1]")
{
    GIVEN("a started runtime with an audit sink")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(flood_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = FrozenAuditClock{};
        runtime.homeserver.database.audit_rate_gate.set_clock([&clock]() {
            return clock.now;
        });
        auto const rows_before = durable_audit_rows(runtime.homeserver.database.persistent_store);

        WHEN("ten thousand requests carry unknown bearer tokens from one source")
        {
            auto rejected = std::size_t{0U};
            for (auto i = 0; i < 10000; ++i)
            {
                auto const result = merovingian::homeserver::handle_client_server_request(
                    runtime, request_with_bad_token("unknown-token-" + std::to_string(i), "203.0.113.50"));
                if (result.response.status == 401U || result.response.status == 429U)
                {
                    ++rejected;
                }
            }

            THEN("every request was refused, the in-memory audit storage stayed inside its cap, and far fewer "
                 "than ten thousand durable audit rows were committed")
            {
                REQUIRE(rejected == 10000U);
                auto const& database = runtime.homeserver.database;
                REQUIRE(database.audit_events.size() <= merovingian::database::max_in_memory_audit_events);
                REQUIRE(database.persistent_store.audit_log.size() <=
                        merovingian::database::max_in_memory_audit_events);
                auto const rows = durable_audit_rows(database.persistent_store) - rows_before;
                REQUIRE(rows < 10000U);
                // Three rate-capped kinds, ten rows each, one window (the clock is frozen).
                REQUIRE(rows <= 30U);
            }

            THEN("each rate-capped kind wrote no more than its per-window allowance")
            {
                auto const& store = runtime.homeserver.database.persistent_store;
                REQUIRE(count_rows(store, "access_token.rejected") <=
                        merovingian::observability::audit_rate_gate_max_rows);
                REQUIRE(count_rows(store, "rate_limit.exceeded") <=
                        merovingian::observability::audit_rate_gate_max_rows);
                REQUIRE(count_rows(store, "request.rejected") <= merovingian::observability::audit_rate_gate_max_rows);
            }
        }
    }
}

SCENARIO("The first rejection row after the window carries the number of rows the window suppressed",
         "[homeserver][audit][flood][security][auth-1]")
{
    GIVEN("a runtime whose unknown-token rejections overran their per-window allowance")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(flood_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = FrozenAuditClock{};
        runtime.homeserver.database.audit_rate_gate.set_clock([&clock]() {
            return clock.now;
        });
        auto const& store = runtime.homeserver.database.persistent_store;

        // Each request comes from its own source address so the per-IP rate
        // limiter never answers 429 and every request reaches the token check.
        auto send = [&runtime](int index) {
            return merovingian::homeserver::handle_client_server_request(
                runtime, request_with_bad_token("unknown-token-" + std::to_string(index),
                                                "198.51.100." + std::to_string((index % 200) + 1)));
        };
        for (auto i = 0; i < 40; ++i)
        {
            REQUIRE(send(i).response.status == 401U);
        }
        auto const window_rows = count_rows(store, "access_token.rejected");
        REQUIRE(window_rows == merovingian::observability::audit_rate_gate_max_rows);

        WHEN("the window elapses and another unknown token arrives")
        {
            clock.now += merovingian::observability::audit_rate_gate_window;
            REQUIRE(send(1000).response.status == 401U);

            THEN("new rows are written, and the first of them reports a suppressed count of at least the overrun")
            {
                // One request can reach the token check more than once (rate-limit
                // key, then the handler), so more than one new row may be written.
                REQUIRE(count_rows(store, "access_token.rejected") > window_rows);
                auto const first_new = std::ranges::find_if(store.audit_log, [](auto const& event) {
                    return event.event_type == "access_token.rejected" &&
                           event.reason.find("suppressed=") != std::string::npos;
                });
                REQUIRE(first_new != store.audit_log.end());
                auto const marker = std::string_view{"suppressed="};
                auto const at = first_new->reason.find(marker);
                auto const count = std::stoul(first_new->reason.substr(at + marker.size()));
                REQUIRE(count >= 30U);
                // The count is reported exactly once.
                REQUIRE(std::ranges::count_if(store.audit_log, [](auto const& event) {
                            return event.reason.find("suppressed=") != std::string::npos;
                        }) == 1);
            }
        }
    }
}

SCENARIO("A login carrying 60 KiB identifiers records audit fields of at most 255 bytes",
         "[homeserver][audit][flood][security][auth-1]")
{
    GIVEN("a started runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(flood_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a password login names a 30 KiB user and a 30 KiB device id")
        {
            auto const huge = std::string(30U * 1024U, 'u');
            auto const body = R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")" + huge +
                              R"("},"password":"irrelevant","device_id":")" + huge + R"("})";
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, body, {}, "203.0.113.77"});

            THEN("the login is refused and no stored audit field exceeds 255 bytes")
            {
                REQUIRE(result.response.status == 403U);
                auto const& database = runtime.homeserver.database;
                auto const rejected = std::ranges::find_if(database.persistent_store.audit_log, [](auto const& event) {
                    return event.event_type == "login.rejected";
                });
                REQUIRE(rejected != database.persistent_store.audit_log.end());
                for (auto const& event : database.persistent_store.audit_log)
                {
                    REQUIRE(event.actor.size() <= merovingian::database::max_audit_field_bytes);
                    REQUIRE(event.target.size() <= merovingian::database::max_audit_field_bytes);
                    REQUIRE(event.reason.size() <= merovingian::database::max_audit_field_bytes);
                }
                for (auto const& event : database.audit_events)
                {
                    REQUIRE(event.actor.size() <= merovingian::database::max_audit_field_bytes);
                    REQUIRE(event.target.size() <= merovingian::database::max_audit_field_bytes);
                    REQUIRE(event.reason_code.size() <= merovingian::database::max_audit_field_bytes);
                }
            }
        }

        WHEN("a login names a 60 KiB user and omits the device id")
        {
            auto const huge = std::string(60U * 1024U, 'v');
            auto const body = R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")" + huge +
                              R"("},"password":"irrelevant"})";
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, body, {}, "203.0.113.78"});

            THEN("the recorded actor is at most 255 bytes")
            {
                REQUIRE(result.response.status == 403U);
                auto const& log = runtime.homeserver.database.persistent_store.audit_log;
                auto const rejected = std::ranges::find_if(log, [](auto const& event) {
                    return event.event_type == "login.rejected";
                });
                REQUIRE(rejected != log.end());
                REQUIRE(rejected->actor.size() <= 255U);
                REQUIRE_FALSE(rejected->actor.empty());
            }
        }
    }
}

SCENARIO("Audit events that are not per-request rejections are neither sampled nor lost",
         "[homeserver][audit][flood][auth-1]")
{
    GIVEN("a started runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(flood_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& database = runtime.homeserver.database;
        auto const rows_before = durable_audit_rows(database.persistent_store);

        WHEN("more login-success audit events than the in-memory cap are appended")
        {
            auto const total = merovingian::database::max_in_memory_audit_events + 300U;
            for (auto i = std::size_t{0U}; i < total; ++i)
            {
                merovingian::homeserver::append_local_audit(database, merovingian::observability::AuditCategory::auth,
                                                            "auth.login", "@alice:example.org", std::to_string(i),
                                                            "ok");
            }

            THEN("every event reached the durable store while both in-memory windows stayed at the cap")
            {
                REQUIRE(durable_audit_rows(database.persistent_store) - rows_before == total);
                REQUIRE(database.audit_events.size() == merovingian::database::max_in_memory_audit_events);
                REQUIRE(database.persistent_store.audit_log.size() ==
                        merovingian::database::max_in_memory_audit_events);
                REQUIRE(database.audit_events.back().target == std::to_string(total - 1U));
                REQUIRE(database.persistent_store.audit_log.back().target == std::to_string(total - 1U));
            }
        }
    }
}

namespace
{

// Redirects std::cout into a string for the lifetime of the object. Warnings
// are written to the console by the process-wide logger at its default level.
class ConsoleCapture final
{
public:
    ConsoleCapture()
        : m_previous{std::cout.rdbuf(m_buffer.rdbuf())}
    {
    }

    ~ConsoleCapture()
    {
        std::cout.rdbuf(m_previous);
    }

    ConsoleCapture(ConsoleCapture const&) = delete;
    auto operator=(ConsoleCapture const&) -> ConsoleCapture& = delete;
    ConsoleCapture(ConsoleCapture&&) = delete;
    auto operator=(ConsoleCapture&&) -> ConsoleCapture& = delete;

    [[nodiscard]] auto text() const -> std::string
    {
        return m_buffer.str();
    }

private:
    std::ostringstream m_buffer{};
    std::streambuf* m_previous{nullptr};
};

// Lowers the process-wide logger to debug for its lifetime and puts it back to
// its documented default (info) afterwards.
class VerboseProcessLogger final
{
public:
    VerboseProcessLogger()
    {
        auto& logger = merovingian::observability::SingleLog::instance();
        logger.set_console_log_level(merovingian::observability::LogLevel::debug);
        logger.set_default_log_level(merovingian::observability::LogLevel::debug);
    }

    ~VerboseProcessLogger()
    {
        auto& logger = merovingian::observability::SingleLog::instance();
        logger.set_console_log_level(merovingian::observability::LogLevel::info);
        logger.set_default_log_level(merovingian::observability::LogLevel::info);
    }

    VerboseProcessLogger(VerboseProcessLogger const&) = delete;
    auto operator=(VerboseProcessLogger const&) -> VerboseProcessLogger& = delete;
    VerboseProcessLogger(VerboseProcessLogger&&) = delete;
    auto operator=(VerboseProcessLogger&&) -> VerboseProcessLogger& = delete;
};

[[nodiscard]] auto split_lines(std::string const& text) -> std::vector<std::string>
{
    auto lines = std::vector<std::string>{};
    auto start = std::size_t{0U};
    while (start < text.size())
    {
        auto const end = text.find('\n', start);
        lines.push_back(text.substr(start, end == std::string::npos ? std::string::npos : end - start));
        if (end == std::string::npos)
        {
            break;
        }
        start = end + 1U;
    }
    return lines;
}

} // namespace

// AUTH-9 (security-audit-report-2026-09-29.md): the whole path, from a hostile
// login body to the console, must produce bounded single-line records.
SCENARIO("A login with a huge identifier containing line feeds logs bounded "
         "single-line records",
         "[homeserver][observability][logger][auth-9]")
{
    GIVEN("a started runtime and a captured console")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(flood_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        // login.started is logged at debug with the raw, uncapped user_id and
        // device_id (the audit helper's 255-byte cut applies only to the
        // login.rejected path), so the process-wide logger is lowered to debug.
        auto const verbose = VerboseProcessLogger{};
        auto capture = ConsoleCapture{};

        WHEN("a password login names a 30 KiB user and device id that start with a "
             "forged log line")
        {
            // The JSON \n escapes decode to real line feeds in the logged values.
            auto const hostile = std::string{R"(a\nFORGED forged-record)"} + std::string(30U * 1024U, 'u');
            auto const body = R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")" + hostile +
                              R"("},"password":"irrelevant","device_id":")" + hostile + R"("})";
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, body, {}, "203.0.113.79"});
            auto const output = capture.text();
            auto const lines = split_lines(output);

            THEN("the login is refused and every record is one physical line of "
                 "bounded length")
            {
                REQUIRE(result.response.status == 403U);
                REQUIRE_FALSE(lines.empty());
                CHECK(output.find("[truncated ") != std::string::npos);
                for (auto const& line : lines)
                {
                    CHECK(line.size() < 8U * 1024U);
                    CHECK_FALSE(line.starts_with("FORGED"));
                }
                CHECK(output.find("a\\nFORGED forged-record") != std::string::npos);
                CHECK(output.size() < 32U * 1024U);
            }
        }
    }
}
