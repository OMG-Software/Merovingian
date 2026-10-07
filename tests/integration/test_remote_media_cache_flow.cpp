// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0119 / OUT-4: remote media is persisted like local media, so the cache
// that maps a remote (origin, media_id) to its stored copy must be durable as
// well, and every stored copy must stay reachable from it. Otherwise each
// restart, TTL expiry or eviction strands a stored record, and records pile up
// until max_records refuses every upload.

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/media/repository.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace
{

[[nodiscard]] auto sample_png() -> std::string
{
    constexpr std::array<unsigned char, 81U> bytes{
        137, 80,  78,  71,  13,  10, 26, 10,  0,   0,   0,   13,  73, 72,  68,  82,  0,  0,  0,  8,   0,
        0,   0,   8,   8,   6,   0,  0,  0,   196, 15,  190, 139, 0,  0,   0,   24,  73, 68, 65, 84,  120,
        156, 99,  248, 207, 192, 0,  66, 255, 113, 209, 12,  248, 36, 193, 244, 176, 48, 1,  0,  131, 23,
        127, 129, 6,   228, 109, 45, 0,  0,   0,   0,   73,  69,  78, 68,  174, 66,  96, 130};
    return {reinterpret_cast<char const*>(bytes.data()), bytes.size()};
}

[[nodiscard]] auto media_response(std::string const& payload) -> std::string
{
    auto const multipart = std::string{"--audit-boundary\r\nContent-Type: application/json\r\n\r\n{}\r\n"
                                       "--audit-boundary\r\nContent-Type: image/png\r\n\r\n"} +
                           payload + "\r\n--audit-boundary--\r\n";
    return std::string{"HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; "
                       "boundary=audit-boundary\r\nConnection: close\r\nContent-Length: "} +
           std::to_string(multipart.size()) + "\r\n\r\n" + multipart;
}

// Connects to `port` and closes at once, so a mock server still waiting in
// accept() for a request that never comes finishes its loop promptly.
auto release_waiting_acceptor(std::uint16_t port) -> void
{
    auto const fd = merovingian::core::SocketHandle{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    if (!fd.valid())
    {
        return;
    }
    auto address = ::sockaddr_in{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    std::ignore = ::connect(fd.native_handle(), reinterpret_cast<::sockaddr const*>(&address), sizeof(address));
}

struct CacheSettings final
{
    std::string fetch_policy{"allow"};
    std::uint32_t ttl_seconds{86400U};
    std::uint64_t max_entries{1024U};
};

[[nodiscard]] auto sqlite_remote_media_config(std::filesystem::path const& path, CacheSettings const& settings)
    -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.media.remote_fetch_enabled = true;
    security.media.remote_fetch_media_policy = settings.fetch_policy;
    security.media.remote_media_cache_ttl_seconds = settings.ttl_seconds;
    security.media.remote_media_cache_max_entries = settings.max_entries;
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto unique_sqlite_path(std::string_view label) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-remote-cache-" + std::string{label} + "-" + std::to_string(now) + ".sqlite3");
}

// A real HTTPS origin standing in for peer.example.org.
struct Origin final
{
    merovingian::tests::tls_mock::TlsTestCertificate certificate{
        merovingian::tests::tls_mock::write_test_tls_certificate()};
    merovingian::homeserver::TlsServerContextResult tls{
        merovingian::homeserver::make_tls_server_context(certificate.certificate_file, certificate.private_key_file)};
    merovingian::net::TcpAcceptor acceptor{};
};

// Points a started server at `origin` and returns a logged-in user's token.
// Registers the user only on the first start. The runtime is prepared in
// place: its wired callbacks capture its address, so it must never be moved.
[[nodiscard]] auto prepare(merovingian::homeserver::ClientServerRuntime& runtime, Origin& origin, bool first_start)
    -> std::string
{
    runtime.homeserver.media_repository.config.private_address_fetches_blocked = false;
    runtime.rate_limit_engine.reset();
    auto user_id = std::string{"@cache_user:example.org"};
    if (first_start)
    {
        auto const user = merovingian::homeserver::register_local_user(
            runtime.homeserver, "cache_user", "CorrectHorse7!", merovingian::tests::registration_token);
        REQUIRE(user.ok);
        user_id = user.value;
    }
    auto const login = merovingian::homeserver::login_local_user_by_id(runtime.homeserver, user_id, "CACHE");
    REQUIRE(login.ok);
    runtime.homeserver.test_forced_outbound_resolution["peer.example.org"] = {
        "localhost", origin.acceptor.bound_port(), {"127.0.0.1"}, origin.certificate.certificate_pem};
    return login.value;
}

[[nodiscard]] auto download(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                            std::string_view media_id) -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v1/media/download/peer.example.org/" + std::string{media_id}, token, {}});
}

// Waits until the wall clock, against which cache expiry is measured, is past
// `seconds` from now; a fixed sleep can end early when the wall clock steps.
auto wait_past(std::chrono::seconds seconds) -> void
{
    auto const target = std::chrono::system_clock::now() + seconds + std::chrono::milliseconds{200};
    auto const give_up = std::chrono::steady_clock::now() + std::chrono::seconds{15};
    while (std::chrono::system_clock::now() < target && std::chrono::steady_clock::now() < give_up)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
    REQUIRE(std::chrono::system_clock::now() >= target);
}

} // namespace

SCENARIO("The remote media cache survives a restart", "[media-on-demand][out-4][media][remote]")
{
    GIVEN("a SQLite-backed server that has fetched a remote image")
    {
        auto origin = Origin{};
        REQUIRE(origin.tls.ok());
        REQUIRE(origin.acceptor.bind("127.0.0.1", 0U).ok);
        auto const path = unique_sqlite_path("restart");
        auto const config = sqlite_remote_media_config(path, {});
        auto const image = sample_png();
        auto captured = std::vector<std::string>{};
        auto origin_thread = std::thread{[&]() {
            merovingian::tests::tls_mock::run_path_dispatch_tls_server(
                origin.acceptor, *origin.tls.context,
                {
                    {"/media/download/kept", media_response(image)},
                    {"/media/download/kept", media_response(image)}
            },
                &captured);
        }};
        auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{origin_thread};
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            auto const token = prepare(started.runtime, origin, true);
            auto const fetched = download(started.runtime, token, "kept");
            INFO("first download: " << fetched.response.status << " " << fetched.response.body);
            REQUIRE(fetched.response.status == 200U);
        }

        WHEN("the server restarts and the image is requested again within the TTL")
        {
            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto const token = prepare(restarted.runtime, origin, false);
            auto const again = download(restarted.runtime, token, "kept");
            release_waiting_acceptor(origin.acceptor.bound_port());
            origin_thread.join();

            THEN("it is served from storage without contacting the origin")
            {
                REQUIRE(again.response.status == 200U);
                REQUIRE(again.response.body.find("PNG") != std::string::npos);
                REQUIRE(captured.size() == 1U);
            }

            THEN("one stored record holds it")
            {
                REQUIRE(restarted.runtime.homeserver.database.persistent_store.local_media.size() == 1U);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("Re-fetching remote media after its TTL replaces the stored copy instead of adding one",
         "[media-on-demand][out-4][media][remote]")
{
    GIVEN("a server whose remote media cache entries last one second")
    {
        auto origin = Origin{};
        REQUIRE(origin.tls.ok());
        REQUIRE(origin.acceptor.bind("127.0.0.1", 0U).ok);
        auto const path = unique_sqlite_path("ttl");
        auto settings = CacheSettings{};
        settings.ttl_seconds = 1U;
        auto started = merovingian::homeserver::start_client_server(sqlite_remote_media_config(path, settings));
        REQUIRE(started.started);
        auto const token = prepare(started.runtime, origin, true);
        auto& runtime = started.runtime;
        auto const image = sample_png();
        auto captured = std::vector<std::string>{};
        auto origin_thread = std::thread{[&]() {
            merovingian::tests::tls_mock::run_path_dispatch_tls_server(
                origin.acceptor, *origin.tls.context,
                {
                    {"/media/download/ttl", media_response(image)},
                    {"/media/download/ttl", media_response(image)}
            },
                &captured);
        }};
        auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{origin_thread};

        WHEN("the image is fetched, the TTL passes, and it is fetched again")
        {
            auto const first = download(runtime, token, "ttl");
            wait_past(std::chrono::seconds{1});
            auto const second = download(runtime, token, "ttl");
            origin_thread.join();
            auto const& store = runtime.homeserver.database.persistent_store;

            THEN("both downloads succeed and the origin was asked twice")
            {
                REQUIRE(first.response.status == 200U);
                REQUIRE(second.response.status == 200U);
                REQUIRE(captured.size() == 2U);
            }

            THEN("exactly one record, one cache row and one live blob reference remain, in memory and stored")
            {
                REQUIRE(runtime.homeserver.media_repository.records.size() == 1U);
                REQUIRE(store.local_media.size() == 1U);
                REQUIRE(store.remote_media.size() == 1U);
                REQUIRE(store.media_blobs.size() == 1U);
                REQUIRE(store.media_blobs.front().ref_count == 1U);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("Quarantined remote media is not re-fetched while it is cached", "[media-on-demand][out-4][media][remote]")
{
    GIVEN("a server using the default quarantine policy for remote media")
    {
        auto origin = Origin{};
        REQUIRE(origin.tls.ok());
        REQUIRE(origin.acceptor.bind("127.0.0.1", 0U).ok);
        auto const path = unique_sqlite_path("quarantine");
        auto settings = CacheSettings{};
        settings.fetch_policy = "quarantine";
        auto started = merovingian::homeserver::start_client_server(sqlite_remote_media_config(path, settings));
        REQUIRE(started.started);
        auto const token = prepare(started.runtime, origin, true);
        auto& runtime = started.runtime;
        auto const image = sample_png();
        auto captured = std::vector<std::string>{};
        auto origin_thread = std::thread{[&]() {
            merovingian::tests::tls_mock::run_path_dispatch_tls_server(
                origin.acceptor, *origin.tls.context,
                {
                    {"/media/download/held", media_response(image)},
                    {"/media/download/held", media_response(image)}
            },
                &captured);
        }};
        auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{origin_thread};

        WHEN("the same image is requested twice")
        {
            auto const first = download(runtime, token, "held");
            auto const second = download(runtime, token, "held");
            release_waiting_acceptor(origin.acceptor.bound_port());
            origin_thread.join();

            THEN("both are refused as quarantined, and only the first reached the origin")
            {
                REQUIRE(first.response.status == 451U);
                REQUIRE(second.response.status == 451U);
                REQUIRE(captured.size() == 1U);
            }

            THEN("one held record is stored for moderation, not one per request")
            {
                REQUIRE(runtime.homeserver.database.persistent_store.local_media.size() == 1U);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("Evicting a remote media cache entry deletes its stored copy", "[media-on-demand][out-4][media][remote]")
{
    GIVEN("a server whose remote media cache holds one entry")
    {
        auto origin = Origin{};
        REQUIRE(origin.tls.ok());
        REQUIRE(origin.acceptor.bind("127.0.0.1", 0U).ok);
        auto const path = unique_sqlite_path("evict");
        auto settings = CacheSettings{};
        settings.max_entries = 1U;
        auto started = merovingian::homeserver::start_client_server(sqlite_remote_media_config(path, settings));
        REQUIRE(started.started);
        auto const token = prepare(started.runtime, origin, true);
        auto& runtime = started.runtime;
        auto const image = sample_png();
        auto other = image;
        other.back() = static_cast<char>(other.back() ^ 0x01);
        auto captured = std::vector<std::string>{};
        auto origin_thread = std::thread{[&]() {
            merovingian::tests::tls_mock::run_path_dispatch_tls_server(
                origin.acceptor, *origin.tls.context,
                {
                    {"/media/download/first",  media_response(image)},
                    {"/media/download/second", media_response(other)}
            },
                &captured);
        }};
        auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{origin_thread};

        WHEN("two different remote images are fetched")
        {
            auto const first = download(runtime, token, "first");
            auto const second = download(runtime, token, "second");
            origin_thread.join();
            auto const& store = runtime.homeserver.database.persistent_store;

            THEN("only the second remains, in memory and stored")
            {
                REQUIRE(first.response.status == 200U);
                REQUIRE(second.response.status == 200U);
                REQUIRE(runtime.homeserver.media_repository.records.size() == 1U);
                REQUIRE(store.local_media.size() == 1U);
                REQUIRE(store.remote_media.size() == 1U);
                REQUIRE(store.remote_media.front().media_id == "second");
            }

            THEN("the evicted image's bytes are released")
            {
                auto live_blobs = std::size_t{0U};
                for (auto const& blob : store.media_blobs)
                {
                    live_blobs += blob.ref_count > 0U ? 1U : 0U;
                }
                REQUIRE(live_blobs == 1U);
            }
        }

        std::filesystem::remove(path);
    }
}
