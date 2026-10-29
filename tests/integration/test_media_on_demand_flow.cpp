// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0119: media bytes live only in the database and are read per request,
// with the runtime mutex released for the read. These scenarios fail against
// the earlier design, which held every file's bytes in memory.

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

#include <sqlite3.h>

namespace
{

struct SqliteHandleCloser final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        std::ignore = sqlite3_close(connection);
    }
};

[[nodiscard]] auto sqlite_media_config(std::filesystem::path const& sqlite_path) -> merovingian::config::Config
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

[[nodiscard]] auto unique_sqlite_path(std::string_view label) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-media-on-demand-" + std::string{label} + "-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto admin_token(merovingian::homeserver::HomeserverRuntime& runtime) -> std::string
{
    REQUIRE(merovingian::homeserver::bootstrap_admin_user(runtime, "alice", "CorrectHorse7!").ok);
    auto const login = merovingian::homeserver::handle_local_http_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, "@alice:example.org|CorrectHorse7!|DEVICE1"});
    REQUIRE(login.status == 200U);
    return login.body;
}

[[nodiscard]] auto media_id_from_upload(std::string_view body) -> std::string
{
    auto constexpr prefix = std::string_view{"mxc://example.org/"};
    REQUIRE(body.starts_with(prefix));
    auto const rest = body.substr(prefix.size());
    return std::string{rest.substr(0U, rest.find('|'))};
}

// Replaces every stored blob's bytes behind the server's back, so a download
// can only return the new bytes if it reads the database.
auto overwrite_durable_bytes(std::filesystem::path const& path, std::string const& bytes) -> void
{
    sqlite3* raw = nullptr;
    auto const opened = sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
    auto const connection = std::unique_ptr<sqlite3, SqliteHandleCloser>{raw};
    REQUIRE(opened == SQLITE_OK);
    auto const sql = "UPDATE media_blobs SET bytes = CAST('" + bytes + "' AS BLOB)";
    REQUIRE(sqlite3_exec(connection.get(), sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
}

} // namespace

SCENARIO("Media downloads read the stored bytes from the database", "[media-on-demand][media][database]")
{
    GIVEN("a SQLite-backed server holding an uploaded file")
    {
        auto const path = unique_sqlite_path("served");
        auto started = merovingian::homeserver::start_runtime(sqlite_media_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = admin_token(runtime);
        auto const uploaded = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hello"});
        REQUIRE(uploaded.status == 200U);
        auto const media_id = media_id_from_upload(uploaded.body);

        WHEN("the durable bytes change underneath the running server and the file is downloaded")
        {
            overwrite_durable_bytes(path, "world");
            auto const downloaded = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/client/v1/media/download/example.org/" + media_id, token, {}});

            THEN("the bytes come from the database, not from a copy held in memory")
            {
                REQUIRE(downloaded.status == 200U);
                REQUIRE(downloaded.body == "text/plain|world");
            }

            THEN("the store's in-memory blob row carries no bytes")
            {
                REQUIRE(runtime.database.persistent_store.media_blobs.size() == 1U);
                REQUIRE(runtime.database.persistent_store.media_blobs.front().bytes.empty());
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A deduplicated upload updates the reference count without rewriting the bytes",
         "[media-on-demand][media][database]")
{
    GIVEN("a SQLite-backed server recording its committed statements")
    {
        auto const path = unique_sqlite_path("dedup");
        auto started = merovingian::homeserver::start_runtime(sqlite_media_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = admin_token(runtime);
        merovingian::database::enable_statement_capture(runtime.database.persistent_store, 256U);

        WHEN("the same file is uploaded twice")
        {
            for (auto i = 0; i < 2; ++i)
            {
                REQUIRE(merovingian::homeserver::handle_local_http_request(
                            runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hello"})
                            .status == 200U);
            }
            auto upserts = std::size_t{0U};
            auto ref_count_updates = std::size_t{0U};
            for (auto const& statement : runtime.database.persistent_store.captured_statements)
            {
                upserts += statement.name == "upsert_media_blob" ? 1U : 0U;
                ref_count_updates += statement.name == "update_media_blob_ref_count" ? 1U : 0U;
            }

            THEN("the bytes are written once and the second upload only bumps the reference count")
            {
                REQUIRE(upserts == 1U);
                REQUIRE(ref_count_updates == 1U);
            }
        }

        std::filesystem::remove(path);
    }
}

// The federation core calls its media provider without the runtime mutex.
// The provider must take it for the repository lookups, which rebuild their
// indices, or it races with uploads; ThreadSanitizer reports that race here.
SCENARIO("Federation media downloads run safely alongside uploads", "[media-on-demand][media][concurrency]")
{
    GIVEN("a server holding a file, with one thread downloading it over federation while another uploads")
    {
        auto const path = unique_sqlite_path("concurrent");
        auto started = merovingian::homeserver::start_runtime(sqlite_media_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = admin_token(runtime);
        auto const uploaded = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|shared"});
        REQUIRE(uploaded.status == 200U);
        auto const media_id = media_id_from_upload(uploaded.body);

        WHEN("both run at once")
        {
            constexpr auto rounds = 25;
            auto release = std::atomic<bool>{false};
            auto served = std::atomic<int>{0};
            auto downloader = std::thread{[&runtime, &media_id, &release, &served] {
                while (!release.load())
                {
                    std::this_thread::yield();
                }
                for (auto i = 0; i < rounds; ++i)
                {
                    auto const result = merovingian::homeserver::download_local_media_for_federation(runtime, media_id);
                    if (result.ok && result.bytes == "shared")
                    {
                        served.fetch_add(1);
                    }
                }
            }};
            auto upload_statuses = std::vector<std::uint16_t>{};
            release.store(true);
            for (auto i = 0; i < rounds; ++i)
            {
                upload_statuses.push_back(merovingian::homeserver::handle_local_http_request(
                                              runtime, {"POST", "/_matrix/media/v3/upload", token,
                                                        "text/plain|text/plain|clean|upload-" + std::to_string(i)})
                                              .status);
            }
            downloader.join();

            THEN("every federation download returns the file and every upload succeeds")
            {
                REQUIRE(served.load() == rounds);
                for (auto const status : upload_statuses)
                {
                    REQUIRE(status == 200U);
                }
            }
        }

        std::filesystem::remove(path);
    }
}

// MED-7: federation media must consult the same production media policy as
// authenticated client downloads, before repository resolution or byte reads.
#include "../support/json_test_support.hpp"
#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <algorithm>
#include <utility>
#include <variant>

namespace
{

class Med7SqliteDirectory final
{
public:
    explicit Med7SqliteDirectory(std::string_view label)
        : directory_{unique_sqlite_path(label)}
    {
        REQUIRE(std::filesystem::create_directory(directory_));
    }

    ~Med7SqliteDirectory() noexcept
    {
        auto error = std::error_code{};
        std::ignore = std::filesystem::remove_all(directory_, error);
    }

    Med7SqliteDirectory(Med7SqliteDirectory const&) = delete;
    auto operator=(Med7SqliteDirectory const&) -> Med7SqliteDirectory& = delete;
    Med7SqliteDirectory(Med7SqliteDirectory&&) = delete;
    auto operator=(Med7SqliteDirectory&&) -> Med7SqliteDirectory& = delete;

    [[nodiscard]] auto database_path() const -> std::filesystem::path
    {
        return directory_ / "media.sqlite";
    }

private:
    std::filesystem::path directory_{};
};

[[nodiscard]] auto med7_json_string(std::string const& body, std::string_view key) -> std::string
{
    auto const object = merovingian::tests::parse_object(body);
    auto const member = std::ranges::find_if(object, [key](auto const& entry) {
        return entry.key == key;
    });
    REQUIRE(member != object.end());
    REQUIRE(member->value != nullptr);
    REQUIRE(std::holds_alternative<std::string>(member->value->storage()));
    return std::get<std::string>(member->value->storage());
}

[[nodiscard]] auto med7_admin_token(merovingian::homeserver::ClientServerRuntime& runtime) -> std::string
{
    REQUIRE(sodium_init() >= 0);
    auto entropy = std::string(32U, '\0');
    randombytes_buf(entropy.data(), entropy.size());
    auto const password = std::string{"Aa7!"} + merovingian::events::matrix_base64_from_bytes(entropy);
    auto const bootstrap = merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, "med7admin", password);
    REQUIRE(bootstrap.ok);
    auto identifier = merovingian::canonicaljson::Object{};
    identifier.push_back(
        merovingian::canonicaljson::make_member("type", merovingian::canonicaljson::Value{std::string{"m.id.user"}}));
    identifier.push_back(merovingian::canonicaljson::make_member(
        "user", merovingian::canonicaljson::Value{"@med7admin:" + runtime.homeserver.config.server().server_name}));
    auto body = merovingian::canonicaljson::Object{};
    body.push_back(merovingian::canonicaljson::make_member(
        "type", merovingian::canonicaljson::Value{std::string{"m.login.password"}}));
    body.push_back(merovingian::canonicaljson::make_member("identifier",
                                                           merovingian::canonicaljson::Value{std::move(identifier)}));
    body.push_back(merovingian::canonicaljson::make_member("password", merovingian::canonicaljson::Value{password}));
    body.push_back(merovingian::canonicaljson::make_member(
        "device_id", merovingian::canonicaljson::Value{std::string{"MED7DEVICE"}}));
    auto const serialized =
        merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(body)});
    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, serialized.output});
    REQUIRE(login.response.status == 200U);
    auto const token = med7_json_string(login.response.body, "access_token");
    REQUIRE(!token.empty());
    REQUIRE(merovingian::homeserver::authenticated_admin_user(runtime.homeserver, token).has_value());
    return token;
}

[[nodiscard]] auto med7_peer_keypair() -> merovingian::federation::test::SigningKeypair
{
    REQUIRE(sodium_init() >= 0);
    auto entropy = std::string(32U, '\0');
    randombytes_buf(entropy.data(), entropy.size());
    return merovingian::federation::test::keypair_from_seed(entropy);
}

// The cached verification key is live, not a fixed historical timestamp. No
// resolver, authentication flag, policy callback or media provider is replaced.
auto med7_cache_peer(merovingian::homeserver::HomeserverRuntime& runtime,
                     merovingian::federation::test::SigningKeypair const& keypair) -> void
{
    auto peer = merovingian::federation::FederationRemoteRuntime{};
    peer.server_name = "med7-peer.example.test";
    auto const deadline = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                         std::chrono::system_clock::now().time_since_epoch())
                                                         .count()) +
                          3600000U;
    peer.signing_key = {peer.server_name, "ed25519:med7", deadline, keypair.public_key};
    peer.discovery.server_name = peer.server_name;
    peer.discovery.well_known_host = peer.server_name;
    peer.discovery.resolved_host = peer.server_name;
    peer.discovery.resolved_addresses = {"8.8.8.8"};
    peer.discovery.tls_required = true;
    peer.trust.reputation_score = 100U;
    merovingian::federation::upsert_remote(runtime.federation, std::move(peer));
    merovingian::homeserver::wire_federation_callbacks(runtime);
    REQUIRE(static_cast<bool>(runtime.federation.media_download_provider));
}

[[nodiscard]] auto med7_signed_download(merovingian::homeserver::HomeserverRuntime& runtime,
                                        merovingian::federation::test::SigningKeypair const& keypair,
                                        std::string const& media_id) -> merovingian::homeserver::LocalHttpResponse
{
    auto request = merovingian::homeserver::LocalHttpRequest{};
    request.method = "GET";
    request.target = "/_matrix/federation/v1/media/download/" + media_id;
    request.remote_addr = "127.0.0.1";
    auto const origin = std::string{"med7-peer.example.test"};
    auto const signature = merovingian::federation::make_federation_signature(
        origin, runtime.config.server().server_name, request.method, request.target, request.body, keypair.secret_key);
    request.access_token = "X-Matrix origin=\"" + origin + "\",destination=\"" + runtime.config.server().server_name +
                           "\",key=\"ed25519:med7\",sig=\"" + signature + "\"";
    REQUIRE_FALSE(request.sig_verified);
    REQUIRE(request.verified_origin.empty());
    REQUIRE(request.verified_key_id.empty());
    return merovingian::homeserver::handle_federation_http_request(runtime, request);
}

[[nodiscard]] auto med7_content_type(merovingian::homeserver::LocalHttpResponse const& response) -> std::string_view
{
    auto const header = std::ranges::find_if(response.headers, [](auto const& entry) {
        return entry.first == "Content-Type";
    });
    return header == response.headers.end() ? std::string_view{} : std::string_view{header->second};
}

auto med7_require_media(merovingian::homeserver::LocalHttpResponse const& response, std::string_view bytes) -> void
{
    REQUIRE(response.status == 200U);
    auto const content_type = med7_content_type(response);
    REQUIRE(content_type.starts_with("multipart/mixed;"));
    auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, response.body);
    REQUIRE(parsed.ok);
    REQUIRE_FALSE(parsed.is_redirect);
    REQUIRE(parsed.content_type == "text/plain");
    REQUIRE(parsed.bytes == bytes);
}

auto med7_check_provider_denied(merovingian::media::LocalMediaDownloadResult const& result) -> void
{
    CHECK_FALSE(result.ok);
    CHECK(result.status == 403U);
    CHECK(result.bytes.empty());
    CHECK(result.content_type.empty());
}

} // namespace

SCENARIO("A durable media deny rule also blocks genuinely signed federation downloads",
         "[med-7][media-on-demand][media][database][federation]")
{
    GIVEN("a SQLite-backed server with an authenticated admin and two distinct nonquarantined uploads")
    {
        auto const directory = Med7SqliteDirectory{"med7-rule"};
        auto const path = directory.database_path();
        {
            auto started = merovingian::homeserver::start_client_server(sqlite_media_config(path));
            REQUIRE(started.started);
            auto& client = started.runtime;
            auto& runtime = client.homeserver;
            auto const token = med7_admin_token(client);
            auto const first_bytes = std::string{"med7-first-clean-payload"};
            auto const second_bytes = std::string{"med7-independent-clean-payload"};
            auto const first_upload = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|" + first_bytes});
            auto const second_upload = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|" + second_bytes});
            REQUIRE(first_upload.status == 200U);
            REQUIRE(second_upload.status == 200U);
            auto const first_id = media_id_from_upload(first_upload.body);
            auto const second_id = media_id_from_upload(second_upload.body);
            REQUIRE(first_id != second_id);
            auto const keypair = med7_peer_keypair();
            // Cached peers are sufficient for real signature verification; making
            // transport unavailable also prevents any accidental outbound I/O.
            runtime.outbound_client.reset();
            med7_cache_peer(runtime, keypair);
            med7_require_media(med7_signed_download(runtime, keypair, first_id), first_bytes);
            med7_require_media(med7_signed_download(runtime, keypair, second_id), second_bytes);
            auto const rule_path = "/_matrix/client/v3/admin/safety/policy_rules/media/" + first_id;

            WHEN("the admin PUTs a deny rule for the first bare media ID")
            {
                auto const put = merovingian::homeserver::handle_client_server_request(
                    client, {"PUT", rule_path, token, R"({"action":"deny","reason":"med7_admin_block"})"});

                THEN("both production media paths refuse it, the other upload stays healthy, and DELETE restores it")
                {
                    REQUIRE(put.response.status == 200U);
                    // Reopening the actual SQLite store proves the rule was
                    // committed, rather than merely inserted into runtime state.
                    {
                        auto const reopened = merovingian::database::open_sqlite_persistent_store(path.string());
                        REQUIRE(reopened.ok);
                        auto const rule = std::ranges::find_if(reopened.store.policy_rules, [&](auto const& entry) {
                            return entry.rule_id == "media:" + first_id;
                        });
                        REQUIRE(rule != reopened.store.policy_rules.end());
                        REQUIRE(rule->scope == "media");
                        REQUIRE(rule->entity == first_id);
                        REQUIRE(rule->action == "deny");
                        REQUIRE(rule->reason == "med7_admin_block");
                    }
                    auto const blocked_client = merovingian::homeserver::handle_local_http_request(
                        runtime, {"GET", "/_matrix/client/v1/media/download/example.org/" + first_id, token, {}});
                    REQUIRE(blocked_client.status == 403U);
                    med7_check_provider_denied(
                        merovingian::homeserver::download_local_media_for_federation(runtime, first_id));
                    auto const blocked = med7_signed_download(runtime, keypair, first_id);
                    CHECK(blocked.status == 403U);
                    CHECK_FALSE(med7_content_type(blocked).starts_with("multipart/mixed"));
                    CHECK(blocked.body.find(first_bytes) == std::string::npos);
                    auto const error = merovingian::canonicaljson::parse_lossless(blocked.body);
                    CHECK(error.error == merovingian::canonicaljson::ParseError::none);
                    auto const is_object =
                        std::holds_alternative<merovingian::canonicaljson::Object>(error.value.storage());
                    CHECK(is_object);
                    if (error.error == merovingian::canonicaljson::ParseError::none && is_object)
                    {
                        auto const& object = std::get<merovingian::canonicaljson::Object>(error.value.storage());
                        auto const errcode = std::ranges::find_if(object, [](auto const& entry) {
                            return entry.key == "errcode";
                        });
                        CHECK(errcode != object.end());
                        if (errcode != object.end() && errcode->value != nullptr)
                        {
                            auto const is_string = std::holds_alternative<std::string>(errcode->value->storage());
                            CHECK(is_string);
                            if (is_string)
                            {
                                CHECK(std::get<std::string>(errcode->value->storage()) == "M_FORBIDDEN");
                            }
                        }
                    }
                    med7_require_media(med7_signed_download(runtime, keypair, second_id), second_bytes);
                    auto const removed =
                        merovingian::homeserver::handle_client_server_request(client, {"DELETE", rule_path, token, {}});
                    REQUIRE(removed.response.status == 200U);
                    med7_require_media(med7_signed_download(runtime, keypair, first_id), first_bytes);
                }
            }
        }
    }
}

SCENARIO("Federation media honors the real configured policy hook when its transport is unavailable",
         "[med-7][media-on-demand][media][database][federation]")
{
    GIVEN("a SQLite-backed server serving a clean upload to a genuinely authenticated cached peer")
    {
        auto const directory = Med7SqliteDirectory{"med7-unavailable-hook"};
        auto const path = directory.database_path();
        {
            auto started = merovingian::homeserver::start_client_server(sqlite_media_config(path));
            REQUIRE(started.started);
            auto& client = started.runtime;
            auto& runtime = client.homeserver;
            auto const token = med7_admin_token(client);
            auto const bytes = std::string{"med7-unavailable-hook-clean-payload"};
            auto const upload = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|" + bytes});
            REQUIRE(upload.status == 200U);
            auto const media_id = media_id_from_upload(upload.body);
            auto const keypair = med7_peer_keypair();
            runtime.outbound_client.reset();
            REQUIRE_FALSE(static_cast<bool>(runtime.trust_safety_policy_server));
            med7_cache_peer(runtime, keypair);
            med7_require_media(med7_signed_download(runtime, keypair, media_id), bytes);

            WHEN("the operator enables a configured policy server with unavailable transport and fail-closed policy")
            {
                auto& safety = runtime.config.security().trust_safety;
                safety.enabled = true;
                safety.policy_server_url = "https://operator-policy.example.test/med7";
                safety.policy_server_allow_without_result = false;

                THEN("the real hook blocks media without leaking bytes and the explicit fail-open setting restores it")
                {
                    REQUIRE(runtime.outbound_client == nullptr);
                    REQUIRE_FALSE(static_cast<bool>(runtime.trust_safety_policy_server));
                    med7_check_provider_denied(
                        merovingian::homeserver::download_local_media_for_federation(runtime, media_id));
                    auto const blocked = med7_signed_download(runtime, keypair, media_id);
                    CHECK(blocked.status == 403U);
                    CHECK(blocked.body.find(bytes) == std::string::npos);
                    CHECK_FALSE(med7_content_type(blocked).starts_with("multipart/mixed"));
                    // The federation-wide hook also fails closed here; the
                    // direct provider assertions above independently prove the
                    // media surface invokes the genuine production helper.
                    safety.policy_server_allow_without_result = true;
                    auto const permitted =
                        merovingian::homeserver::download_local_media_for_federation(runtime, media_id);
                    REQUIRE(permitted.ok);
                    REQUIRE(permitted.status == 200U);
                    REQUIRE(permitted.content_type == "text/plain");
                    REQUIRE(permitted.bytes == bytes);
                    med7_require_media(med7_signed_download(runtime, keypair, media_id), bytes);
                }
            }
        }
    }
}
