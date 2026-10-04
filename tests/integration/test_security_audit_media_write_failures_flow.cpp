// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/media/repository.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>

#include <sqlite3.h>

namespace
{

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

    [[nodiscard]] auto execute(std::string_view sql) const -> bool
    {
        auto const statement = std::string{sql};
        return sqlite3_exec(connection_.get(), statement.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
    }

private:
    std::unique_ptr<sqlite3, SqliteCloser> connection_{};
};

class TemporarySqliteDatabase final
{
public:
    TemporarySqliteDatabase()
    {
        auto const ticks = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = merovingian::tests::temporary_directory() /
                ("merovingian-security-audit-media-write-" + std::to_string(ticks) + ".sqlite3");
        remove_files();
    }

    TemporarySqliteDatabase(TemporarySqliteDatabase const&) = delete;
    auto operator=(TemporarySqliteDatabase const&) -> TemporarySqliteDatabase& = delete;
    TemporarySqliteDatabase(TemporarySqliteDatabase&&) = delete;
    auto operator=(TemporarySqliteDatabase&&) -> TemporarySqliteDatabase& = delete;

    ~TemporarySqliteDatabase()
    {
        remove_files();
    }

    [[nodiscard]] auto path() const noexcept -> std::filesystem::path const&
    {
        return path_;
    }

private:
    auto remove_files() const noexcept -> void
    {
        auto error = std::error_code{};
        std::filesystem::remove(path_, error);
        error.clear();
        std::filesystem::remove(path_.string() + "-wal", error);
        error.clear();
        std::filesystem::remove(path_.string() + "-shm", error);
        error.clear();
        std::filesystem::remove(path_.string() + "-journal", error);
    }

    std::filesystem::path path_{};
};

enum class FailurePoint
{
    quarantine_row,
    release_row,
    remove_row,
    remove_blob,
    quarantine_admin_action,
    remove_audit_log,
};

struct MediaSnapshot final
{
    merovingian::media::LocalMediaState runtime_state{merovingian::media::LocalMediaState::removed};
    bool persistent_quarantined{false};
    bool persistent_removed{false};
    std::string runtime_blob_bytes{};
    std::string persistent_blob_bytes{};
    std::uint64_t runtime_blob_ref_count{0U};
    std::uint64_t persistent_blob_ref_count{0U};
    std::size_t admin_action_count{0U};
    std::size_t audit_event_count{0U};
};

struct FailureObservation final
{
    std::uint16_t operation_status{0U};
    MediaSnapshot immediate{};
    MediaSnapshot after_restart{};
    std::uint16_t download_status{0U};
    std::string download_body{};
};

[[nodiscard]] auto sqlite_media_config(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();

    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.media.max_upload_size = "8B";
    security.media.quarantine_unknown_mime = false;

    return {merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            std::move(database),
            std::move(security),
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{}};
}

[[nodiscard]] auto register_and_login_admin(merovingian::homeserver::HomeserverRuntime& runtime) -> std::string
{
    auto const registration = merovingian::homeserver::bootstrap_admin_user(runtime, "media_admin", "CorrectHorse7!");
    REQUIRE(registration.ok);
    auto const login = merovingian::homeserver::handle_local_http_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, "@media_admin:example.org|CorrectHorse7!|MEDIA_ADMIN"});
    REQUIRE(login.status == 200U);
    return login.body;
}

[[nodiscard]] auto media_id_from_upload(std::string_view body) -> std::string
{
    constexpr auto prefix = std::string_view{"mxc://example.org/"};
    REQUIRE(body.starts_with(prefix));
    auto const tail = body.substr(prefix.size());
    auto const delimiter = tail.find('|');
    REQUIRE(delimiter != std::string_view::npos);
    return std::string{tail.substr(0U, delimiter)};
}

[[nodiscard]] auto upload_hello(merovingian::homeserver::HomeserverRuntime& runtime,
                                std::string_view token) -> std::string
{
    auto const upload = merovingian::homeserver::handle_local_http_request(
        runtime, {"POST", "/_matrix/media/v3/upload", std::string{token}, "text/plain|text/plain|clean|hello"});
    REQUIRE(upload.status == 200U);
    return media_id_from_upload(upload.body);
}

[[nodiscard]] auto moderation_names(FailurePoint point) -> std::pair<std::string_view, std::string_view>
{
    switch (point)
    {
    case FailurePoint::quarantine_row:
    case FailurePoint::quarantine_admin_action:
        return {"media.quarantine", "media.quarantined"};
    case FailurePoint::release_row:
        return {"media.release", "media.released"};
    case FailurePoint::remove_row:
    case FailurePoint::remove_blob:
    case FailurePoint::remove_audit_log:
        return {"media.remove", "media.removed"};
    }
    return {};
}

[[nodiscard]] auto media_snapshot(merovingian::homeserver::HomeserverRuntime const& runtime, std::string_view media_id,
                                  FailurePoint point) -> MediaSnapshot
{
    auto const record = std::ranges::find_if(runtime.media_repository.records, [media_id](auto const& candidate) {
        return candidate.media_id == media_id;
    });
    REQUIRE(record != runtime.media_repository.records.end());
    auto const persistent_media =
        std::ranges::find_if(runtime.database.persistent_store.local_media, [media_id](auto const& candidate) {
            return candidate.media_id == media_id;
        });
    REQUIRE(persistent_media != runtime.database.persistent_store.local_media.end());
    auto const runtime_blob = std::ranges::find_if(runtime.media_repository.blobs, [&record](auto const& candidate) {
        return candidate.storage_id == record->storage_id;
    });
    REQUIRE(runtime_blob != runtime.media_repository.blobs.end());
    auto const persistent_blob =
        std::ranges::find_if(runtime.database.persistent_store.media_blobs, [&record](auto const& candidate) {
            return candidate.storage_id == record->storage_id;
        });
    REQUIRE(persistent_blob != runtime.database.persistent_store.media_blobs.end());

    auto const [action_name, event_type] = moderation_names(point);
    auto const& store = runtime.database.persistent_store;
    auto const actions = std::ranges::count_if(store.admin_actions, [action_name, media_id](auto const& action) {
        return action.action == action_name && action.target == media_id;
    });
    auto const audit_events = std::ranges::count_if(store.audit_log, [event_type, media_id](auto const& event) {
        return event.event_type == event_type && event.target == media_id;
    });

    return {record->state,
            persistent_media->quarantined,
            persistent_media->removed,
            runtime_blob->bytes,
            persistent_blob->bytes,
            runtime_blob->ref_count,
            persistent_blob->ref_count,
            static_cast<std::size_t>(actions),
            static_cast<std::size_t>(audit_events)};
}

auto install_failure_trigger(std::filesystem::path const& path, FailurePoint point) -> void
{
    auto trigger = SqliteConnection{path};
    switch (point)
    {
    case FailurePoint::quarantine_row:
        REQUIRE(trigger.execute(
            "CREATE TRIGGER reject_media_quarantine BEFORE UPDATE OF quarantined ON media "
            "WHEN NEW.quarantined = 'true' BEGIN SELECT RAISE(ABORT, 'injected quarantine write failure'); END;"));
        return;
    case FailurePoint::release_row:
        REQUIRE(trigger.execute("CREATE TRIGGER reject_media_release BEFORE UPDATE OF quarantined ON media "
                                "WHEN OLD.quarantined = 'true' AND NEW.quarantined = 'false' "
                                "BEGIN SELECT RAISE(ABORT, 'injected release write failure'); END;"));
        return;
    case FailurePoint::remove_row:
        REQUIRE(trigger.execute(
            "CREATE TRIGGER reject_media_remove BEFORE UPDATE OF removed ON media "
            "WHEN NEW.removed = 'true' BEGIN SELECT RAISE(ABORT, 'injected media removal write failure'); END;"));
        return;
    case FailurePoint::remove_blob:
        REQUIRE(trigger.execute(
            "CREATE TRIGGER reject_media_blob_clear BEFORE UPDATE OF ref_count ON media_blobs "
            "WHEN NEW.ref_count = '0' BEGIN SELECT RAISE(ABORT, 'injected media blob write failure'); END;"));
        return;
    case FailurePoint::quarantine_admin_action:
        REQUIRE(trigger.execute("CREATE TRIGGER reject_media_admin_action BEFORE INSERT ON admin_actions "
                                "WHEN NEW.action = 'media.quarantine' "
                                "BEGIN SELECT RAISE(ABORT, 'injected admin action write failure'); END;"));
        return;
    case FailurePoint::remove_audit_log:
        REQUIRE(trigger.execute("CREATE TRIGGER reject_media_audit_log BEFORE INSERT ON audit_log "
                                "WHEN NEW.event_type = 'media.removed' "
                                "BEGIN SELECT RAISE(ABORT, 'injected audit log write failure'); END;"));
        return;
    }
}

[[nodiscard]] auto run_admin_write_failure(std::filesystem::path const& path, merovingian::config::Config const& config,
                                           FailurePoint point) -> FailureObservation
{
    auto observation = FailureObservation{};
    auto token = std::string{};
    auto media_id = std::string{};
    {
        auto started = merovingian::homeserver::start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        token = register_and_login_admin(runtime);
        media_id = upload_hello(runtime, token);

        if (point == FailurePoint::release_row)
        {
            auto const quarantined = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/quarantine/" + media_id, token, "policy review"});
            REQUIRE(quarantined.status == 200U);
        }

        install_failure_trigger(path, point);
        auto const response = [&] {
            switch (point)
            {
            case FailurePoint::quarantine_row:
            case FailurePoint::quarantine_admin_action:
                return merovingian::homeserver::handle_local_http_request(
                    runtime, {"POST", "/_merovingian/admin/media/quarantine/" + media_id, token, "policy review"});
            case FailurePoint::release_row:
                return merovingian::homeserver::handle_local_http_request(
                    runtime, {"POST", "/_merovingian/admin/media/release/" + media_id, token, {}});
            case FailurePoint::remove_row:
            case FailurePoint::remove_blob:
            case FailurePoint::remove_audit_log:
                return merovingian::homeserver::handle_local_http_request(
                    runtime, {"POST", "/_merovingian/admin/media/remove/" + media_id, token, "retention expired"});
            }
            return merovingian::homeserver::LocalHttpResponse{};
        }();
        observation.operation_status = response.status;
        observation.immediate = media_snapshot(runtime, media_id, point);
    }

    auto restarted = merovingian::homeserver::start_runtime(config);
    REQUIRE(restarted.started);
    observation.after_restart = media_snapshot(restarted.runtime, media_id, point);
    auto const download = merovingian::homeserver::handle_local_http_request(
        restarted.runtime, {"GET", "/_matrix/client/v1/media/download/example.org/" + media_id, token, {}});
    observation.download_status = download.status;
    observation.download_body = download.body;
    return observation;
}

} // namespace

SCENARIO("Failed quarantine persistence leaves media available across restart", "[security_audit_media_writes]")
{
    GIVEN("a SQLite-backed homeserver where media metadata updates abort")
    {
        auto const database = TemporarySqliteDatabase{};
        auto const config = sqlite_media_config(database.path());

        WHEN("an administrator quarantines an uploaded media item")
        {
            auto const result = run_admin_write_failure(database.path(), config, FailurePoint::quarantine_row);

            THEN("the request fails and runtime and persisted state retain the available bytes")
            {
                CHECK(result.operation_status == 500U);
                CHECK(result.immediate.runtime_state == merovingian::media::LocalMediaState::available);
                CHECK_FALSE(result.immediate.persistent_quarantined);
                CHECK_FALSE(result.immediate.persistent_removed);
                CHECK(result.immediate.runtime_blob_bytes == "hello");
                CHECK(result.immediate.persistent_blob_bytes == "hello");
                CHECK(result.immediate.runtime_blob_ref_count == 1U);
                CHECK(result.immediate.persistent_blob_ref_count == 1U);
                CHECK(result.after_restart.runtime_state == merovingian::media::LocalMediaState::available);
                CHECK_FALSE(result.after_restart.persistent_quarantined);
                CHECK_FALSE(result.after_restart.persistent_removed);
                CHECK(result.after_restart.runtime_blob_bytes == "hello");
                CHECK(result.after_restart.persistent_blob_bytes == "hello");
                CHECK(result.download_status == 200U);
                CHECK(result.download_body == "text/plain|hello");
            }
        }
    }
}

SCENARIO("Failed release persistence preserves quarantine across restart", "[security_audit_media_writes]")
{
    GIVEN("a SQLite-backed homeserver where media release updates abort")
    {
        auto const database = TemporarySqliteDatabase{};
        auto const config = sqlite_media_config(database.path());

        WHEN("an administrator releases quarantined media")
        {
            auto const result = run_admin_write_failure(database.path(), config, FailurePoint::release_row);

            THEN("the request fails and runtime and persisted state stay quarantined")
            {
                CHECK(result.operation_status == 500U);
                CHECK(result.immediate.runtime_state == merovingian::media::LocalMediaState::quarantined);
                CHECK(result.immediate.persistent_quarantined);
                CHECK_FALSE(result.immediate.persistent_removed);
                CHECK(result.immediate.runtime_blob_bytes == "hello");
                CHECK(result.immediate.persistent_blob_bytes == "hello");
                CHECK(result.after_restart.runtime_state == merovingian::media::LocalMediaState::quarantined);
                CHECK(result.after_restart.persistent_quarantined);
                CHECK_FALSE(result.after_restart.persistent_removed);
                CHECK(result.after_restart.runtime_blob_bytes == "hello");
                CHECK(result.after_restart.persistent_blob_bytes == "hello");
                CHECK(result.download_status == 451U);
            }
        }
    }
}

SCENARIO("Failed media-row removal persistence does not clear the blob", "[security_audit_media_writes]")
{
    GIVEN("a SQLite-backed homeserver where media removal updates abort")
    {
        auto const database = TemporarySqliteDatabase{};
        auto const config = sqlite_media_config(database.path());

        WHEN("an administrator removes uploaded media")
        {
            auto const result = run_admin_write_failure(database.path(), config, FailurePoint::remove_row);

            THEN("the failed request preserves the live row and bytes before and after restart")
            {
                CHECK(result.operation_status == 500U);
                CHECK(result.immediate.runtime_state == merovingian::media::LocalMediaState::available);
                CHECK_FALSE(result.immediate.persistent_removed);
                CHECK(result.immediate.runtime_blob_bytes == "hello");
                CHECK(result.immediate.persistent_blob_bytes == "hello");
                CHECK(result.immediate.runtime_blob_ref_count == 1U);
                CHECK(result.immediate.persistent_blob_ref_count == 1U);
                CHECK(result.after_restart.runtime_state == merovingian::media::LocalMediaState::available);
                CHECK_FALSE(result.after_restart.persistent_removed);
                CHECK(result.after_restart.runtime_blob_bytes == "hello");
                CHECK(result.after_restart.persistent_blob_bytes == "hello");
                CHECK(result.download_status == 200U);
                CHECK(result.download_body == "text/plain|hello");
            }
        }
    }
}

SCENARIO("Failed media-blob persistence rolls back the removal tombstone", "[security_audit_media_writes]")
{
    GIVEN("a SQLite-backed homeserver where media blob updates abort")
    {
        auto const database = TemporarySqliteDatabase{};
        auto const config = sqlite_media_config(database.path());

        WHEN("an administrator removes uploaded media")
        {
            auto const result = run_admin_write_failure(database.path(), config, FailurePoint::remove_blob);

            THEN("the row remains available with its original bytes after the transaction fails")
            {
                CHECK(result.operation_status == 500U);
                CHECK(result.immediate.runtime_state == merovingian::media::LocalMediaState::available);
                CHECK_FALSE(result.immediate.persistent_removed);
                CHECK(result.immediate.runtime_blob_bytes == "hello");
                CHECK(result.immediate.persistent_blob_bytes == "hello");
                CHECK(result.immediate.runtime_blob_ref_count == 1U);
                CHECK(result.immediate.persistent_blob_ref_count == 1U);
                CHECK(result.after_restart.runtime_state == merovingian::media::LocalMediaState::available);
                CHECK_FALSE(result.after_restart.persistent_removed);
                CHECK(result.after_restart.runtime_blob_bytes == "hello");
                CHECK(result.after_restart.persistent_blob_bytes == "hello");
                CHECK(result.after_restart.runtime_blob_ref_count == 1U);
                CHECK(result.after_restart.persistent_blob_ref_count == 1U);
                CHECK(result.download_status == 200U);
                CHECK(result.download_body == "text/plain|hello");
            }
        }
    }
}

SCENARIO("Failed admin-action audit insertion rolls back quarantine metadata", "[security_audit_media_writes]")
{
    GIVEN("a SQLite-backed homeserver where the required moderation action insert aborts")
    {
        auto const database = TemporarySqliteDatabase{};
        auto const config = sqlite_media_config(database.path());

        WHEN("an administrator quarantines uploaded media")
        {
            auto const result = run_admin_write_failure(database.path(), config, FailurePoint::quarantine_admin_action);

            THEN("neither the metadata flag nor either durable audit record survives the failed transaction")
            {
                CHECK(result.operation_status == 500U);
                CHECK(result.immediate.runtime_state == merovingian::media::LocalMediaState::available);
                CHECK_FALSE(result.immediate.persistent_quarantined);
                CHECK_FALSE(result.immediate.persistent_removed);
                CHECK(result.immediate.runtime_blob_bytes == "hello");
                CHECK(result.immediate.persistent_blob_bytes == "hello");
                CHECK(result.immediate.admin_action_count == 0U);
                CHECK(result.immediate.audit_event_count == 0U);
                CHECK(result.after_restart.runtime_state == merovingian::media::LocalMediaState::available);
                CHECK_FALSE(result.after_restart.persistent_quarantined);
                CHECK(result.after_restart.admin_action_count == 0U);
                CHECK(result.after_restart.audit_event_count == 0U);
                CHECK(result.download_status == 200U);
                CHECK(result.download_body == "text/plain|hello");
            }
        }
    }
}

SCENARIO("Failed final moderation audit insertion rolls back removal and blob clearing",
         "[security_audit_media_writes]")
{
    GIVEN("a SQLite-backed homeserver where the final durable audit-log insert aborts")
    {
        auto const database = TemporarySqliteDatabase{};
        auto const config = sqlite_media_config(database.path());

        WHEN("an administrator removes uploaded media")
        {
            auto const result = run_admin_write_failure(database.path(), config, FailurePoint::remove_audit_log);

            THEN("metadata, blob reference count, admin action, and audit row all remain unchanged")
            {
                CHECK(result.operation_status == 500U);
                CHECK(result.immediate.runtime_state == merovingian::media::LocalMediaState::available);
                CHECK_FALSE(result.immediate.persistent_removed);
                CHECK(result.immediate.runtime_blob_bytes == "hello");
                CHECK(result.immediate.persistent_blob_bytes == "hello");
                CHECK(result.immediate.runtime_blob_ref_count == 1U);
                CHECK(result.immediate.persistent_blob_ref_count == 1U);
                CHECK(result.immediate.admin_action_count == 0U);
                CHECK(result.immediate.audit_event_count == 0U);
                CHECK(result.after_restart.runtime_state == merovingian::media::LocalMediaState::available);
                CHECK_FALSE(result.after_restart.persistent_removed);
                CHECK(result.after_restart.runtime_blob_bytes == "hello");
                CHECK(result.after_restart.persistent_blob_bytes == "hello");
                CHECK(result.after_restart.runtime_blob_ref_count == 1U);
                CHECK(result.after_restart.persistent_blob_ref_count == 1U);
                CHECK(result.after_restart.admin_action_count == 0U);
                CHECK(result.after_restart.audit_event_count == 0U);
                CHECK(result.download_status == 200U);
                CHECK(result.download_body == "text/plain|hello");
            }
        }
    }
}
