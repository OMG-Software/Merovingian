// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/database/postgresql_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto postgresql_uri_from_environment() -> std::string_view
{
    auto const* value = std::getenv("MEROVINGIAN_TEST_POSTGRESQL_URI");
    return value == nullptr ? std::string_view{} : std::string_view{value};
}

[[nodiscard]] auto unique_test_suffix() -> std::string
{
    static auto const base = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    static auto counter = std::uint64_t{0U};
    return std::to_string(base) + "-" + std::to_string(counter++);
}

[[nodiscard]] auto find_media(merovingian::database::PersistentStore const& store, std::string_view media_id)
{
    return std::ranges::find_if(store.local_media, [media_id](auto const& media) {
        return media.media_id == media_id;
    });
}

[[nodiscard]] auto find_blob(merovingian::database::PersistentStore const& store, std::string_view storage_id)
{
    return std::ranges::find_if(store.media_blobs, [storage_id](auto const& blob) {
        return blob.storage_id == storage_id;
    });
}

[[nodiscard]] auto admin_action_count(merovingian::database::PersistentStore const& store,
                                      std::string_view media_id) -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(store.admin_actions, [media_id](auto const& action) {
        return action.action == "media.remove" && action.target == media_id;
    }));
}

[[nodiscard]] auto audit_event_count(merovingian::database::PersistentStore const& store,
                                     std::string_view media_id) -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(store.audit_log, [media_id](auto const& event) {
        return event.event_type == "media.removed" && event.target == media_id;
    }));
}

} // namespace

SCENARIO("PostgreSQL media moderation commits shared-blob references and audit records durably",
         "[security_audit_postgresql_media][database][postgresql][integration]")
{
    GIVEN("two store handles and two media records sharing one binary blob")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }

        auto opened_a = merovingian::database::open_postgresql_persistent_store(uri);
        auto opened_b = merovingian::database::open_postgresql_persistent_store(uri);
        REQUIRE(opened_a.ok);
        REQUIRE(opened_b.ok);

        auto const suffix = unique_test_suffix();
        auto const admin_id = "@db5-admin-" + suffix + ":example.org";
        auto const first_media_id = "db5-first-" + suffix;
        auto const final_media_id = "db5-final-" + suffix;
        auto const digest = "db5digest" + suffix;
        auto const storage_id = "db5blob_" + suffix;
        auto const bytes = std::string{"payload\0bytes", 13U};

        WHEN("handle B commits removal of the first reference, then the final reference")
        {
            REQUIRE(merovingian::database::store_local_media(
                opened_b.store,
                {first_media_id, admin_id, "text/plain", bytes.size(), "blake2b", digest, false, false, false}));
            REQUIRE(merovingian::database::store_local_media(
                opened_b.store,
                {final_media_id, admin_id, "text/plain", bytes.size(), "blake2b", digest, false, false, false}));
            REQUIRE(merovingian::database::store_media_blob(opened_b.store,
                                                            {storage_id, "blake2b", digest, bytes.size(), bytes, 2U}));

            auto const first_action =
                merovingian::database::PersistentAdminAction{admin_id, "media.remove", first_media_id};
            auto const first_audit = merovingian::database::PersistentAuditEvent{
                "moderation", "media.removed", admin_id, first_media_id, "first reference removed"};
            REQUIRE(merovingian::database::commit_local_media_moderation(opened_b.store, first_media_id, false, true,
                                                                         first_action, first_audit));

            THEN("the first commit retains bytes with one reference and atomically stores metadata and both audits")
            {
                auto const first_record = find_media(opened_b.store, first_media_id);
                REQUIRE(first_record != opened_b.store.local_media.end());
                CHECK(first_record->removed);
                auto const first_blob = find_blob(opened_b.store, storage_id);
                REQUIRE(first_blob != opened_b.store.media_blobs.end());
                CHECK(first_blob->ref_count == 1U);
                CHECK(first_blob->bytes == bytes);
                CHECK(admin_action_count(opened_b.store, first_media_id) == 1U);
                CHECK(audit_event_count(opened_b.store, first_media_id) == 1U);

                opened_a = {};
                opened_b = {};
                auto after_first_restart = merovingian::database::open_postgresql_persistent_store(uri);
                REQUIRE(after_first_restart.ok);

                auto const persisted_first = find_media(after_first_restart.store, first_media_id);
                auto const persisted_final = find_media(after_first_restart.store, final_media_id);
                REQUIRE(persisted_first != after_first_restart.store.local_media.end());
                REQUIRE(persisted_final != after_first_restart.store.local_media.end());
                CHECK(persisted_first->removed);
                CHECK_FALSE(persisted_final->removed);
                auto const persisted_blob = find_blob(after_first_restart.store, storage_id);
                REQUIRE(persisted_blob != after_first_restart.store.media_blobs.end());
                CHECK(persisted_blob->ref_count == 1U);
                CHECK(persisted_blob->bytes == bytes);
                CHECK(admin_action_count(after_first_restart.store, first_media_id) == 1U);
                CHECK(audit_event_count(after_first_restart.store, first_media_id) == 1U);

                auto const final_action =
                    merovingian::database::PersistentAdminAction{admin_id, "media.remove", final_media_id};
                auto const final_audit = merovingian::database::PersistentAuditEvent{
                    "moderation", "media.removed", admin_id, final_media_id, "final reference removed"};
                REQUIRE(merovingian::database::commit_local_media_moderation(after_first_restart.store, final_media_id,
                                                                             false, true, final_action, final_audit));

                after_first_restart = {};
                auto after_final_restart = merovingian::database::open_postgresql_persistent_store(uri);

                THEN("the final commit clears the bytes and persists the second removal and its audit records")
                {
                    REQUIRE(after_final_restart.ok);
                    auto const final_record = find_media(after_final_restart.store, final_media_id);
                    REQUIRE(final_record != after_final_restart.store.local_media.end());
                    CHECK(final_record->removed);
                    auto const final_blob = find_blob(after_final_restart.store, storage_id);
                    REQUIRE(final_blob != after_final_restart.store.media_blobs.end());
                    CHECK(final_blob->ref_count == 0U);
                    CHECK(final_blob->bytes.empty());
                    CHECK(admin_action_count(after_final_restart.store, first_media_id) == 1U);
                    CHECK(admin_action_count(after_final_restart.store, final_media_id) == 1U);
                    CHECK(audit_event_count(after_final_restart.store, first_media_id) == 1U);
                    CHECK(audit_event_count(after_final_restart.store, final_media_id) == 1U);
                }
            }
        }
    }
}
