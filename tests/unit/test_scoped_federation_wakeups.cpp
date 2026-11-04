// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/master_key.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/rooms/room_version_policy.hpp"
#include "merovingian/sync/sync_notifier.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace
{

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("merovingian-scoped-federation-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto config_with_sqlite(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "local.example.org";

    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();

    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.federation.enabled = true;

    return {server,   merovingian::config::ListenersConfig{},        database,
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
}

[[nodiscard]] auto make_seed_event_json(std::string_view room_id, std::string_view event_type,
                                        std::string_view state_key, std::string_view sender,
                                        merovingian::canonicaljson::Object content, std::int64_t depth,
                                        std::int64_t origin_server_ts) -> std::string
{
    using namespace merovingian;

    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{std::string{"hash"}}));

    auto event_obj = canonicaljson::Object{};
    event_obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{canonicaljson::Array{}}));
    event_obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    event_obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{depth}));
    event_obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));
    event_obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{origin_server_ts}));
    event_obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{canonicaljson::Array{}}));
    event_obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{std::string{room_id}}));
    event_obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{sender}}));
    event_obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{state_key}}));
    event_obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{event_type}}));

    auto value = canonicaljson::Value{std::move(event_obj)};
    auto const serialized = canonicaljson::serialize_canonical(value);
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

auto seed_room(merovingian::homeserver::HomeserverRuntime& runtime, std::string_view room_id) -> void
{
    using namespace merovingian;

    auto& store = runtime.database.persistent_store;
    auto& local = runtime.database.rooms;

    store.rooms.push_back({std::string{room_id}, "@admin:local.example.org"});
    local.push_back({std::string{room_id},
                     "@admin:local.example.org",
                     std::vector<std::string>{"@alice:remote.example.org"},
                     {},
                     false});
    store.memberships.push_back({std::string{room_id}, "@alice:remote.example.org", "join", 0U});

    auto const create_id = std::string{room_id} + ":create";
    auto const pl_id = std::string{room_id} + ":pl";
    auto const member_id = std::string{room_id} + ":member";

    auto create_content = canonicaljson::Object{};
    create_content.push_back(
        canonicaljson::make_member("creator", canonicaljson::Value{std::string{"@admin:local.example.org"}}));
    create_content.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{"12"}}));
    auto const create_json =
        make_seed_event_json(room_id, "m.room.create", "", "@admin:local.example.org", std::move(create_content), 0, 1);
    store.events.push_back(
        {create_id, std::string{room_id}, "@admin:local.example.org", create_json, 0U, 0U, {}, {}, {}});
    store.state.push_back({std::string{room_id}, "m.room.create", "", create_id});

    auto pl_content = canonicaljson::Object{};
    pl_content.push_back(canonicaljson::make_member("ban", canonicaljson::Value{static_cast<std::int64_t>(50)}));
    pl_content.push_back(
        canonicaljson::make_member("events_default", canonicaljson::Value{static_cast<std::int64_t>(0)}));
    pl_content.push_back(canonicaljson::make_member("invite", canonicaljson::Value{static_cast<std::int64_t>(50)}));
    pl_content.push_back(canonicaljson::make_member("kick", canonicaljson::Value{static_cast<std::int64_t>(50)}));
    pl_content.push_back(canonicaljson::make_member("redact", canonicaljson::Value{static_cast<std::int64_t>(50)}));
    pl_content.push_back(
        canonicaljson::make_member("state_default", canonicaljson::Value{static_cast<std::int64_t>(0)}));
    pl_content.push_back(
        canonicaljson::make_member("users_default", canonicaljson::Value{static_cast<std::int64_t>(0)}));
    auto pl_users = canonicaljson::Object{};
    pl_users.push_back(
        canonicaljson::make_member("@admin:local.example.org", canonicaljson::Value{static_cast<std::int64_t>(100)}));
    pl_content.push_back(canonicaljson::make_member("users", canonicaljson::Value{std::move(pl_users)}));
    auto const pl_json = make_seed_event_json(room_id, "m.room.power_levels", "", "@admin:local.example.org",
                                              std::move(pl_content), 1, 2);
    store.events.push_back({pl_id, std::string{room_id}, "@admin:local.example.org", pl_json, 0U, 0U, {}, {}, {}});
    store.state.push_back({std::string{room_id}, "m.room.power_levels", "", pl_id});

    auto member_content = canonicaljson::Object{};
    member_content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    auto const member_json = make_seed_event_json(room_id, "m.room.member", "@alice:remote.example.org",
                                                  "@alice:remote.example.org", std::move(member_content), 2, 3);
    store.events.push_back(
        {member_id, std::string{room_id}, "@alice:remote.example.org", member_json, 0U, 0U, {}, {}, {}});
    store.state.push_back({std::string{room_id}, "m.room.member", "@alice:remote.example.org", member_id});

    // ADR-0064 phase B2: ingest_pdu_event now also authorises against the
    // state immediately before the PDU (spec step 5, via
    // homeserver::compute_state_before), which needs a real state group —
    // not just the naive store.state rows above — matching
    // seed_room_with_genesis_state_group in
    // tests/unit/test_pdu_ingestion_state_groups.cpp.
    auto const* policy = rooms::find_room_version_policy("12");
    REQUIRE(policy != nullptr);
    auto const genesis_state = std::vector<database::PersistentStateGroupStateEntry>{
        {"", "m.room.create",       "",                          create_id},
        {"", "m.room.power_levels", "",                          pl_id    },
        {"", "m.room.member",       "@alice:remote.example.org", member_id},
    };
    auto const group_id = database::create_or_reuse_state_group(store, room_id, std::string{room_id} + ":genesis-group",
                                                                std::nullopt, genesis_state);
    REQUIRE(group_id.has_value());
    REQUIRE(database::set_event_state_group(store, member_id, *group_id));
    REQUIRE(database::update_forward_extremities(store, room_id, member_id, {}, true));

    // FED-11 admission gate: the pdu_sink now rejects PDUs for rooms with no
    // local member. Seed a local join in every test room so remote messages
    // are admitted.
    auto const local_user = std::string{"@local_user:local.example.org"};
    auto local_member_content = canonicaljson::Object{};
    local_member_content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    auto const local_member_id = std::string{room_id} + ":local_member";
    auto const local_member_json =
        make_seed_event_json(room_id, "m.room.member", local_user, local_user, std::move(local_member_content), 3, 4);
    store.events.push_back({local_member_id, std::string{room_id}, local_user, local_member_json, 0U, 0U, {}, {}, {}});
    store.state.push_back({std::string{room_id}, "m.room.member", local_user, local_member_id});
    store.memberships.push_back({std::string{room_id}, local_user, "join", 0U});

    auto const local_state = std::vector<database::PersistentStateGroupStateEntry>{
        {"", "m.room.create",       "",                          create_id      },
        {"", "m.room.power_levels", "",                          pl_id          },
        {"", "m.room.member",       "@alice:remote.example.org", member_id      },
        {"", "m.room.member",       local_user,                  local_member_id},
    };
    auto const local_group_id = database::create_or_reuse_state_group(
        store, room_id, std::string{room_id} + ":local-member-group", std::nullopt, local_state);
    REQUIRE(local_group_id.has_value());
    REQUIRE(database::set_event_state_group(store, local_member_id, *local_group_id));
    REQUIRE(database::update_forward_extremities(store, room_id, local_member_id, {member_id}, false));
}

[[nodiscard]] auto make_message_pdu(std::string_view room_id, std::size_t seq)
    -> merovingian::federation::InboundPduEnvelope
{
    using namespace merovingian;

    auto content = canonicaljson::Object{};
    content.push_back(
        canonicaljson::make_member("body", canonicaljson::Value{std::string{"hello "} + std::to_string(seq)}));
    content.push_back(canonicaljson::make_member("msgtype", canonicaljson::Value{std::string{"m.text"}}));

    auto event_obj = canonicaljson::Object{};
    event_obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.message"}}));
    event_obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{std::string{room_id}}));
    event_obj.push_back(
        canonicaljson::make_member("sender", canonicaljson::Value{std::string{"@alice:remote.example.org"}}));
    event_obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    event_obj.push_back(
        canonicaljson::make_member("origin_server_ts", canonicaljson::Value{static_cast<std::int64_t>(1000 + seq)}));
    event_obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{static_cast<std::int64_t>(3)}));
    // ADR-0064 phase B2: ingest_pdu_event now also authorises against the
    // state immediately before the PDU (spec step 5), which needs a real
    // prev_event with a recorded state group — seed_room's genesis tip.
    // Every concurrently-sent message in a room names the same tip: the
    // per-room stripe mutex already serializes ingestion for one room, so
    // this does not weaken the concurrency coverage (still many threads
    // racing to ingest into the same and different rooms), it just gives
    // each message a resolvable state-before instead of the trivial empty
    // one an empty prev_events list produced before this phase.
    auto const member_id = std::string{room_id} + ":member";
    auto prev_events_array = canonicaljson::Array{};
    prev_events_array.push_back(canonicaljson::Value{member_id});
    event_obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{std::move(prev_events_array)}));
    // Named auth_events: alice's real power_levels/member events, matching
    // seed_room's naming convention. m.room.create is deliberately NOT
    // named: this room is v12 (MSC4291), where the create event is
    // implicit in the room ID and naming it is itself a selection
    // violation; ingest_pdu_event resolves it separately for v12.
    auto const pl_id = std::string{room_id} + ":pl";
    auto auth_event_ids = std::vector<std::string>{pl_id, member_id};
    auto auth_events_array = canonicaljson::Array{};
    for (auto const& id : auth_event_ids)
    {
        auth_events_array.push_back(canonicaljson::Value{id});
    }
    event_obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{std::move(auth_events_array)}));

    auto const hash = events::make_content_hash(canonicaljson::Value{event_obj});
    REQUIRE(hash.error.empty());

    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{hash.sha256}));
    event_obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));

    auto value = canonicaljson::Value{std::move(event_obj)};
    auto const serialized = canonicaljson::serialize_canonical(value);
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);

    auto env = federation::InboundPduEnvelope{};
    env.event_id = std::string{room_id} + ":message:" + std::to_string(seq);
    env.room_id = std::string{room_id};
    env.room_version = "12";
    env.sender = "@alice:remote.example.org";
    env.event_type = "m.room.message";
    env.origin_server_ts = static_cast<std::int64_t>(1000 + seq);
    env.depth = 3U;
    env.prev_event_ids = {member_id};
    env.auth_event_ids = std::move(auth_event_ids);
    env.json = serialized.output;
    return env;
}

} // namespace

namespace
{

using merovingian::homeserver::PublishedStreamOrdering;

constexpr auto member = "@local_user:local.example.org";
constexpr auto outsider = "@outsider:local.example.org";

// A started runtime with its federation callbacks wired and a notifier of its own, as production wires them.
class FederationFixture final
{
public:
    FederationFixture()
        : path_{unique_sqlite_path()}
        , started_{(std::filesystem::remove(path_), merovingian::homeserver::start_runtime(config_with_sqlite(path_)))}
    {
        REQUIRE(started_.started);
        started_.runtime.sync_notifier = &notifier_;
        merovingian::homeserver::wire_federation_callbacks(started_.runtime);
    }
    FederationFixture(FederationFixture const&) = delete;
    auto operator=(FederationFixture const&) -> FederationFixture& = delete;
    ~FederationFixture()
    {
        std::filesystem::remove(path_);
    }

    [[nodiscard]] auto runtime() -> merovingian::homeserver::HomeserverRuntime&
    {
        return started_.runtime;
    }
    [[nodiscard]] auto notifier() -> merovingian::sync::SyncNotifier&
    {
        return notifier_;
    }

    // A stream ordering reserved, as an inbound PDU reserves one while it commits with runtime.mutex released.
    [[nodiscard]] auto hold() -> std::unique_ptr<PublishedStreamOrdering>
    {
        auto const lock = std::lock_guard{started_.runtime.mutex};
        auto const ordering = merovingian::homeserver::allocate_stream_ordering(started_.runtime.database);
        return std::make_unique<PublishedStreamOrdering>(started_.runtime, ordering);
    }
    [[nodiscard]] auto visible() -> std::uint64_t
    {
        auto const lock = std::lock_guard{started_.runtime.mutex};
        return merovingian::homeserver::visible_stream_position(started_.runtime.database);
    }
    [[nodiscard]] auto ordering_of(std::string const& event_id) -> std::uint64_t
    {
        auto const lock = std::lock_guard{started_.runtime.mutex};
        auto const found = started_.runtime.database.persistent_store.events.find(event_id);
        REQUIRE(found != started_.runtime.database.persistent_store.events.end());
        return found->stream_ordering;
    }
    [[nodiscard]] auto ingest(merovingian::federation::InboundPduEnvelope const& envelope)
        -> merovingian::federation::PduIngestionResult
    {
        return started_.runtime.federation.pdu_sink(envelope);
    }
    // Whether anything wakes `cursor`'s user: true when a publish concerning them happened since it was taken.
    [[nodiscard]] auto moved(merovingian::sync::WaitCursor const& cursor) -> bool
    {
        return notifier_.wait_for_change(cursor, std::chrono::milliseconds{0});
    }

private:
    std::filesystem::path path_;
    merovingian::homeserver::RuntimeStartResult started_;
    merovingian::sync::SyncNotifier notifier_{};
};

} // namespace

// ADR-0437: an inbound PDU concerns the room's members, not every long-poll on the server.
SCENARIO("An inbound PDU wakes the room's members and no one else", "[scoped-federation][federation]")
{
    GIVEN("a room with a local member, and a local user who shares no room with it")
    {
        auto fixture = FederationFixture{};
        seed_room(fixture.runtime(), "!x:local.example.org");
        auto const members_cursor = fixture.notifier().observe(member);
        auto const outsiders_cursor = fixture.notifier().observe(outsider);

        WHEN("a PDU for the room is ingested through the PDU sink")
        {
            auto const result = fixture.ingest(make_message_pdu("!x:local.example.org", 1U));

            THEN("it is accepted, the member is woken and the outsider is not")
            {
                REQUIRE(result.status == merovingian::federation::PduIngestionStatus::accepted);
                REQUIRE(fixture.moved(members_cursor));
                REQUIRE_FALSE(fixture.moved(outsiders_cursor));
            }
        }
    }
}

// ADR-0437: an event that was not yet visible when its own publish ran is announced when the position reaches it.
SCENARIO("An event held behind a pending ordering is announced when that ordering ends",
         "[scoped-federation][federation]")
{
    GIVEN("two orderings pending and a PDU for another room applied behind them")
    {
        for (auto const release_first_held_first : {true, false})
        {
            auto fixture = FederationFixture{};
            seed_room(fixture.runtime(), "!y:local.example.org");
            auto first = fixture.hold();
            auto second = fixture.hold();
            auto const before = fixture.notifier().observe(member);

            auto const envelope = make_message_pdu("!y:local.example.org", 1U);
            auto const result = fixture.ingest(envelope);
            REQUIRE(result.status == merovingian::federation::PduIngestionStatus::accepted);
            auto const event_ordering = fixture.ordering_of(envelope.event_id);

            // The member is woken by the event's own publish, and finds nothing: it is behind the pending orderings.
            REQUIRE(fixture.moved(before));
            REQUIRE(fixture.visible() < event_ordering);

            auto const after_early_wake = fixture.notifier().observe(member);
            if (release_first_held_first)
            {
                first.reset();
            }
            else
            {
                second.reset();
            }
            auto const between_releases = fixture.notifier().observe(member);
            if (release_first_held_first)
            {
                second.reset();
            }
            else
            {
                first.reset();
            }

            WHEN(std::string{"the pending orderings end, "} +
                 (release_first_held_first ? "oldest first" : "newest first"))
            {
                THEN("the member is woken again, and the event is now visible")
                {
                    REQUIRE(fixture.moved(between_releases));
                    REQUIRE(fixture.visible() >= event_ordering);
                    // Whatever woke it before the last release, the last one woke it.
                    REQUIRE(fixture.moved(after_early_wake));
                }
            }
        }
    }
}

// ADR-0437: 5, 6 and 7 pending, released 7, 6, 5.
SCENARIO("Pending orderings released out of order announce only when the oldest ends",
         "[scoped-federation][federation]")
{
    GIVEN("three orderings pending")
    {
        auto fixture = FederationFixture{};
        auto five = fixture.hold();
        auto six = fixture.hold();
        auto seven = fixture.hold();
        auto const cursor = fixture.notifier().observe(member);

        WHEN("they end newest first")
        {
            seven.reset();
            six.reset();

            THEN("nothing is announced while the oldest is still pending")
            {
                REQUIRE_FALSE(fixture.moved(cursor));
            }
            AND_WHEN("the oldest ends")
            {
                five.reset();

                THEN("every user is woken, for the events that were held behind it")
                {
                    REQUIRE(fixture.moved(cursor));
                }
            }
        }
    }
}

// ADR-0437: ending a reservation whose commit failed has nothing to announce.
SCENARIO("A reservation that ends with no event wakes no user", "[scoped-federation][federation]")
{
    GIVEN("a reservation with nothing held behind it")
    {
        auto fixture = FederationFixture{};
        auto const cursor = fixture.notifier().observe(member);

        WHEN("it ends without an event")
        {
            fixture.hold().reset();
            auto const position = fixture.visible();

            THEN("no user is woken, the positions moved, and a later scoped publish still wakes")
            {
                REQUIRE_FALSE(fixture.moved(cursor));
                REQUIRE(fixture.notifier().wait_for_change(position - 1U, 0U, std::chrono::milliseconds{0}));
                auto const audience = std::vector<std::string>{member};
                fixture.notifier().publish(position + 1U, 0U, audience);
                REQUIRE(fixture.moved(cursor));
            }
        }
    }
}
