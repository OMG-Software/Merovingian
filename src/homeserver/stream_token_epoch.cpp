// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/stream_token_epoch.hpp"

#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/crypto/random.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    auto log_epoch_event(std::string_view event, std::vector<observability::StructuredLogField> fields,
                         observability::LogEventSeverity severity) -> void
    {
        observability::log_diagnostic("stream_token_epoch", event, fields, severity);
    }

    // A random epoch that is neither zero (a token's "no epoch") nor `avoid`. Eight bytes from libsodium; a
    // repeat is drawn again, so the loop ends after one draw in all but a 2^-63 case.
    [[nodiscard]] auto draw_epoch(std::uint64_t avoid) -> std::optional<std::uint64_t>
    {
        constexpr auto max_draws = 4;
        for (auto draw = 0; draw < max_draws; ++draw)
        {
            auto const bytes = crypto::secure_random_bytes(sizeof(std::uint64_t));
            if (!bytes.has_value() || bytes->size() != sizeof(std::uint64_t))
            {
                return std::nullopt;
            }
            auto epoch = std::uint64_t{0U};
            for (auto const byte : *bytes)
            {
                epoch = (epoch << 8U) | static_cast<std::uint64_t>(byte);
            }
            if (epoch != 0U && epoch != avoid)
            {
                return epoch;
            }
        }
        return std::nullopt;
    }

} // namespace

auto ensure_stream_token_epoch(database::PersistentStore& store) -> bool
{
    if (store.stream_token_epoch != 0U)
    {
        return true;
    }
    auto const epoch = draw_epoch(0U);
    if (!epoch.has_value() || !database::persist_stream_token_epoch(store, *epoch))
    {
        log_epoch_event("stream_token_epoch.unavailable",
                        {
                            {"reason", epoch.has_value() ? "write failed" : "no random value", false}
        },
                        observability::LogEventSeverity::error);
        return false;
    }
    log_epoch_event("stream_token_epoch.created",
                    {
                        {"epoch", std::to_string(*epoch), false}
    },
                    observability::LogEventSeverity::info);
    return true;
}

auto begin_stream_token_epoch_after_restore(config::Config const& config) -> bool
{
    // The in-memory backend starts empty every time: there is no backup to restore into it.
    if (config.database().backend == config::DatabaseBackend::memory)
    {
        log_epoch_event("stream_token_epoch.restore_refused",
                        {
                            {"reason", "the in-memory database backend has nothing to restore", false}
        },
                        observability::LogEventSeverity::error);
        return false;
    }
    // Opening the store is what starting the server would do first; it gives a fresh database its first epoch.
    auto database = bootstrap_local_database(config, {}, database::TableLoadProfile::full);
    if (!database.opened)
    {
        log_epoch_event("stream_token_epoch.restore_refused",
                        {
                            {"reason", "the database could not be opened", false}
        },
                        observability::LogEventSeverity::error);
        return false;
    }
    auto& store = database.persistent_store;
    auto const previous = store.stream_token_epoch;
    auto const epoch = draw_epoch(previous);
    if (!epoch.has_value() || !database::persist_stream_token_epoch(store, *epoch))
    {
        log_epoch_event("stream_token_epoch.restore_failed",
                        {
                            {"reason", epoch.has_value() ? "write failed" : "no random value", false}
        },
                        observability::LogEventSeverity::error);
        return false;
    }
    log_epoch_event("stream_token_epoch.restarted",
                    {
                        {"previous_epoch", std::to_string(previous), false},
                        {"epoch",          std::to_string(*epoch),   false}
    },
                    observability::LogEventSeverity::notice);
    return true;
}

} // namespace merovingian::homeserver
