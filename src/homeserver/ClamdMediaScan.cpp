// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/ClamdMediaScan.hpp"

#include "merovingian/homeserver/RuntimeLockRelease.hpp"
#include "merovingian/homeserver/LocalServices.hpp"
#include "merovingian/media/ClamdScanResult.hpp"
#include "merovingian/media/ClamdScanner.hpp"
#include "merovingian/media/ClamdVerdict.hpp"
#include "merovingian/media/MediaAcceptancePolicy.hpp"
#include "merovingian/observability/AuditCategory.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"

#include <functional>
#include <string>

namespace merovingian::homeserver
{

auto clamd_media_cleared(HomeserverRuntime& runtime, bool const remote_fetch, std::string_view const actor,
                         std::string_view const subject, std::string_view const bytes) -> std::optional<bool>
{
    auto* const scanner = runtime.clamd_scanner.get();
    if (scanner == nullptr || !scanner->enabled())
    {
        return std::nullopt;
    }
    auto const policy = remote_fetch ? runtime.media_repository.config.remote_fetch_media_policy
                                     : runtime.media_repository.config.local_upload_policy;
    if (policy != media::MediaAcceptancePolicy::allow_after_scan)
    {
        return std::nullopt;
    }

    // A scan blocks on a local socket for up to its deadline: never with runtime.mutex held.
    auto const result = std::invoke([&] {
        auto const unlocked = RuntimeLockRelease{};
        return scanner->scan(bytes);
    });
    if (result.is_clean())
    {
        return true;
    }

    auto const infected = result.verdict == media::ClamdVerdict::infected;
    auto const event = infected ? "media.scan_infected" : "media.scan_failed";
    observability::log_diagnostic(
        "media_service", event,
        {
            {"actor",                           std::string{actor},                                             false},
            {"subject",                         std::string{subject},                                           false},
            {"verdict",
             infected ? "infected" : (result.verdict == media::ClamdVerdict::oversize ? "oversize" : "failed"), false},
            {infected ? "signature" : "reason", result.detail,                                                  false}
    },
        infected ? observability::LogEventSeverity::warning : observability::LogEventSeverity::error);
    append_local_audit(runtime.database, observability::AuditCategory::moderation, event, actor, subject,
                       result.detail);
    return false;
}

} // namespace merovingian::homeserver
