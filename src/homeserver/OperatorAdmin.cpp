// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/OperatorAdmin.hpp"

#include "merovingian/auth/Identity.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/core/QueryParams.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AccountSummary.hpp"
#include "merovingian/homeserver/OperatorReply.hpp"
#include "merovingian/homeserver/ReviewOutcome.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/LocalServices.hpp"
#include "merovingian/observability/AuditCategory.hpp"
#include "merovingian/trust_safety/ReviewRecord.hpp"
#include "merovingian/trust_safety/PolicyEngine.hpp"

#include <stdexcept>
#include <variant>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto text_reply(std::uint16_t status, std::string_view message) -> OperatorReply
    {
        return {status, std::string{message}, false};
    }

    [[nodiscard]] auto json_reply(canonicaljson::Object members) -> OperatorReply
    {
        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(members)});
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return text_reply(500U, "response could not be built");
        }
        return {200U, serialized.output, true};
    }

    [[nodiscard]] auto member_value(canonicaljson::Object const& object, std::string_view key)
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto summary_reply(std::string_view user_id, AccountSummary const& summary) -> OperatorReply
    {
        auto members = canonicaljson::Object{};
        members.push_back(canonicaljson::make_member("admin", canonicaljson::Value{summary.admin}));
        members.push_back(canonicaljson::make_member("deactivated", canonicaljson::Value{summary.deactivated}));
        members.push_back(
            canonicaljson::make_member("devices", canonicaljson::Value{static_cast<std::int64_t>(summary.devices)}));
        members.push_back(canonicaljson::make_member("locked", canonicaljson::Value{summary.locked}));
        members.push_back(canonicaljson::make_member("suspended", canonicaljson::Value{summary.suspended}));
        members.push_back(canonicaljson::make_member("user_id", canonicaljson::Value{std::string{user_id}}));
        return json_reply(std::move(members));
    }

    enum class AccountAction : std::uint8_t
    {
        deactivate,
        lock,
        unlock,
        suspend,
        unsuspend,
    };

    struct ParsedAction final
    {
        AccountAction action{AccountAction::lock};
        bool confirmed{false};
    };

    // The body must be a JSON object with a string `action` among the five; `confirm`, when present, must be a
    // boolean. Anything else is nullopt (400).
    [[nodiscard]] auto parse_account_action(std::string_view body) -> std::optional<ParsedAction>
    {
        auto const parsed = canonicaljson::parse_lossless(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        auto const* action_value = member_value(*object, "action");
        auto const* action_name =
            action_value == nullptr ? nullptr : std::get_if<std::string>(&action_value->storage());
        if (action_name == nullptr)
        {
            return std::nullopt;
        }
        auto result = ParsedAction{};
        if (*action_name == "deactivate")
        {
            result.action = AccountAction::deactivate;
        }
        else if (*action_name == "lock")
        {
            result.action = AccountAction::lock;
        }
        else if (*action_name == "unlock")
        {
            result.action = AccountAction::unlock;
        }
        else if (*action_name == "suspend")
        {
            result.action = AccountAction::suspend;
        }
        else if (*action_name == "unsuspend")
        {
            result.action = AccountAction::unsuspend;
        }
        else
        {
            return std::nullopt;
        }
        if (auto const* confirm_value = member_value(*object, "confirm"); confirm_value != nullptr)
        {
            auto const* confirm = std::get_if<bool>(&confirm_value->storage());
            if (confirm == nullptr)
            {
                return std::nullopt;
            }
            result.confirmed = *confirm;
        }
        return result;
    }

    // Decodes one path segment once. A segment holding a NUL is refused by the router before it gets here;
    // the catch is for a caller that did not go through it.
    [[nodiscard]] auto decode_segment(std::string_view encoded) -> std::optional<std::string>
    {
        try
        {
            return core::percent_decode_path_component(encoded);
        }
        catch (std::invalid_argument const&)
        {
            return std::nullopt;
        }
    }

    struct ReviewBody final
    {
        std::string reason{"manual_review"};
    };

    [[nodiscard]] auto parse_review_body(std::string_view body) -> std::optional<ReviewBody>
    {
        if (body.empty())
        {
            return ReviewBody{};
        }
        auto const parsed = canonicaljson::parse_lossless(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        auto const* reason_value = member_value(*object, "reason");
        auto const* reason = reason_value == nullptr ? nullptr : std::get_if<std::string>(&reason_value->storage());
        if (reason == nullptr || reason->empty())
        {
            return ReviewBody{};
        }
        return ReviewBody{*reason};
    }

    constexpr auto bad_action_message = std::string_view{
        "body must be a JSON object with an \"action\" of deactivate, lock, unlock, suspend or unsuspend"};
    constexpr auto confirm_message = std::string_view{"deactivation is permanent: send \"confirm\": true"};

} // namespace

auto operator_account_request(HomeserverRuntime& runtime, std::string_view admin_id, std::string_view method,
                              std::string_view encoded_user_id, std::string_view body) -> OperatorReply
{
    auto const target = decode_segment(encoded_user_id);
    if (!target.has_value() || !auth::user_id_is_valid(*target) ||
        auth::user_id_server_name(*target) != runtime.config.server().server_name)
    {
        return text_reply(400U, "user does not belong to the local server");
    }
    // The guards of the spec's lock endpoint: acting on your own account is refused (reading it is not), and
    // another administrator can be neither acted on nor read.
    if (method == "POST" && *target == admin_id)
    {
        return text_reply(403U, "cannot act on your own account");
    }
    auto const summary = local_account_summary(runtime, *target);
    if (!summary.has_value())
    {
        return text_reply(404U, "user not found");
    }
    if (summary->admin && *target != admin_id)
    {
        return text_reply(403U, "cannot act on another administrator");
    }
    if (method == "GET")
    {
        return summary_reply(*target, *summary);
    }
    if (body.size() > operator_account_body_limit)
    {
        return text_reply(413U, "request body too large");
    }
    auto const parsed = parse_account_action(body);
    if (!parsed.has_value())
    {
        return text_reply(400U, bad_action_message);
    }
    if (parsed->action == AccountAction::deactivate)
    {
        if (!parsed->confirmed)
        {
            return text_reply(400U, confirm_message);
        }
        // A repeat runs the whole deactivation again, which completes one that failed part way.
        auto const result =
            deactivate_user_account(runtime, *target, {std::string{admin_id}, *target, "deactivated_by_admin"});
        if (!result.ok)
        {
            return text_reply(500U, "deactivation failed");
        }
    }
    else
    {
        if (summary->deactivated)
        {
            return text_reply(409U, "account is deactivated");
        }
        auto suspended = summary->suspended;
        auto locked = summary->locked;
        auto audit_event = std::string_view{"account.locked"};
        auto reason = std::string_view{};
        switch (parsed->action)
        {
        case AccountAction::lock:
            locked = true;
            reason = "locked";
            break;
        case AccountAction::unlock:
            locked = false;
            reason = "unlocked";
            break;
        case AccountAction::suspend:
            suspended = true;
            audit_event = "account.suspended";
            reason = "suspended";
            break;
        case AccountAction::unsuspend:
            suspended = false;
            audit_event = "account.suspended";
            reason = "unsuspended";
            break;
        case AccountAction::deactivate:
            break;
        }
        if (!set_local_user_moderation(runtime, admin_id, *target, suspended, locked, audit_event, reason).ok)
        {
            return text_reply(500U, "failed to persist account state");
        }
    }
    auto const after = local_account_summary(runtime, *target);
    return after.has_value() ? summary_reply(*target, *after) : text_reply(404U, "user not found");
}

auto review_target_from_name(std::string_view name) -> std::optional<trust_safety::ReviewTarget>
{
    if (name == "federation" || name == "federation_server")
    {
        return trust_safety::ReviewTarget::federation_server;
    }
    if (name == "media")
    {
        return trust_safety::ReviewTarget::media;
    }
    if (name == "room")
    {
        return trust_safety::ReviewTarget::room;
    }
    return std::nullopt;
}

auto apply_admin_review(HomeserverRuntime& runtime, std::string_view admin_user,
                        std::optional<trust_safety::ReviewTarget> target, std::string_view target_id,
                        std::string_view body) -> ReviewOutcome
{
    auto const parsed_body = parse_review_body(body);
    if (!target.has_value() || target_id.empty() || !parsed_body.has_value())
    {
        return {400U, "M_BAD_JSON", "admin review body must be Matrix JSON"};
    }
    auto const reason = trust_safety::enforcement_reason(parsed_body->reason, "target held for review",
                                                         "admin marked target for review");
    auto const record = trust_safety::ReviewRecord{*target, std::string{target_id}, true, reason};
    auto const decision = trust_safety::review_policy(record);
    auto const audit = trust_safety::make_safety_audit_event(admin_user, target_id, decision);
    append_local_audit(runtime.database, observability::AuditCategory::policy, audit.event_type, audit.actor,
                       audit.entity, audit.reason.code);
    auto const scope = std::string{trust_safety::policy_surface_name(decision.surface)};
    if (!database::store_policy_rule(runtime.database.persistent_store,
                                     {scope + ':' + std::string{target_id}, scope, std::string{target_id},
                                      std::string{trust_safety::policy_action_name(decision.action)},
                                      parsed_body->reason}))
    {
        return {500U, "M_UNKNOWN", "policy rule persistence failed"};
    }
    if (!database::append_admin_action(runtime.database.persistent_store,
                                       {std::string{admin_user}, audit.event_type, std::string{target_id}}))
    {
        return {500U, "M_UNKNOWN", "admin action persistence failed"};
    }
    if (decision.action == trust_safety::PolicyAction::quarantine || decision.allowed)
    {
        return {200U, {}, {}};
    }
    return {400U, "M_BAD_REQUEST", decision.reason.public_summary};
}

auto operator_review_request(HomeserverRuntime& runtime, std::string_view admin_id, std::string_view type_and_id,
                             std::string_view body) -> OperatorReply
{
    auto const separator = type_and_id.find('/');
    if (separator == std::string_view::npos || separator == 0U || separator + 1U >= type_and_id.size())
    {
        return text_reply(400U, "review target must be {targetType}/{targetId}");
    }
    auto const target_id = decode_segment(type_and_id.substr(separator + 1U));
    if (!target_id.has_value())
    {
        return text_reply(400U, "review target id is not valid");
    }
    auto const outcome = apply_admin_review(
        runtime, admin_id, review_target_from_name(type_and_id.substr(0U, separator)), *target_id, body);
    if (outcome.status == 200U)
    {
        return {200U, "{}", true};
    }
    return text_reply(outcome.status, outcome.message);
}

} // namespace merovingian::homeserver
