// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/authorization.hpp"

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>
#include <vector>

namespace merovingian::events
{
namespace
{

    [[nodiscard]] auto auth_rule_name(rooms::AuthRules rules) noexcept -> char const*
    {
        switch (rules)
        {
        case rooms::AuthRules::room_v1:
            return "room_v1";
        case rooms::AuthRules::room_v6_plus:
            return "room_v6_plus";
        case rooms::AuthRules::room_v12:
            // Distinct hook for auditability: v12 adds creator privilege (MSC4289)
            // and implicit create (MSC4291) on top of the v6+ rule base.
            return "room_v12";
        }

        return "unknown";
    }

    [[nodiscard]] auto requires_power_levels(std::string_view event_type) noexcept -> bool
    {
        return event_type != "m.room.create";
    }

    [[nodiscard]] auto requires_membership(std::string_view event_type) noexcept -> bool
    {
        return event_type == "m.room.member";
    }

    [[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
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

    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto integer_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::int64_t const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::int64_t>(&value->storage());
    }

    [[nodiscard]] auto object_member_as_object(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&value->storage());
    }

    [[nodiscard]] auto value_is_object(canonicaljson::Value const& value) noexcept -> canonicaljson::Object const*
    {
        return std::get_if<canonicaljson::Object>(&value.storage());
    }

    [[nodiscard]] auto value_has_content(canonicaljson::Value const& value) noexcept -> bool
    {
        return !std::holds_alternative<std::nullptr_t>(value.storage());
    }

    [[nodiscard]] auto make_denied(std::string step, std::string reason) -> EventAuthorizationDecision
    {
        observability::log_diagnostic("event_auth", "authorization.rejected",
                                      {
                                          {"rule_step", step,   false},
                                          {"reason",    reason, false}
        });
        return {false, {}, std::move(step), std::move(reason)};
    }

    [[nodiscard]] auto make_allowed(std::string step) -> EventAuthorizationDecision
    {
        return {true, {}, std::move(step), {}};
    }

    [[nodiscard]] auto event_content_string(canonicaljson::Value const& event, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* obj = value_is_object(event);
        if (obj == nullptr)
        {
            return nullptr;
        }
        auto const* content = object_member_as_object(*obj, "content");
        return content == nullptr ? nullptr : string_member(*content, key);
    }

    // Reads a power level that may be encoded either as an integer or, in room
    // versions 1-9, as a string representation of one. Returns nullopt when the
    // value is absent or is not a power level in a form this room version accepts.
    // Spec: ../../docs/matrix-v1.19-spec/rooms/v10.md — "Values in
    // m.room.power_levels events must be integers" (and, for v1-v9, v9's
    // "m.room.power_levels events accept values as strings").
    [[nodiscard]] auto power_level_value(canonicaljson::Value const* value, bool allow_string_values) noexcept
        -> std::optional<std::int64_t>
    {
        if (value == nullptr)
        {
            return std::nullopt;
        }
        if (auto const* integer = std::get_if<std::int64_t>(&value->storage()); integer != nullptr)
        {
            return *integer;
        }
        if (!allow_string_values)
        {
            return std::nullopt;
        }
        auto const* text = std::get_if<std::string>(&value->storage());
        if (text == nullptr || text->empty())
        {
            return std::nullopt;
        }
        // Only a plain optionally-signed decimal integer counts. from_chars
        // rejects leading whitespace, "+", "0x" and trailing junk, and the
        // end-pointer check rejects anything it stopped short on, so "10abc" and
        // "1.5" are not power levels.
        auto parsed = std::int64_t{0};
        auto const* first = text->data();
        auto const* last = first + text->size();
        auto const result = std::from_chars(first, last, parsed);
        if (result.ec != std::errc{} || result.ptr != last)
        {
            return std::nullopt;
        }
        return parsed;
    }

    [[nodiscard]] auto power_level_member(canonicaljson::Object const& object, std::string_view key,
                                          bool allow_string_values) noexcept -> std::optional<std::int64_t>
    {
        return power_level_value(object_member(object, key), allow_string_values);
    }

    [[nodiscard]] auto extract_user_level_from_users(canonicaljson::Object const& users_object,
                                                     std::string_view user_id, bool allow_string_values) noexcept
        -> std::int64_t
    {
        auto const level = power_level_member(users_object, user_id, allow_string_values);
        return level.has_value() ? *level : -1;
    }

    [[nodiscard]] auto membership_at_least_one_of(MembershipState current,
                                                  std::initializer_list<MembershipState> required) noexcept -> bool
    {
        for (auto const m : required)
        {
            if (current == m)
            {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] auto array_contains_string(canonicaljson::Value const& value, std::string_view needle) noexcept
        -> bool
    {
        auto const* array = std::get_if<canonicaljson::Array>(&value.storage());
        if (array == nullptr)
        {
            return false;
        }
        return std::ranges::any_of(*array, [needle](canonicaljson::Value const& element) {
            auto const* text = std::get_if<std::string>(&element.storage());
            return text != nullptr && *text == needle;
        });
    }

    // MSC4289 (room v12): the create event's sender and every user listed in the
    // create event's content.additional_creators are room creators. Only room
    // versions whose policy privileges creators treat them specially.
    [[nodiscard]] auto user_is_room_creator(canonicaljson::Value const& create_event, std::string_view user_id,
                                            rooms::RoomVersionPolicy const& policy) noexcept -> bool
    {
        if (!policy.privilege_room_creators)
        {
            return false;
        }
        auto const* obj = value_is_object(create_event);
        if (obj == nullptr)
        {
            return false;
        }
        if (auto const* sender = string_member(*obj, "sender"); sender != nullptr && *sender == user_id)
        {
            return true;
        }
        auto const* content = object_member_as_object(*obj, "content");
        if (content == nullptr)
        {
            return false;
        }
        auto const* additional = object_member(*content, "additional_creators");
        return additional != nullptr && array_contains_string(*additional, user_id);
    }

    // The "creator infinite power" sentinel for MSC4289. A room creator outranks
    // every integer power level, so comparisons treat their power as the maximum
    // representable value rather than a literal number from the power_levels event.
    constexpr auto creator_power = std::numeric_limits<std::int64_t>::max();

    [[nodiscard]] auto effective_sender_power(canonicaljson::Value const& power_levels, std::string_view sender,
                                              canonicaljson::Value const& create_event,
                                              rooms::RoomVersionPolicy const& policy) noexcept -> std::int64_t
    {
        // MSC4289: room creators hold an effectively infinite power level that is
        // independent of (and overrides) any entry in the power_levels event.
        if (user_is_room_creator(create_event, sender, policy))
        {
            return creator_power;
        }
        if (value_has_content(power_levels))
        {
            return extract_user_power_level(power_levels, sender, !policy.power_levels_require_integers);
        }
        auto const* creator = event_content_string(create_event, "creator");
        if (creator != nullptr && sender == *creator)
        {
            return 100;
        }
        return 0;
    }

    // Every candidate public key a third-party invite's "signed" blob may be
    // checked against: content.public_key (legacy single-key form) plus each
    // entry of content.public_keys[].public_key.
    // Spec: rooms/v11.md Authorization rules for m.room.member, rule 4.3.1.7.
    [[nodiscard]] auto collect_third_party_invite_public_keys(canonicaljson::Value const& third_party_invite_event)
        -> std::vector<std::string>
    {
        auto keys = std::vector<std::string>{};
        auto const* event_obj = value_is_object(third_party_invite_event);
        auto const* content = event_obj == nullptr ? nullptr : object_member_as_object(*event_obj, "content");
        if (content == nullptr)
        {
            return keys;
        }
        if (auto const* single_key = string_member(*content, "public_key"); single_key != nullptr)
        {
            keys.push_back(*single_key);
        }
        if (auto const* list = object_member(*content, "public_keys"); list != nullptr)
        {
            if (auto const* array = std::get_if<canonicaljson::Array>(&list->storage()); array != nullptr)
            {
                for (auto const& entry : *array)
                {
                    auto const* entry_obj = value_is_object(entry);
                    if (entry_obj == nullptr)
                    {
                        continue;
                    }
                    if (auto const* key = string_member(*entry_obj, "public_key"); key != nullptr)
                    {
                        keys.push_back(*key);
                    }
                }
            }
        }
        return keys;
    }

    // Spec: rooms/v11.md rule 4.3.1.7 — "If any signature in signed matches any
    // public key in the m.room.third_party_invite event, allow." The signed blob
    // ({mxid, sender, token, signatures}) is signed like any other Matrix signed
    // JSON object: canonical JSON with "signatures" (and "unsigned") stripped.
    [[nodiscard]] auto third_party_invite_signature_is_valid(canonicaljson::Object const& signed_obj,
                                                             canonicaljson::Value const& third_party_invite_event)
        -> bool
    {
        auto const* signatures_value = object_member(signed_obj, "signatures");
        auto const* signatures = signatures_value == nullptr ? nullptr : value_is_object(*signatures_value);
        if (signatures == nullptr)
        {
            return false;
        }

        auto const candidate_keys = collect_third_party_invite_public_keys(third_party_invite_event);
        if (candidate_keys.empty())
        {
            return false;
        }

        auto const payload = make_event_signing_payload(canonicaljson::Value{signed_obj});
        if (payload.error != canonicaljson::CanonicalJsonError::none)
        {
            return false;
        }

        for (auto const& server_entry : *signatures)
        {
            auto const* key_signatures = value_is_object(*server_entry.value);
            if (key_signatures == nullptr)
            {
                continue;
            }
            for (auto const& key_entry : *key_signatures)
            {
                auto const* signature_b64 = std::get_if<std::string>(&key_entry.value->storage());
                if (signature_b64 == nullptr)
                {
                    continue;
                }
                auto const signature = crypto::Ed25519Signature{matrix_bytes_from_base64(*signature_b64)};
                if (!crypto::ed25519_signature_shape_is_valid(signature))
                {
                    continue;
                }
                for (auto const& public_key_b64 : candidate_keys)
                {
                    auto const public_key = crypto::Ed25519PublicKey{matrix_bytes_from_base64(public_key_b64)};
                    if (!crypto::ed25519_public_key_shape_is_valid(public_key))
                    {
                        continue;
                    }
                    if (crypto::ed25519_verify(public_key, payload.output, signature).valid)
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // Spec: rooms/v11.md Authorization rules for m.room.member — rule 4.3.1.
    // "If content has a third_party_invite property" — a fully self-contained
    // decision tree that replaces the normal invite checks (target-not-joined,
    // sender-joined, invite-power) for invites accepted via a 3PID token.
    [[nodiscard]] auto authorize_third_party_invite(canonicaljson::Value const& third_party_invite_content,
                                                    std::string_view state_key, std::string_view sender,
                                                    MembershipState target_current_membership,
                                                    canonicaljson::Value const& third_party_invite_event)
        -> EventAuthorizationDecision
    {
        // 4.3.1.1: target user banned -> reject.
        if (target_current_membership == MembershipState::ban)
        {
            return make_denied("6", "banned user cannot accept a third-party invite");
        }

        // 4.3.1.2: third_party_invite must have a "signed" property.
        auto const* tpi_obj = value_is_object(third_party_invite_content);
        auto const* signed_value = tpi_obj == nullptr ? nullptr : object_member(*tpi_obj, "signed");
        auto const* signed_obj = signed_value == nullptr ? nullptr : value_is_object(*signed_value);
        if (signed_obj == nullptr)
        {
            return make_denied("6", "third_party_invite missing signed property");
        }

        // 4.3.1.3: "signed" must have "mxid" and "token".
        auto const* mxid = string_member(*signed_obj, "mxid");
        auto const* token = string_member(*signed_obj, "token");
        if (mxid == nullptr || token == nullptr)
        {
            return make_denied("6", "third_party_invite signed is missing mxid or token");
        }

        // 4.3.1.4: mxid must match the event's state_key.
        if (*mxid != state_key)
        {
            return make_denied("6", "third_party_invite signed mxid does not match state_key");
        }

        // 4.3.1.5: an m.room.third_party_invite event with state_key == token must
        // be present in current room state.
        auto const* tpi_event_obj = value_is_object(third_party_invite_event);
        auto const* tpi_event_state_key =
            tpi_event_obj == nullptr ? nullptr : string_member(*tpi_event_obj, "state_key");
        if (!value_has_content(third_party_invite_event) || tpi_event_state_key == nullptr ||
            *tpi_event_state_key != *token)
        {
            return make_denied("6", "no matching m.room.third_party_invite event for token");
        }

        // 4.3.1.6: sender must match the sender of the m.room.third_party_invite event.
        auto const* tpi_event_sender = string_member(*tpi_event_obj, "sender");
        if (tpi_event_sender == nullptr || *tpi_event_sender != sender)
        {
            return make_denied("6", "sender does not match m.room.third_party_invite sender");
        }

        // 4.3.1.7 / 4.3.1.8: a signature in "signed" must verify against a public
        // key carried by the m.room.third_party_invite event; otherwise reject.
        if (!third_party_invite_signature_is_valid(*signed_obj, third_party_invite_event))
        {
            return make_denied("6", "third_party_invite signature does not match any public key");
        }

        return make_allowed("6");
    }

    // The seven scalar power-level keys. Rule 9.1 requires each to be an integer
    // when present; rule 9.5 bounds every alteration of one by the sender's own
    // power level, in both the old and the new direction.
    // Spec: ../../docs/matrix-v1.19-spec/rooms/v11.md — Authorization rules, rule 9.
    constexpr auto scalar_power_level_keys = std::array{
        std::string_view{"users_default"}, std::string_view{"events_default"}, std::string_view{"state_default"},
        std::string_view{"ban"},           std::string_view{"redact"},         std::string_view{"kick"},
        std::string_view{"invite"},
    };

    // Minimal user-ID well-formedness check, used by rule 9.3 (content.users keys)
    // and by rule 1.4 (v12 content.additional_creators). Deliberately as permissive
    // as auth::user_id_is_valid_federated — historical localparts must keep working
    // — and restated here rather than imported because events_lib does not link
    // auth_lib and adding that edge for one grammar check is not worth the coupling.
    [[nodiscard]] auto user_id_is_well_formed(std::string_view user_id) noexcept -> bool
    {
        if (user_id.size() < 3U || user_id.size() > 255U || user_id.front() != '@')
        {
            return false;
        }
        // Split at the FIRST colon: the localpart may not contain one, so a second
        // colon belongs to the server name's port and anything before it does not.
        auto const separator = user_id.find(':');
        if (separator == std::string_view::npos || separator + 1U >= user_id.size())
        {
            return false;
        }
        auto const localpart = user_id.substr(1U, separator - 1U);
        auto const server_name = user_id.substr(separator + 1U);

        // Deliberately permissive on the localpart's character set -- historical
        // user IDs carry bytes the current grammar would reject, and this runs on
        // events other servers have already accepted. What it will not accept is
        // anything that cannot be a user ID at all: an embedded NUL, a control
        // character, or whitespace. A prefix-only check passed all of those, so
        // values like "@alice:not a server" satisfied a rule that exists
        // specifically to require valid user IDs.
        auto const is_structurally_invalid = [](char c) {
            auto const byte = static_cast<unsigned char>(c);
            return byte <= 0x20U || byte == 0x7FU;
        };
        if (std::ranges::any_of(localpart, is_structurally_invalid) ||
            std::ranges::any_of(server_name, is_structurally_invalid))
        {
            return false;
        }
        // The server-name half must additionally look like a host: no colons
        // beyond an optional single port separator, and a non-empty host.
        auto const port_separator = server_name.find(':');
        auto const host = server_name.substr(0U, port_separator);
        if (host.empty())
        {
            return false;
        }
        return port_separator == std::string_view::npos ||
               server_name.find(':', port_separator + 1U) == std::string_view::npos;
    }

    // Rules 9.1, 9.2 and 9.3: structural validation of an m.room.power_levels
    // content object. Returns an empty string when well formed, else the reason.
    // The power-level maps rule 9 bounds. `notifications` joined the algorithm in
    // room version 6: for v1-v5 the rules speak only of `events`, so iterating
    // both there would reject changes those versions explicitly allow.
    // Spec: ../../docs/matrix-v1.19-spec/rooms/v6.md — "the authorisation rules
    // for events of type m.room.power_levels now include a notifications property".
    [[nodiscard]] auto bounded_power_level_maps(rooms::RoomVersionPolicy const& policy) -> std::vector<std::string_view>
    {
        if (policy.auth_rules == rooms::AuthRules::room_v1)
        {
            return {std::string_view{"events"}};
        }
        return {std::string_view{"events"}, std::string_view{"notifications"}};
    }

    [[nodiscard]] auto power_levels_content_rejection_reason(canonicaljson::Object const& content,
                                                             rooms::RoomVersionPolicy const& policy) -> std::string
    {
        // Room versions 1-9 accept an integer power level encoded as a string;
        // v10 removed that compatibility. Validating unconditionally as integers
        // rejected valid historical events such as "events_default":"0".
        auto const allow_strings = !policy.power_levels_require_integers;

        // 9.1 — scalar keys must be power-level values when present.
        for (auto const& key : scalar_power_level_keys)
        {
            auto const* value = object_member(content, key);
            if (value != nullptr && !power_level_value(value, allow_strings).has_value())
            {
                return std::string{key} + " must be an integer";
            }
        }

        // 9.2 — the bounded maps must be objects of power-level values.
        for (auto const& key : bounded_power_level_maps(policy))
        {
            auto const* value = object_member(content, key);
            if (value == nullptr)
            {
                continue;
            }
            auto const* map = std::get_if<canonicaljson::Object>(&value->storage());
            if (map == nullptr)
            {
                return std::string{key} + " must be an object";
            }
            for (auto const& entry : *map)
            {
                if (!power_level_value(entry.value.get(), allow_strings).has_value())
                {
                    return std::string{key} + " values must be integers";
                }
            }
        }

        // 9.3 — users must map valid user IDs to power-level values.
        auto const* users_value = object_member(content, "users");
        if (users_value == nullptr)
        {
            return {};
        }
        auto const* users = std::get_if<canonicaljson::Object>(&users_value->storage());
        if (users == nullptr)
        {
            return "users must be an object";
        }
        for (auto const& entry : *users)
        {
            if (!user_id_is_well_formed(entry.key))
            {
                return "users keys must be valid user IDs";
            }
            if (!power_level_value(entry.value.get(), allow_strings).has_value())
            {
                return "users values must be integers";
            }
        }

        return {};
    }

    // Rule 9.5: for each scalar key added to, changed in, or removed from content,
    // neither the current nor the new value may exceed the sender's power level.
    // Absence of this check let any sender holding state_default rewrite
    // users_default, ban, kick, redact and invite without bound (#487).
    [[nodiscard]] auto scalar_power_level_rejection_reason(canonicaljson::Object const& old_content,
                                                           canonicaljson::Object const& new_content,
                                                           std::int64_t sender_power, bool allow_string_values)
        -> std::string
    {
        for (auto const& key : scalar_power_level_keys)
        {
            auto const old_level = power_level_member(old_content, key, allow_string_values);
            auto const new_level = power_level_member(new_content, key, allow_string_values);
            auto const unchanged = (!old_level.has_value() && !new_level.has_value()) ||
                                   (old_level.has_value() && new_level.has_value() && *old_level == *new_level);
            if (unchanged)
            {
                continue;
            }
            // 9.5.1 — the value being replaced must be within the sender's reach.
            if (old_level.has_value() && *old_level > sender_power)
            {
                return "cannot alter " + std::string{key} + ": its current value exceeds the sender's power level";
            }
            // 9.5.2 — and so must the value replacing it.
            if (new_level.has_value() && *new_level > sender_power)
            {
                return "cannot set " + std::string{key} + " above the sender's own power level";
            }
        }

        return {};
    }

    // Rules 9.6 and 9.7: entries in the events and notifications maps are bounded
    // by the sender's power in their current value (when changed or removed) and
    // in their new value (when added or changed).
    [[nodiscard]] auto power_level_map_rejection_reason(canonicaljson::Object const& old_content,
                                                        canonicaljson::Object const& new_content,
                                                        std::string_view map_key, std::int64_t sender_power,
                                                        bool allow_string_values) -> std::string
    {
        auto const* old_map = object_member_as_object(old_content, map_key);
        auto const* new_map = object_member_as_object(new_content, map_key);

        // 9.6 — for each entry changed in, or removed from, the map.
        if (old_map != nullptr)
        {
            for (auto const& entry : *old_map)
            {
                auto const old_level = power_level_value(entry.value.get(), allow_string_values);
                if (!old_level.has_value())
                {
                    continue;
                }
                auto const new_level = new_map == nullptr
                                           ? std::optional<std::int64_t>{}
                                           : power_level_member(*new_map, entry.key, allow_string_values);
                auto const removed_or_changed = !new_level.has_value() || (*new_level != *old_level);
                if (removed_or_changed && *old_level > sender_power)
                {
                    return std::string{map_key} + " entry '" + entry.key +
                           "' currently exceeds the sender's power level";
                }
            }
        }

        // 9.7 — for each entry added to, or changed in, the map.
        if (new_map != nullptr)
        {
            for (auto const& entry : *new_map)
            {
                auto const new_level = power_level_value(entry.value.get(), allow_string_values);
                if (!new_level.has_value())
                {
                    continue;
                }
                auto const old_level = old_map == nullptr
                                           ? std::optional<std::int64_t>{}
                                           : power_level_member(*old_map, entry.key, allow_string_values);
                auto const added_or_changed = !old_level.has_value() || (*new_level != *old_level);
                if (added_or_changed && *new_level > sender_power)
                {
                    return std::string{map_key} + " entry '" + entry.key + "' exceeds the sender's power level";
                }
            }
        }

        return {};
    }

    // Rule 1: m.room.create. Sub-rules 1.1 and 1.3 are common to every room
    // version; 1.2 and 1.4 differ between v1-v10, v11 and v12. None of these was
    // enforced before 0.12.4, which let a remote server mint a create event whose
    // room_id claimed another homeserver's domain (#487).
    // Spec: ../../docs/matrix-v1.19-spec/rooms/v1.md, v11.md and v12.md.
    [[nodiscard]] auto create_event_rejection_reason(canonicaljson::Object const& event,
                                                     rooms::RoomVersionPolicy const& policy) -> std::string
    {
        // 1.1 — a create event starts the room's DAG and can reference nothing.
        if (auto const* prev_events = object_member(event, "prev_events"); prev_events != nullptr)
        {
            auto const* entries = std::get_if<canonicaljson::Array>(&prev_events->storage());
            if (entries != nullptr && !entries->empty())
            {
                return "create event must not have prev_events";
            }
        }

        auto const* sender = string_member(event, "sender");
        auto const* room_id = string_member(event, "room_id");

        if (policy.create_event_is_room_id)
        {
            // 1.2 (v12/MSC4291) — the room ID *is* this event's ID, so the event
            // must not carry a room_id of its own.
            if (room_id != nullptr)
            {
                return "v12 create event must not carry a room_id";
            }
        }
        else
        {
            // 1.2 (v1-v11) — the room ID is minted by the creating server and must
            // sit in that server's own namespace. Without this check a federating
            // server can squat room IDs inside another homeserver's domain.
            if (room_id == nullptr)
            {
                return "create event requires a room_id";
            }
            if (sender == nullptr || domain_of(*room_id) != domain_of(*sender))
            {
                return "create event room_id domain does not match the sender domain";
            }
        }

        auto const* content = object_member_as_object(event, "content");

        // 1.4 (v1-v10) — content.creator is required. Room v11 removed the field
        // (the create event's sender is the creator), and the redaction-rules
        // bucket identifies the pre-v11 versions exactly.
        auto const creator_field_required =
            !policy.create_event_is_room_id && policy.redaction_rules != rooms::RedactionRules::room_v11_plus;
        // Presence, not type: rule 1.4 rejects a create event only when content
        // has no `creator` property. It says nothing about that property's value,
        // so testing with string_member treated a present non-string creator as
        // absent and rejected historical events other servers must accept.
        if (creator_field_required && (content == nullptr || object_member(*content, "creator") == nullptr))
        {
            return "create event content requires a creator";
        }

        if (content == nullptr)
        {
            return {};
        }

        // 1.3 — a room_version this server does not recognise cannot be authorised.
        if (auto const* room_version = string_member(*content, "room_version"); room_version != nullptr)
        {
            if (!rooms::room_version_is_supported(*room_version))
            {
                return "create event declares an unrecognised room_version";
            }
        }

        // 1.4 (v12/MSC4289) — additional_creators, when present, must be an array
        // of well-formed user IDs. Each entry gains creator privilege, so a
        // malformed entry must not be silently ignored.
        if (policy.create_event_is_room_id)
        {
            if (auto const* additional = object_member(*content, "additional_creators"); additional != nullptr)
            {
                auto const* entries = std::get_if<canonicaljson::Array>(&additional->storage());
                if (entries == nullptr)
                {
                    return "additional_creators must be an array";
                }
                for (auto const& entry : *entries)
                {
                    auto const* user_id = std::get_if<std::string>(&entry.storage());
                    if (user_id == nullptr || !user_id_is_well_formed(*user_id))
                    {
                        return "additional_creators must contain only valid user IDs";
                    }
                }
            }
        }

        return {};
    }

} // namespace

auto auth_rule_hook_name(rooms::RoomVersionPolicy const& policy) -> std::string
{
    return std::string{"auth_rules."} + auth_rule_name(policy.auth_rules);
}

auto membership_name(MembershipState membership) noexcept -> char const*
{
    switch (membership)
    {
    case MembershipState::leave:
        return "leave";
    case MembershipState::invite:
        return "invite";
    case MembershipState::join:
        return "join";
    case MembershipState::ban:
        return "ban";
    case MembershipState::knock:
        return "knock";
    case MembershipState::restricted:
        return "restricted";
    }

    return "unknown";
}

auto power_level_allows(PowerLevelPolicy policy) noexcept -> bool
{
    return policy.sender_power >= policy.required_power;
}

auto membership_policy_allows(MembershipPolicy policy) -> EventAuthorizationDecision
{
    if (policy.target_is_restricted)
    {
        return {false, "membership", "4", "target membership is restricted"};
    }
    if (policy.requested_membership == MembershipState::join && policy.target_is_sender)
    {
        return {true, "membership", "4", {}};
    }
    if (policy.requested_membership == MembershipState::invite)
    {
        if (policy.sender_power >= policy.invite_power)
        {
            return {true, "membership", "4", {}};
        }
        return {false, "membership", "4", "insufficient power to invite"};
    }
    if (policy.requested_membership == MembershipState::restricted)
    {
        if (policy.sender_power >= policy.restrict_power)
        {
            return {true, "membership", "4", {}};
        }
        return {false, "membership", "4", "insufficient power to restrict membership"};
    }
    if (policy.requested_membership == MembershipState::leave)
    {
        if (policy.target_is_sender)
        {
            return {true, "membership", "4", {}};
        }
        if (policy.sender_power >= policy.remove_power)
        {
            return {true, "membership", "4", {}};
        }
        return {false, "membership", "4", "insufficient power to remove another member"};
    }

    return {false, "membership", "4", "membership transition is not allowed"};
}

auto parse_membership_state(std::string_view membership) noexcept -> std::optional<MembershipState>
{
    if (membership == "join")
    {
        return MembershipState::join;
    }
    if (membership == "invite")
    {
        return MembershipState::invite;
    }
    if (membership == "leave")
    {
        return MembershipState::leave;
    }
    if (membership == "ban")
    {
        return MembershipState::ban;
    }
    if (membership == "knock")
    {
        return MembershipState::knock;
    }
    return std::nullopt;
}

auto domain_of(std::string_view matrix_id) noexcept -> std::string_view
{
    auto const colon = matrix_id.find(':');
    if (colon == std::string_view::npos)
    {
        return {};
    }
    return matrix_id.substr(colon + 1);
}

auto extract_content_membership(canonicaljson::Value const& event) noexcept -> std::string
{
    auto const* membership = event_content_string(event, "membership");
    return membership == nullptr ? std::string{} : *membership;
}

auto extract_user_power_level(canonicaljson::Value const& power_levels_event, std::string_view user_id,
                              bool allow_string_values) noexcept -> std::int64_t
{
    auto const* obj = value_is_object(power_levels_event);
    if (obj == nullptr)
    {
        return 0;
    }
    auto const* content = object_member_as_object(*obj, "content");
    if (content == nullptr)
    {
        return 0;
    }
    auto const default_level = extract_power_level_key(power_levels_event, "users_default", 0, allow_string_values);
    auto const* users = object_member_as_object(*content, "users");
    if (users == nullptr)
    {
        return default_level;
    }
    auto const user_level = extract_user_level_from_users(*users, user_id, allow_string_values);
    return user_level >= 0 ? user_level : default_level;
}

auto extract_power_level_key(canonicaljson::Value const& power_levels_event, std::string_view key,
                             std::int64_t default_value, bool allow_string_values) noexcept -> std::int64_t
{
    auto const* obj = value_is_object(power_levels_event);
    if (obj == nullptr)
    {
        return default_value;
    }
    auto const* content = object_member_as_object(*obj, "content");
    if (content == nullptr)
    {
        return default_value;
    }
    if (auto const level = power_level_member(*content, key, allow_string_values); level.has_value())
    {
        return *level;
    }
    // No fallback into content.events. That map keys *event types* to power
    // levels, so "ban", "kick", "redact", "invite", "users_default",
    // "events_default" and "state_default" are not names it can legitimately
    // carry. Consulting it here let a sender who omitted a top-level scalar key
    // smuggle its value in under an event-type name and, for example, drop the
    // effective ban level to zero (#487).
    return default_value;
}

auto authorize_event(rooms::RoomVersionPolicy const& policy, EventAuthorizationRequest const& request)
    -> EventAuthorizationDecision
{
    auto const rule_hook = auth_rule_hook_name(policy);
    if (policy.id != request.room_version)
    {
        return {false, rule_hook, "0", "room version mismatch"};
    }
    if (request.event_type.empty())
    {
        return {false, rule_hook, "0", "event type is required"};
    }
    if (!power_level_allows(request.power_level))
    {
        return {false, rule_hook, "0", "insufficient power level"};
    }
    if (requires_membership(request.event_type))
    {
        auto membership_decision = membership_policy_allows(request.membership);
        membership_decision.rule_hook = rule_hook;
        return membership_decision;
    }

    return {true, rule_hook, "0", {}};
}

auto authorize_event_against_auth_events(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy,
                                         AuthEventMap const& auth_events) -> EventAuthorizationDecision
{
    auto const* obj = value_is_object(event);
    if (obj == nullptr)
    {
        return make_denied("0", "event must be an object");
    }

    auto const* event_type = string_member(*obj, "type");
    if (event_type == nullptr || event_type->empty())
    {
        return make_denied("0", "missing event type");
    }
    auto const* sender = string_member(*obj, "sender");
    if (sender == nullptr || sender->empty())
    {
        return make_denied("0", "missing sender");
    }

    // Step 1: m.room.create allows if this is the first event (no create event in auth events)
    if (*event_type == "m.room.create")
    {
        if (value_has_content(auth_events.create))
        {
            return make_denied("1", "room already has a create event");
        }
        // Sub-rules 1.1-1.4 — prev_events, the room_id/sender relationship, the
        // declared room_version, and the creator fields. See
        // create_event_rejection_reason() for the per-version breakdown.
        if (auto const reason = create_event_rejection_reason(*obj, policy); !reason.empty())
        {
            return make_denied("1", reason);
        }
        return make_allowed("1");
    }

    // Step 2: All other events require a create event
    if (!value_has_content(auth_events.create))
    {
        return make_denied("2", "room has no create event");
    }

    // Step 3: For v6+ and v12, only reject cross-domain senders when the room
    // explicitly disables federation via content.m.federate = false. When m.federate
    // is absent or true the check does not apply and cross-domain senders are permitted.
    // Spec: Matrix Server-Server API v1.19 — Authorization Rules, Step 3.
    // URL: ../../docs/matrix-v1.19-spec/server-server-api.md#authorization-rules
    if (policy.auth_rules == rooms::AuthRules::room_v6_plus || policy.auth_rules == rooms::AuthRules::room_v12)
    {
        auto const* create_obj = value_is_object(auth_events.create);
        auto is_non_federated = false;
        if (create_obj != nullptr)
        {
            auto const* content = object_member_as_object(*create_obj, "content");
            if (content != nullptr)
            {
                auto const* federate_val = object_member(*content, "m.federate");
                if (federate_val != nullptr)
                {
                    auto const* federate_bool = std::get_if<bool>(&federate_val->storage());
                    is_non_federated = (federate_bool != nullptr && !*federate_bool);
                }
            }
        }

        if (is_non_federated)
        {
            auto const sender_domain = domain_of(*sender);
            // v6–v10 rooms store the creator in content.creator; v11+ rooms (including v12)
            // removed content.creator — use the create event's sender field as the fallback.
            auto const* content_creator = event_content_string(auth_events.create, "creator");
            std::string_view creator_domain_src;
            if (content_creator != nullptr)
            {
                creator_domain_src = *content_creator;
            }
            else if (create_obj != nullptr)
            {
                auto const* create_sender = string_member(*create_obj, "sender");
                if (create_sender != nullptr)
                {
                    creator_domain_src = *create_sender;
                }
            }
            if (creator_domain_src.empty())
            {
                return make_denied("3", "create event has no identifiable creator");
            }
            if (sender_domain != domain_of(creator_domain_src))
            {
                return make_denied("3", "sender domain does not match creator domain");
            }
        }
    }

    // Steps 4-9: m.room.member events
    if (*event_type == "m.room.member")
    {
        auto const* state_key = string_member(*obj, "state_key");
        if (state_key == nullptr || state_key->empty())
        {
            return make_denied("4", "m.room.member requires a state_key");
        }

        auto const content_membership = extract_content_membership(event);
        auto const requested_opt = parse_membership_state(content_membership);
        if (!requested_opt.has_value())
        {
            return make_denied("4", "membership value is unrecognized");
        }
        auto const requested = *requested_opt;

        auto const target_is_sender = *sender == *state_key;

        auto sender_current_membership = MembershipState::leave;
        if (value_has_content(auth_events.sender_member))
        {
            sender_current_membership = parse_membership_state(extract_content_membership(auth_events.sender_member))
                                            .value_or(MembershipState::leave);
        }

        auto target_current_membership = MembershipState::leave;
        if (target_is_sender && value_has_content(auth_events.sender_member))
        {
            target_current_membership = parse_membership_state(extract_content_membership(auth_events.sender_member))
                                            .value_or(MembershipState::leave);
        }
        else if (value_has_content(auth_events.target_member))
        {
            target_current_membership = parse_membership_state(extract_content_membership(auth_events.target_member))
                                            .value_or(MembershipState::leave);
        }

        // Step 5: For join, sender must equal state_key (v6+)
        if (requested == MembershipState::join && !target_is_sender)
        {
            return make_denied("5", "cannot force another user to join");
        }

        // Step 5 continued: A user can join if they are joined already (re-join accepted)
        if (requested == MembershipState::join && target_is_sender)
        {
            if (target_current_membership == MembershipState::ban)
            {
                return make_denied("5", "banned user cannot join");
            }

            // Matrix auth rule: the room creator's initial join is allowed when
            // the only prior state is m.room.create — i.e. they have no existing
            // membership event yet. This bootstraps every room before join rules
            // or power levels exist.
            if (!value_has_content(auth_events.sender_member) && !value_has_content(auth_events.target_member))
            {
                auto const* creator = event_content_string(auth_events.create, "creator");
                if (creator != nullptr && *creator == *sender)
                {
                    return make_allowed("5");
                }
            }

            // Check join rules
            auto join_rule = std::string{"invite"};
            if (value_has_content(auth_events.join_rules))
            {
                auto const* rule = event_content_string(auth_events.join_rules, "join_rule");
                if (rule != nullptr)
                {
                    join_rule = *rule;
                }
            }

            if (join_rule == "public")
            {
                return make_allowed("5");
            }

            // invite join rule: user must be invited or already joined
            if (join_rule == "invite")
            {
                if (membership_at_least_one_of(target_current_membership,
                                               {MembershipState::invite, MembershipState::join}))
                {
                    return make_allowed("5");
                }
                return make_denied("5", "user was not invited to this invite-only room");
            }

            // knock join rule: knocked users can join if invited
            if (join_rule == "knock")
            {
                if (membership_at_least_one_of(target_current_membership,
                                               {MembershipState::invite, MembershipState::join}))
                {
                    return make_allowed("5");
                }
                return make_denied("5", "user was not invited to knock-restricted room");
            }

            // restricted / restricted_v2 join rules
            if (join_rule == "restricted" || join_rule == "restricted_v2")
            {
                if (membership_at_least_one_of(target_current_membership,
                                               {MembershipState::invite, MembershipState::join}))
                {
                    return make_allowed("5");
                }
                auto const* authorising_user = event_content_string(event, "join_authorised_via_users_server");
                if (authorising_user == nullptr || authorising_user->empty())
                {
                    return make_denied("5", "restricted join requires join_authorised_via_users_server");
                }
                auto const* authorising_member_obj = value_is_object(auth_events.authorising_user_member);
                if (authorising_member_obj == nullptr)
                {
                    return make_denied("5", "restricted join missing authorising user membership");
                }
                auto const* authorising_state_key = string_member(*authorising_member_obj, "state_key");
                if (authorising_state_key == nullptr || *authorising_state_key != *authorising_user)
                {
                    return make_denied("5", "restricted join authorising user does not match membership event");
                }
                if (parse_membership_state(extract_content_membership(auth_events.authorising_user_member)) !=
                    MembershipState::join)
                {
                    return make_denied("5", "restricted join authorising user is not joined");
                }
                auto const invite_power = value_has_content(auth_events.power_levels)
                                              ? extract_power_level_key(auth_events.power_levels, "invite", 0,
                                                                        !policy.power_levels_require_integers)
                                              : 0;
                auto const authorising_power =
                    effective_sender_power(auth_events.power_levels, *authorising_user, auth_events.create, policy);
                if (authorising_power < invite_power)
                {
                    return make_denied("5", "restricted join authorising user lacks invite power");
                }
                return make_allowed("5");
            }

            return make_denied("5", "unknown join rule");
        }

        // Step 5: knock membership — Spec § Authorization Rules, rule 5.
        // ../../docs/matrix-v1.19-spec/server-server-api.md#authorization-rules
        // A knock event is only valid when:
        //   • sender == state_key (cannot knock for someone else)
        //   • sender is not banned
        //   • sender is not already joined or invited
        //   • the room join_rule is "knock" or "knock_restricted"
        if (requested == MembershipState::knock)
        {
            if (!target_is_sender)
            {
                return make_denied("5", "cannot knock on behalf of another user");
            }
            if (target_current_membership == MembershipState::ban)
            {
                return make_denied("5", "banned user cannot knock");
            }
            if (membership_at_least_one_of(target_current_membership, {MembershipState::join, MembershipState::invite}))
            {
                return make_denied("5", "already joined or invited user cannot knock");
            }

            auto knock_join_rule = std::string{"invite"};
            if (value_has_content(auth_events.join_rules))
            {
                auto const* rule = event_content_string(auth_events.join_rules, "join_rule");
                if (rule != nullptr)
                {
                    knock_join_rule = *rule;
                }
            }
            if (knock_join_rule == "knock" || knock_join_rule == "knock_restricted")
            {
                return make_allowed("5");
            }
            return make_denied("5", "join_rule does not permit knocking");
        }

        // Step 6: invites
        if (requested == MembershipState::invite)
        {
            // Rule 4.3.1: a 3PID-token invite is a fully self-contained decision —
            // it replaces (does not supplement) the normal invite checks below.
            auto const* content_obj = object_member_as_object(*obj, "content");
            auto const* third_party_invite_value =
                content_obj == nullptr ? nullptr : object_member(*content_obj, "third_party_invite");
            if (third_party_invite_value != nullptr && value_is_object(*third_party_invite_value) != nullptr)
            {
                return authorize_third_party_invite(*third_party_invite_value, *state_key, *sender,
                                                    target_current_membership, auth_events.third_party_invite);
            }

            // Target must not be currently joined or banned
            if (target_current_membership == MembershipState::join)
            {
                return make_denied("6", "cannot invite already-joined user");
            }
            if (target_current_membership == MembershipState::ban)
            {
                return make_denied("6", "cannot invite banned user");
            }

            // Sender must be joined
            if (sender_current_membership != MembershipState::join)
            {
                return make_denied("6", "inviter must be joined");
            }

            // Check invite power level
            auto const invite_power = value_has_content(auth_events.power_levels)
                                          ? extract_power_level_key(auth_events.power_levels, "invite", 0,
                                                                    !policy.power_levels_require_integers)
                                          : 0;
            auto const sender_power =
                effective_sender_power(auth_events.power_levels, *sender, auth_events.create, policy);
            if (sender_power < invite_power)
            {
                return make_denied("6", "insufficient power to invite");
            }

            return make_allowed("6");
        }

        // Step 7: leave
        if (requested == MembershipState::leave)
        {
            if (target_is_sender)
            {
                // Self-leave is allowed if and only if the user's current membership is
                // invite, join, or knock. A banned or already-left user cannot self-leave
                // (that would let a banned user unban themselves).
                if (membership_at_least_one_of(
                        target_current_membership,
                        {MembershipState::invite, MembershipState::join, MembershipState::knock}))
                {
                    return make_allowed("7");
                }
                return make_denied("7", "self-leave requires current membership of invite, join, or knock");
            }

            // Kicking (or unbanning) another user
            if (sender_current_membership != MembershipState::join)
            {
                return make_denied("7", "kicker must be joined");
            }

            auto const sender_power =
                effective_sender_power(auth_events.power_levels, *sender, auth_events.create, policy);

            // Spec rule 5.3: unbanning is just a "leave" targeting a banned user, not
            // a separate branch — if the target is banned, the sender additionally
            // needs at least the ban level before rule 5.4 is even considered.
            if (target_current_membership == MembershipState::ban)
            {
                auto const ban_power = value_has_content(auth_events.power_levels)
                                           ? extract_power_level_key(auth_events.power_levels, "ban", 50,
                                                                     !policy.power_levels_require_integers)
                                           : 50;
                if (sender_power < ban_power)
                {
                    return make_denied("7", "insufficient power to unban");
                }
            }

            // Spec rule 5.4: kick (and the remaining unban check) requires the
            // sender's power to be at least the kick level AND strictly greater
            // than the target's own power level.
            auto const kick_power = value_has_content(auth_events.power_levels)
                                        ? extract_power_level_key(auth_events.power_levels, "kick", 50,
                                                                  !policy.power_levels_require_integers)
                                        : 50;
            auto const target_power =
                effective_sender_power(auth_events.power_levels, *state_key, auth_events.create, policy);
            if (sender_power >= kick_power && target_power < sender_power)
            {
                return make_allowed("7");
            }

            return make_denied("7", "insufficient power to kick or unban target");
        }

        // Step 8: ban
        if (requested == MembershipState::ban)
        {
            if (sender_current_membership != MembershipState::join)
            {
                return make_denied("8", "banner must be joined");
            }

            // Spec rule 6.2: ban requires the sender's power to be at least the ban
            // level AND strictly greater than the target's own power level.
            auto const ban_power = value_has_content(auth_events.power_levels)
                                       ? extract_power_level_key(auth_events.power_levels, "ban", 50,
                                                                 !policy.power_levels_require_integers)
                                       : 50;
            auto const sender_power =
                effective_sender_power(auth_events.power_levels, *sender, auth_events.create, policy);
            auto const target_power =
                effective_sender_power(auth_events.power_levels, *state_key, auth_events.create, policy);
            if (sender_power >= ban_power && target_power < sender_power)
            {
                return make_allowed("8");
            }

            return make_denied("8", "insufficient power to ban");
        }

        // Unknown membership
        return make_denied("4", "unsupported membership type");
    }

    // Step 10: sender must be in the room (joined)
    auto sender_membership = MembershipState::leave;
    if (value_has_content(auth_events.sender_member))
    {
        sender_membership = parse_membership_state(extract_content_membership(auth_events.sender_member))
                                .value_or(MembershipState::leave);
    }
    else
    {
        auto const* creator = event_content_string(auth_events.create, "creator");
        if (creator != nullptr && *sender == *creator)
        {
            sender_membership = MembershipState::join;
        }
    }
    if (sender_membership != MembershipState::join)
    {
        return make_denied("10", "sender is not joined to the room");
    }

    // Step 6 (spec numbering): m.room.third_party_invite is gated on the room's
    // invite power level specifically, not the generic state_default power used
    // by other state events at step 13 below.
    // Spec: rooms/v11.md Authorization rules, "6. If type is
    // m.room.third_party_invite: allow if and only if sender's current power
    // level is greater than or equal to the invite level."
    if (*event_type == "m.room.third_party_invite")
    {
        auto const invite_power =
            value_has_content(auth_events.power_levels)
                ? extract_power_level_key(auth_events.power_levels, "invite", 0, !policy.power_levels_require_integers)
                : 0;
        auto const sender_power = effective_sender_power(auth_events.power_levels, *sender, auth_events.create, policy);
        if (sender_power < invite_power)
        {
            return make_denied("6", "insufficient power to create a third-party invite");
        }
        return make_allowed("6");
    }

    // Step 11: check power levels for the event type
    auto const sender_power = effective_sender_power(auth_events.power_levels, *sender, auth_events.create, policy);

    auto const* state_key = string_member(*obj, "state_key");
    auto const is_state_event = state_key != nullptr;

    // Spec rule 8: "If the event has a state_key that starts with an @ and does
    // not match the sender, reject." m.room.member is not reached here — it
    // returns from its own branch above, exactly as the spec's rule 5 does — so
    // this governs every other state event type. Without it any member holding
    // state_default could write state keyed to another user's MXID, which
    // clients routinely read as "authored by that user".
    // Spec: ../../docs/matrix-v1.19-spec/rooms/v11.md — Authorization rules, rule 8.
    if (is_state_event && state_key->starts_with('@') && *state_key != *sender)
    {
        return make_denied("8", "state_key belongs to another user");
    }

    if (*event_type == "m.room.power_levels")
    {
        auto const pl_sender_power =
            effective_sender_power(auth_events.power_levels, *sender, auth_events.create, policy);

        auto const* content_obj = object_member_as_object(*obj, "content");
        if (content_obj == nullptr)
        {
            return make_denied("11", "m.room.power_levels requires a content object");
        }

        // Rules 9.1, 9.2 and 9.3 — structural validation, applied before any
        // comparison so a malformed event is rejected outright rather than
        // having its unreadable keys silently treated as absent.
        if (auto const reason = power_levels_content_rejection_reason(*content_obj, policy); !reason.empty())
        {
            return make_denied("11", reason);
        }

        auto const* new_users = object_member_as_object(*content_obj, "users");

        // v12/MSC4289: a room creator's power is effectively infinite and cannot be
        // expressed as an integer in content.users. Any m.room.power_levels event that
        // lists a creator (the create-event sender or any additional_creators member)
        // in content.users MUST be rejected.
        // Spec: ../../docs/matrix-v1.19-spec/rooms/v12.md
        if (policy.privilege_room_creators && new_users != nullptr)
        {
            for (auto const& user_entry : *new_users)
            {
                if (user_is_room_creator(auth_events.create, user_entry.key, policy))
                {
                    return make_denied("11", "creator cannot be specified in m.room.power_levels content.users");
                }
            }
        }

        // For m.room.power_levels, the sender must have the level to change each key.
        // Check that the sender can set the new event's content power levels.
        if (value_has_content(auth_events.power_levels))
        {
            auto const* old_event_obj = value_is_object(auth_events.power_levels);
            auto const* old_content =
                old_event_obj == nullptr ? nullptr : object_member_as_object(*old_event_obj, "content");
            auto const old_users = old_content == nullptr ? nullptr : object_member_as_object(*old_content, "users");

            if (old_content != nullptr)
            {
                // Rule 9.5 — every alteration of users_default, events_default,
                // state_default, ban, redact, kick or invite is bounded by the
                // sender's power in BOTH directions. This is the check whose
                // absence let a moderator set users_default to 100 and take the
                // room (#487).
                auto const allow_strings = !policy.power_levels_require_integers;
                if (auto const reason =
                        scalar_power_level_rejection_reason(*old_content, *content_obj, pl_sender_power, allow_strings);
                    !reason.empty())
                {
                    return make_denied("11", reason);
                }

                // Rules 9.6 and 9.7 — the same two-sided bound for each entry of
                // the bounded maps, so the bar for sending m.room.power_levels
                // itself cannot be lowered from beneath it. `notifications` is
                // only one of those maps from room version 6 onwards.
                for (auto const& map_key : bounded_power_level_maps(policy))
                {
                    if (auto const reason = power_level_map_rejection_reason(*old_content, *content_obj, map_key,
                                                                             pl_sender_power, allow_strings);
                        !reason.empty())
                    {
                        return make_denied("11", reason);
                    }
                }
            }

            // Spec v1.19 authorization rules 9.8 and 9.9 (room v12):
            //   9.9 — For each entry added to or changed in content.users: if the new
            //         value is greater than the sender's current power level, reject.
            //         Unlike 9.8 there is NO "other than the sender's own entry"
            //         carve-out, so the sender cannot self-elevate (#273).
            //   9.8 — For each entry changed in or removed from content.users, other
            //         than the sender's own entry: if the current (old) value is
            //         greater than or equal to the sender's current power level,
            //         reject. This covers removal (key absent from the new event) and
            //         uses ">=" so demoting an equal-power peer is also rejected (#274).
            // An entry is "added or changed" when absent from the old event or when its
            // new integer value differs from the old; "changed or removed" when absent
            // from the new event or when its value differs from the old.
            if (new_users != nullptr)
            {
                for (auto const& user_entry : *new_users)
                {
                    auto const new_level =
                        power_level_value(user_entry.value.get(), !policy.power_levels_require_integers);
                    if (!new_level.has_value())
                    {
                        continue;
                    }
                    auto const old_level = old_users == nullptr
                                               ? -1
                                               : extract_user_level_from_users(*old_users, user_entry.key,
                                                                               !policy.power_levels_require_integers);
                    auto const added_or_changed = (old_level < 0) || (*new_level != old_level);
                    // Rule 9.9 — applies to the sender's own entry too (no self-exemption).
                    if (added_or_changed && *new_level > pl_sender_power)
                    {
                        return make_denied("11", "cannot elevate user above own power level");
                    }
                }
            }
            if (old_users != nullptr)
            {
                for (auto const& old_entry : *old_users)
                {
                    if (old_entry.key == *sender)
                    {
                        continue; // Rule 9.8 exempts the sender's own entry.
                    }
                    auto const old_level =
                        extract_user_level_from_users(*old_users, old_entry.key, !policy.power_levels_require_integers);
                    if (old_level < 0)
                    {
                        continue;
                    }
                    auto const new_level =
                        new_users == nullptr
                            ? std::optional<std::int64_t>{}
                            : power_level_member(*new_users, old_entry.key, !policy.power_levels_require_integers);
                    auto const removed = !new_level.has_value();
                    auto const changed = !removed && (*new_level != old_level);
                    if ((removed || changed) && old_level >= pl_sender_power)
                    {
                        return make_denied("11",
                                           "cannot change or remove power level of user at or above own power level");
                    }
                }
            }
        }

        // Deliberately stricter than spec rule 9.4, which allows any event when the
        // room has no previous m.room.power_levels. Our AuthEventMap is built from
        // this server's own resolved state rather than from the event's declared
        // auth_events, so "no previous power_levels" can also mean "we have not
        // got that state yet" — under which a blanket allow would be a fail-open.
        // Requiring the default state_default (50) instead keeps the room-creation
        // bootstrap working (the creator resolves to 100, or infinite under v12)
        // while denying an ordinary joined member. This is pre-existing behaviour,
        // retained knowingly; it can only reject where the spec would allow, never
        // the reverse. See docs/event-engine.md.
        auto const state_default = value_has_content(auth_events.power_levels)
                                       ? extract_power_level_key(auth_events.power_levels, "state_default", 50,
                                                                 !policy.power_levels_require_integers)
                                       : 50;
        if (pl_sender_power < state_default)
        {
            return make_denied("11", "insufficient power to send power_levels event");
        }

        return make_allowed("11");
    }

    // m.room.redaction is NOT authorized against the "redact" or "ban" power
    // levels — that pair only governs whether an *already-authorized* redaction
    // is applied to its target (see docs/matrix-v1.19-spec/server-server-api.md
    // #redactions). Authorization-wise a redaction is just another non-state
    // message event, so it falls through to the generic events[type]/events_default
    // check at step 14 below (rule 14 keys on event_type, "m.room.redaction"
    // included).

    // Step 13: state events require state_default power
    if (is_state_event)
    {
        auto const state_default = value_has_content(auth_events.power_levels)
                                       ? extract_power_level_key(auth_events.power_levels, "state_default", 50,
                                                                 !policy.power_levels_require_integers)
                                       : 50;

        // Check per-event-type power level in events map
        auto const events_state_level = value_has_content(auth_events.power_levels) ? [&]() -> std::int64_t {
            auto const* pl_obj = value_is_object(auth_events.power_levels);
            if (pl_obj == nullptr)
            {
                return state_default;
            }
            auto const* pl_content = object_member_as_object(*pl_obj, "content");
            if (pl_content == nullptr)
            {
                return state_default;
            }
            auto const* events = object_member_as_object(*pl_content, "events");
            if (events == nullptr)
            {
                return state_default;
            }
            auto const* level = integer_member(*events, *event_type);
            return level != nullptr ? *level : state_default;
        }()
            : state_default;

        if (sender_power < events_state_level)
        {
            return make_denied("13", "insufficient power for state event");
        }

        return make_allowed("13");
    }

    // Step 14: message events
    auto const events_default = value_has_content(auth_events.power_levels)
                                    ? extract_power_level_key(auth_events.power_levels, "events_default", 0,
                                                              !policy.power_levels_require_integers)
                                    : 0;

    auto const events_message_level = value_has_content(auth_events.power_levels) ? [&]() -> std::int64_t {
        auto const* pl_obj = value_is_object(auth_events.power_levels);
        if (pl_obj == nullptr)
        {
            return events_default;
        }
        auto const* pl_content = object_member_as_object(*pl_obj, "content");
        if (pl_content == nullptr)
        {
            return events_default;
        }
        auto const* events = object_member_as_object(*pl_content, "events");
        if (events == nullptr)
        {
            return events_default;
        }
        auto const* level = integer_member(*events, *event_type);
        return level != nullptr ? *level : events_default;
    }()
        : events_default;

    if (sender_power < events_message_level)
    {
        return make_denied("14", "insufficient power for message event");
    }

    return make_allowed("14");
}

auto select_auth_events(EventAuthorizationRequest const& request) -> AuthEventSelection
{
    auto selection = AuthEventSelection{};

    // v12 (MSC4291): the create event is implicit in the room ID and MUST NOT be
    // listed in auth_events. For all earlier room versions create is always required.
    // Spec: ../../docs/matrix-v1.19-spec/rooms/v12.md
    auto const* policy = rooms::find_room_version_policy(request.room_version);
    auto const create_is_implicit = (policy != nullptr && policy->create_event_is_room_id);

    if (!create_is_implicit)
    {
        selection.required.push_back({AuthEventKind::create, "m.room.create", ""});
    }

    if (requires_power_levels(request.event_type))
    {
        selection.required.push_back({AuthEventKind::power_levels, "m.room.power_levels", ""});
    }
    if (request.event_type == "m.room.member")
    {
        selection.required.push_back({AuthEventKind::join_rules, "m.room.join_rules", ""});
        selection.required.push_back({AuthEventKind::member, "m.room.member", request.state_key});
    }
    if (request.membership.third_party_invite)
    {
        selection.required.push_back(
            {AuthEventKind::third_party_invite, "m.room.third_party_invite", request.state_key});
    }

    return selection;
}

auto auth_event_kind_name(AuthEventKind kind) noexcept -> char const*
{
    switch (kind)
    {
    case AuthEventKind::create:
        return "create";
    case AuthEventKind::power_levels:
        return "power_levels";
    case AuthEventKind::join_rules:
        return "join_rules";
    case AuthEventKind::member:
        return "member";
    case AuthEventKind::third_party_invite:
        return "third_party_invite";
    }

    return "unknown";
}

auto auth_chain_contains(AuthChain const& chain, std::string_view event_id) noexcept -> bool
{
    return std::ranges::any_of(chain.event_ids, [event_id](std::string const& existing) {
        return existing == event_id;
    });
}

auto append_auth_chain_event(AuthChain& chain, std::string_view event_id) -> void
{
    if (!event_id.empty() && !auth_chain_contains(chain, event_id))
    {
        chain.event_ids.push_back(std::string{event_id});
    }
}

} // namespace merovingian::events
