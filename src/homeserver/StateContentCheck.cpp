// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/StateContentCheck.hpp"

#include "merovingian/auth/Identity.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/rooms/EncryptionPolicy.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    [[nodiscard]] auto member_of(canonicaljson::Object const& object, std::string_view key) noexcept
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

    // Collects the aliases of a canonical-alias content: `alias` (absent, null or empty means none) and each entry
    // of `alt_aliases`. False when a field has the wrong type.
    [[nodiscard]] auto collect_aliases(canonicaljson::Object const& object, std::vector<std::string>& out) -> bool
    {
        if (auto const* alias = member_of(object, "alias"); alias != nullptr)
        {
            if (auto const* text = std::get_if<std::string>(&alias->storage()); text != nullptr)
            {
                if (!text->empty())
                {
                    out.push_back(*text);
                }
            }
            else if (!std::holds_alternative<std::nullptr_t>(alias->storage()))
            {
                return false;
            }
        }
        if (auto const* alt = member_of(object, "alt_aliases"); alt != nullptr)
        {
            if (auto const* array = std::get_if<canonicaljson::Array>(&alt->storage()); array != nullptr)
            {
                for (auto const& entry : *array)
                {
                    auto const* text = std::get_if<std::string>(&entry.storage());
                    if (text == nullptr)
                    {
                        return false;
                    }
                    out.push_back(*text);
                }
            }
            else if (!std::holds_alternative<std::nullptr_t>(alt->storage()))
            {
                return false;
            }
        }
        return true;
    }

    // The aliases the room's current canonical-alias event already lists.
    [[nodiscard]] auto aliases_already_present(database::PersistentStore const& store, std::string_view room_id)
        -> std::vector<std::string>
    {
        auto present = std::vector<std::string>{};
        if (room_id.empty())
        {
            return present;
        }
        auto const event_id = database::find_current_state_event_id(store, room_id, "m.room.canonical_alias", "");
        if (!event_id.has_value())
        {
            return present;
        }
        auto const event = store.events.find(*event_id);
        if (event == store.events.end())
        {
            return present;
        }
        auto const parsed = canonicaljson::parse_lossless(event->json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return present;
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        auto const* old_content_value = root == nullptr ? nullptr : member_of(*root, "content");
        auto const* old_content =
            old_content_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&old_content_value->storage());
        if (old_content != nullptr)
        {
            std::ignore = collect_aliases(*old_content, present);
        }
        return present;
    }

    // Only this server's directory can say where an alias points, so an alias on another server is judged for syntax
    // only: asking its server would be a client-triggered outbound call (ADR-0079) and the spec says SHOULD.
    [[nodiscard]] auto canonical_alias_refusal(database::PersistentStore const& store, std::string_view room_id,
                                               std::string_view local_server_name, canonicaljson::Object const& content,
                                               std::string_view pending_alias) -> std::optional<StateContentRefusal>
    {
        auto listed = std::vector<std::string>{};
        if (!collect_aliases(content, listed))
        {
            return StateContentRefusal{"M_INVALID_PARAM", "alias and alt_aliases must be room aliases"};
        }
        auto const present = aliases_already_present(store, room_id);
        auto const is_new = [&present](std::string const& alias) {
            return std::ranges::find(present, alias) == present.end();
        };

        for (auto const& alias : listed)
        {
            if (is_new(alias) && !auth::room_alias_is_valid(alias))
            {
                return StateContentRefusal{"M_INVALID_PARAM", "'" + alias + "' is not a valid room alias"};
            }
        }
        for (auto const& alias : listed)
        {
            if (!is_new(alias))
            {
                continue;
            }
            // room_alias_is_valid ended the localpart at the first ':', which the domain follows.
            if (std::string_view{alias}.substr(alias.find(':') + 1U) != local_server_name)
            {
                continue;
            }
            // The alias this request is creating: it points here as soon as the room exists.
            if (!pending_alias.empty() && alias == pending_alias)
            {
                continue;
            }
            auto const mapping = database::find_room_alias(store, alias);
            if (room_id.empty() || !mapping.has_value() || mapping->room_id != room_id)
            {
                return StateContentRefusal{"M_BAD_ALIAS", "The alias '" + alias + "' does not point to this room."};
            }
        }
        return std::nullopt;
    }

} // namespace

auto state_content_refusal(database::PersistentStore const& store, std::string_view room_id,
                           std::string_view local_server_name, std::string_view event_type, std::string_view state_key,
                           canonicaljson::Object const& content, std::string_view pending_alias)
    -> std::optional<StateContentRefusal>
{
    if (!state_key.empty())
    {
        return std::nullopt;
    }
    if (event_type == "m.room.canonical_alias")
    {
        return canonical_alias_refusal(store, room_id, local_server_name, content, pending_alias);
    }
    if (event_type == "m.room.encryption")
    {
        // Spec (m.room.encryption): `algorithm` is "Required", "One of: `[m.megolm.v1.aes-sha2]`". Local writers only:
        // federated events are not judged (ADR-0448).
        auto const* algorithm = member_of(content, "algorithm");
        auto const* text = algorithm == nullptr ? nullptr : std::get_if<std::string>(&algorithm->storage());
        if (text == nullptr || !rooms::encryption_algorithm_is_valid(*text))
        {
            return StateContentRefusal{"M_BAD_JSON", "m.room.encryption requires an algorithm of m.megolm.v1.aes-sha2"};
        }
    }
    return std::nullopt;
}

} // namespace merovingian::homeserver
