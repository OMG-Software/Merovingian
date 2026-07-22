// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/signable.hpp"

#include <algorithm>
#include <utility>
#include <variant>

namespace merovingian::canonicaljson
{

auto make_signable_object_view(Value const& value) -> SerializeResult
{
    // Spec (appendices — Signing JSON): the object is signed with the
    // top-level `signatures` and `unsigned` keys removed, then canonicalised.
    // Eliding them here (#430) makes this helper safe to call on a fully
    // populated event, matching src/canonicaljson/AGENTS.md.
    if (auto const* object = std::get_if<Object>(&value.storage()); object != nullptr)
    {
        auto stripped = *object;
        std::erase_if(stripped, [](ObjectMember const& member) {
            return member.key == "signatures" || member.key == "unsigned";
        });
        // Signing-scoped: canonical JSON MUST NOT contain floats in
        // signed/hashed data, so this fails closed on a Value tree containing
        // a double (see serializer.hpp's serialize_canonical_strict).
        return serialize_canonical_strict(Value{std::move(stripped)});
    }
    return serialize_canonical_strict(value);
}

} // namespace merovingian::canonicaljson
