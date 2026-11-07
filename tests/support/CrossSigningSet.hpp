// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "CrossSigningKeyPair.hpp"

#include <string>

namespace merovingian::tests
{

// A user's three cross-signing keys: the master key unsigned, the self-signing and user-signing keys signed
// by the master key. Each key's JSON is a complete `CrossSigningKey` object.
struct CrossSigningSet final
{
    std::string user_id{};
    CrossSigningKeyPair master{};
    CrossSigningKeyPair self_signing{};
    CrossSigningKeyPair user_signing{};
    std::string master_json{};
    std::string self_signing_json{};
    std::string user_signing_json{};

    [[nodiscard]] auto master_member() const -> std::string
    {
        return R"("master_key":)" + master_json;
    }

    [[nodiscard]] auto self_signing_member() const -> std::string
    {
        return R"("self_signing_key":)" + self_signing_json;
    }

    [[nodiscard]] auto user_signing_member() const -> std::string
    {
        return R"("user_signing_key":)" + user_signing_json;
    }

    // The chosen keys' members, comma separated, for a request body without braces.
    [[nodiscard]] auto selected_members(bool master_key, bool self_signing_key, bool user_signing_key) const
        -> std::string
    {
        auto members = std::string{};
        auto const add = [&members](bool wanted, std::string member) {
            if (wanted)
            {
                members += (members.empty() ? "" : ",") + member;
            }
        };
        add(master_key, master_member());
        add(self_signing_key, self_signing_member());
        add(user_signing_key, user_signing_member());
        return members;
    }

    // `"master_key":…,"self_signing_key":…,"user_signing_key":…` for a request body, without braces.
    [[nodiscard]] auto members() const -> std::string
    {
        return R"("master_key":)" + master_json + R"(,"self_signing_key":)" + self_signing_json +
               R"(,"user_signing_key":)" + user_signing_json;
    }
};

} // namespace merovingian::tests
