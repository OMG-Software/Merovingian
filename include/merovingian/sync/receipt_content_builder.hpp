// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <cstdint>
#include <map>
#include <string>

namespace merovingian::sync
{

// Builds the `content` of one room's `m.receipt` ephemeral event from stored receipts:
// {event_id: {receipt_type: {user_id: {"ts": N, "thread_id": T}}}}. Shared by `/sync` and
// sliding sync so both surfaces emit the same shape. The caller decides which receipts the
// viewer may see (receipt_visible_to, the ignore list) and adds only those.
//
// Spec (client-server-api.md, "Receipts"): a threaded receipt carries its `thread_id`
// ("main" or the thread root's event ID); an unthreaded one carries none. A user may hold an
// unthreaded and a threaded receipt of one type on the same event; the content has room for
// only one, so the receipt set most recently (highest stream_id) is the one delivered.
class ReceiptContentBuilder final
{
public:
    auto add(database::PersistentReceipt const& receipt) -> void;
    [[nodiscard]] auto empty() const noexcept -> bool;
    [[nodiscard]] auto build() const -> canonicaljson::Object;

private:
    struct Entry final
    {
        std::uint64_t ts{0U};
        std::string thread_id{};
        std::uint64_t stream_id{0U};
    };

    // event_id -> receipt_type -> user_id -> receipt
    std::map<std::string, std::map<std::string, std::map<std::string, Entry>>> index_{};
};

} // namespace merovingian::sync
