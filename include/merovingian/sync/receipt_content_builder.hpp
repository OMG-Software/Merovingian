// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

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
// only one, so `build()` delivers the receipt set most recently (highest stream_id).
//
// `build_per_thread()` does not have that limit: Spec: "receipts SHOULD be batched into one
// event per room and thread before delivering them to clients", so it returns one content
// object per categorisation (unthreaded first, then each `thread_id`), and a user's unthreaded
// and threaded receipts for one event each get their own event. `/sync` delivers those.
class ReceiptContentBuilder final
{
public:
    auto add(database::PersistentReceipt const& receipt) -> void;
    [[nodiscard]] auto empty() const noexcept -> bool;
    [[nodiscard]] auto build() const -> canonicaljson::Object;
    [[nodiscard]] auto build_per_thread() const -> std::vector<canonicaljson::Object>;

private:
    struct Entry final
    {
        std::uint64_t ts{0U};
        std::string thread_id{};
        std::uint64_t stream_id{0U};
    };

    // event_id -> receipt_type -> user_id -> receipt
    using Index = std::map<std::string, std::map<std::string, std::map<std::string, Entry>>>;

    static auto insert(Index& index, database::PersistentReceipt const& receipt) -> void;
    [[nodiscard]] static auto render(Index const& index) -> canonicaljson::Object;

    // Every receipt, whatever its thread: the content `build()` merges.
    Index index_{};
    // The same receipts apart by categorisation: "" is unthreaded, else the `thread_id`.
    std::map<std::string, Index> by_thread_{};
};

} // namespace merovingian::sync
