// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/receipt_content_builder.hpp"

#include <utility>

namespace merovingian::sync
{

auto ReceiptContentBuilder::add(database::PersistentReceipt const& receipt) -> void
{
    auto& users = index_[receipt.event_id][receipt.receipt_type];
    auto const existing = users.find(receipt.user_id);
    if (existing != users.end() && existing->second.stream_id > receipt.stream_id)
    {
        return;
    }
    users[receipt.user_id] = Entry{receipt.ts, receipt.thread_id, receipt.stream_id};
}

auto ReceiptContentBuilder::empty() const noexcept -> bool
{
    return index_.empty();
}

auto ReceiptContentBuilder::build() const -> canonicaljson::Object
{
    auto content = canonicaljson::Object{};
    for (auto const& [event_id, receipt_types] : index_)
    {
        auto types = canonicaljson::Object{};
        for (auto const& [receipt_type, users] : receipt_types)
        {
            auto user_members = canonicaljson::Object{};
            for (auto const& [user_id, entry] : users)
            {
                auto receipt = canonicaljson::Object{};
                if (!entry.thread_id.empty())
                {
                    receipt.push_back(canonicaljson::make_member("thread_id", canonicaljson::Value{entry.thread_id}));
                }
                receipt.push_back(
                    canonicaljson::make_member("ts", canonicaljson::Value{static_cast<std::int64_t>(entry.ts)}));
                user_members.push_back(canonicaljson::make_member(user_id, canonicaljson::Value{std::move(receipt)}));
            }
            types.push_back(canonicaljson::make_member(receipt_type, canonicaljson::Value{std::move(user_members)}));
        }
        content.push_back(canonicaljson::make_member(event_id, canonicaljson::Value{std::move(types)}));
    }
    return content;
}

} // namespace merovingian::sync
