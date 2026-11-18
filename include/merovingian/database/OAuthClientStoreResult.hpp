// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::database
{

// What `store_oauth_client` did. `existing` wrote nothing: the row already held keeps its metadata and its
// `created_at_ms`. `refused` wrote nothing either: the row broke a cap or the transaction did not commit.
enum class OAuthClientStoreResult
{
    inserted,
    existing,
    refused,
};

} // namespace merovingian::database
