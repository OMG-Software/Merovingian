// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <map>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace merovingian::database
{
struct PersistentStore;
}

namespace merovingian::federation
{

// The display names of the devices of a set of users, read from `store.devices` in one pass. A key query
// names its users up front; building this once for them keeps the lookup for every published key off the
// device table, which holds every device on the server and is scanned under the runtime lock (work there is
// bounded by the request). Holds views into `store`, so it is valid only while `store.devices` is unchanged:
// build it inside the request and drop it with the response.
class DeviceDisplayNames final
{
public:
    DeviceDisplayNames(database::PersistentStore const& store, std::span<std::string_view const> users);

    // The device's display name, empty when it has none. std::nullopt when the lookup holds no row for the
    // device: it does not exist, or its user was not among those the lookup was built for.
    [[nodiscard]] auto find(std::string_view user_id, std::string_view device_id) const
        -> std::optional<std::string_view>;

private:
    std::map<std::pair<std::string_view, std::string_view>, std::string_view> names_{};
};

} // namespace merovingian::federation
