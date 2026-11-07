// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::auth
{

enum class KeyApiEndpoint
{
    upload_keys,
    query_keys,
    claim_keys,
    device_list_update,
    upload_cross_signing_keys,
    upload_signatures,
    get_key_backup_version,
    create_key_backup_version,
    update_key_backup_version,
    delete_key_backup_version,
    put_room_key_backup,
    put_room_key_backup_room,
    put_room_key_backup_batch,
    get_room_key_backup,
    delete_room_key_backup_room,
    delete_room_key_backup,
    get_key_backup_version_by_id,
    get_room_key_backup_batch,
    delete_room_key_backup_batch,
};

} // namespace merovingian::auth
