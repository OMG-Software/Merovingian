-- merovingian-migration version=6 name=client_txn_dedup direction=upgrade
-- statement create_client_txn_ids
CREATE TABLE IF NOT EXISTS client_txn_ids (
    user_id    TEXT NOT NULL,
    room_id    TEXT NOT NULL,
    event_type TEXT NOT NULL,
    txn_id     TEXT NOT NULL,
    event_id   TEXT NOT NULL,
    PRIMARY KEY (user_id, room_id, event_type, txn_id)
)
