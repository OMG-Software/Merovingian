-- merovingian-migration version=4 name=livekit_delegations direction=upgrade
-- statement create_livekit_delegations
CREATE TABLE "livekit_delegations" (delay_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, room_id TEXT NOT NULL, slot_id TEXT NOT NULL, member_id TEXT NOT NULL, created_ms TEXT NOT NULL)
-- statement create_idx_livekit_delegations_user_id
CREATE INDEX idx_livekit_delegations_user_id ON livekit_delegations (user_id)
