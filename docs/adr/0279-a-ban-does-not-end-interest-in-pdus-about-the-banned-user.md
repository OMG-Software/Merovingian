# A ban does not end this server's interest in PDUs about its banned user

* Status: accepted
* Date: 2026-10-29

Technical Story: Complement run 10 (`TestUnbanViaInvite`)

## Context and Problem Statement

Room-interest admission (FED-11) drops a PDU for a room in which this server has no joined, invited or
knocking user. Once a local user is banned, this server has none of those, so the unban that follows was
dropped as "unsolicited PDU for an uninterested room". The ban stayed on record and a later invite was
refused by "an invite never overwrites a ban".

## Decision Outcome

An `m.room.member` PDU about a local user who holds any membership row for the room is admitted to the
receipt checks (`concerns_local_member_with_row`). It is still verified and judged by the auth rules like
any other PDU; this only admits it to them. Narrowing the gate back to current members strands the ban.
A standing ban still refuses an invite.
