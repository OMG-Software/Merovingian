# Deleting a device deletes the to-device rows addressed to it, never the user's broadcast rows

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`delete_device` removed the device and its keys but left queued to-device messages, so a later login reusing the device ID
received room keys sent to the old device.

## Decision Outcome

The same transaction deletes the `to_device_messages` rows whose `target_user_id` and `target_device_id` name the device,
and the in-memory rows follow once it commits. Rows with an empty or `*` target device are the user's broadcast rows: they
are shared by all of the user's devices, were sent to every device that existed, and stay until their TTL or the
per-recipient cap removes them (as `drain_to_device_messages` already treats them). Deleting them would drop messages the
user's other devices have not yet received.
