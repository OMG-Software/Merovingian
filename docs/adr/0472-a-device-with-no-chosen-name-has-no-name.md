# A device that was given no display name has none; the device ID is never stored as its name

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

A login without `initial_device_display_name` stored the device ID as the device's display name (in memory; the database
row also held the ID). Other users then saw the ID as `unsigned.device_display_name`, and the real chosen name was never
persisted. The spec calls `device_display_name` "the display name which the user set on the device" and `display_name` of
`GET /devices` "absent if no name has been set".

## Decision Outcome

The chosen name is persisted with the device row at creation (`initial_device_display_name` is ignored for a known device).
With none given the name is the empty string, and `GET /devices`, `GET /devices/{id}`, `/keys/query` and the federation
device-list outputs leave the field out. Rejected: keeping the device ID as a visible fallback. It reads as a user's
choice to other users and makes clients show an opaque ID as a name.
