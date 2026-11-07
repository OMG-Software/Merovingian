# Media downloads are streamed from the database in chunks

* Status: accepted; supersedes the "single in-memory blob copy" part of [ADR-0113](0113-default-media-quotas-and-single-blob-copy.md)
* Deciders: James Chapman
* Date: 2026-11-07

Technical Story: analysis finding P15b, media is buffered whole for every transfer.

## Context and Problem Statement

Since [ADR-0119](0119-media-bytes-live-in-the-database-and-are-read-on-demand.md) media bytes are read from
`media_blobs.bytes` on demand, but each download still read the whole file into one `std::string`, wrapped it in
`content_type|bytes`, copied it into the response and copied it again into the formatted HTTP message. A file can be
50 MiB, so a handful of concurrent downloads cost hundreds of MiB. How is a download sent with memory bounded by a
constant instead of the file size, without holding a database connection while a slow client reads?

## Decision Drivers

* Memory per transfer must not grow with the file.
* A client that stops reading must not hold a database connection, a read transaction or the runtime mutex.
* Headers, MIME and quarantine checks must happen exactly as before, before the first byte.
* SQLite is opened rollback-journal only (ADR-0157); a long read transaction would block every writer.

## Considered Options

* Hold one database connection and blob handle open for the whole transfer.
* Read the whole file first, then write it (the old behaviour).
* Read one chunk per short-lived connection and write it before reading the next.

## Decision Outcome

Chosen option: "one chunk per short-lived connection". A download of a file larger than
`database::media_blob_chunk_bytes` (256 KiB) on a database backend returns `OperationResult::body_stream` /
`LocalHttpResponse::body_stream` (a `MediaBodyStream`: a `MediaBlobRead` captured under the runtime mutex, and the
stored `size_bytes`) with an empty body. `http_server.cpp::write_response` sends the head with
`Content-Length: size_bytes`, then `write_streamed_body` reads a chunk with `database::read_media_blob_chunk` and
writes it, one at a time, with no runtime lock held. The write timeouts of the connection stream apply to every
chunk. A file of one chunk or less, and the memory backend, are read whole as before (still at most one chunk).

* SQLite: `sqlite3_blob_open` / `sqlite3_blob_read` on a fresh read-only connection inside a deferred transaction;
  the connection is closed (rolling back) before the chunk is written. The row is selected with a bound `storage_id`
  and `ref_count <> '0'`, and the blob length must equal the promised length. Statement preparation and the first
  step use the ADR-0159 retry.
* PostgreSQL: `substring(bytes from $2::bigint + 1 for $3::bigint)` with bound parameters, plus `octet_length(bytes)`
  in the same statement, on a fresh connection per chunk.

Why the blob cannot change mid-stream unnoticed: a stored blob's bytes are written once, under its content-hash
`storage_id`. The only later write to `bytes` is moderation/release, which sets `ref_count` to 0 and replaces the bytes.
Every chunk read re-checks `ref_count` and the exact length, so a removal during a transfer fails the next chunk read.
The status line is already sent then, so the connection is closed and `response.stream_read_failed` is logged. A
quarantine that changes only the record, not the blob, does not stop a transfer already started; that is the same as a
request answered just before the quarantine.

### Negative Consequences

* A connection (SQLite open, PostgreSQL connect and authenticate) per 256 KiB chunk, so a 50 MiB file costs about 200
  of them. Holding one open would be cheaper and is rejected: it pins a read lock (SQLite) or a backend (PostgreSQL)
  for as long as a client is slow.
* PostgreSQL `substring()` on a compressed TOASTed value detaches the whole value per chunk. The column's storage
  would need to be `EXTERNAL` to slice cheaply; that is a schema change left for later.
* Left buffered: thumbnails (the decoder needs the whole file), uploads, the federation media download (a multipart
  body that also crosses the worker IPC), and a remote media fetch's first response (the bytes just arrived over the
  network). A slow-drip client that accepts a byte inside each write timeout can still hold a request thread, as with
  any large response.

## Links

* Supersedes the in-memory copy decision of [ADR-0113](0113-default-media-quotas-and-single-blob-copy.md)
* Refines [ADR-0119](0119-media-bytes-live-in-the-database-and-are-read-on-demand.md)
