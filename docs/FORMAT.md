# BINATOR1 container format

Version 1. All integer fields are little-endian. The container stores the
original file bytes verbatim; packing and unpacking are byte-identical.

```
+--------------------------+ 0
| Header (64 bytes)        |
+--------------------------+ 64
| Metadata (UTF-8 JSON)    |  metadata_len bytes
+--------------------------+ payload_offset = 64 + metadata_len
| Payload (original bytes) |  payload_len bytes
+--------------------------+
| Trailer (36 bytes)       |
+--------------------------+ EOF
```

## Header (64 bytes)

| Offset | Size | Field | Value |
|-------:|-----:|-------|-------|
| 0 | 8 | magic | ASCII `BINATOR1` |
| 8 | 2 | version | `1` |
| 10 | 2 | flags | `0` (reserved) |
| 12 | 4 | header_size | `64` |
| 16 | 8 | payload_offset | `header_size + metadata_len` |
| 24 | 8 | payload_len | payload bytes |
| 32 | 4 | metadata_len | metadata JSON bytes |
| 36 | 4 | header_crc32 | CRC32 of header bytes `0..36` |
| 40 | 24 | reserved | zero |

## Metadata

UTF-8 JSON object. Unknown fields must be ignored by readers.

```json
{
  "source_name": "disk.img",
  "source_size": 4096,
  "kind": "disk_image",
  "mime": "application/octet-stream",
  "note": null,
  "created_unix_ms": 1793982608916,
  "tool": "bin-inator",
  "tool_version": "0.1.0"
}
```

`source_name` is a file name, not a path. Unpack uses only its final path
component and replaces characters that are invalid on Windows.

## Trailer (36 bytes)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 4 | CRC32 of the payload |
| 4 | 32 | SHA-256 of the payload |

## Validation rules

A reader must reject a container when:

- the file is smaller than `64 + 36` bytes;
- the magic is not `BINATOR1`;
- the version is not `1`;
- `header_size < 64`;
- the header CRC32 does not match;
- `metadata_len > 16 MiB`;
- `payload_offset != header_size + metadata_len`;
- the file size is not exactly `payload_offset + payload_len + 36`;
- metadata is not valid JSON;
- the trailer CRC32 or SHA-256 does not match the payload.

Unpacking must stream the payload and verify both checksums before publishing
the output file. A checksum failure must leave no output behind.

## Limits

- `metadata_len` is capped at 16 MiB.
- Payload length is a `u64`; the implementation streams in 1 MiB chunks.
- `flags` is reserved for future compression/encryption; version 1 requires
  `flags == 0` on write and readers currently ignore it.
