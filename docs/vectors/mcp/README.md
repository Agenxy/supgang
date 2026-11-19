# MCP main-branch wire snapshots

These newline-delimited transcripts were captured from Supgang main at
`04000f70aa92d50829d48736ddfba01bb958b510`, before replacing rmcp 3.9.0.
Each `C:` line is the exact JSON line received from the client, and each `S:`
line is the exact JSON line Supgang emitted. The two-byte prefix is a fixture
direction marker and is not part of the wire message.

- `rmcp-3.9.0-client.ndjson`: the real rmcp SDK client used legacy
  `initialize` and then modern `server/discover`, followed by `tools/list`
  in each lifecycle. It uses empty temporary state and contains no key material.
- `status-call.ndjson`: one successful modern status call, plus rejected
  arguments.
- `fleet-call.ndjson`: successful status and fleet calls from local,
  initialized temporary state.
- `resolve-call.ndjson`: a modern resolve call for the fixed nonexistent
  selector `missing`, with its tool-level error result.

The successful status and fleet snapshots include fresh public test identifiers
generated during capture. Tests compare their stable wire shape and static
fields, while the SDK-client transcript is replayed byte-for-byte.
