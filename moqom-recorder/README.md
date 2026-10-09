# moqom-recorder

The hosted MOQOM recorder. It joins a room through a relay as a viewer, using a
subscribe-only token bound to its own key. It follows the room's namespace,
reads each publisher's catalog, subscribes to every track listed, and writes
down what it receives.

It never publishes. The room learns that a recording is running from the
`recording` watchdog that the control plane attaches.

The full design is in `moqom/docs/RECORDING.md`: the lease, formats, encryption,
billing and deployment. This file covers the crate.

## Commands

```sh
moqom-recorder worker                   # claim recordings from the control plane and record them
moqom-recorder record --token-file T …  # record one room until interrupted, to --out DIR or --gcs-bucket B
moqom-recorder inspect FILE.mqa         # print an archive's records (--objects for every object)
moqom-recorder thumbprint KEY.pem       # print the key's JWK thumbprint (--generate makes the key first)
```

The worker is configured from the environment, which `deploy/modules/recorder`
sets:

| Variable | Purpose |
| --- | --- |
| `MOQOM_CONTROL` | The control plane's gRPC endpoint. |
| `MOQOM_CONTROL_SERVER_NAME` | The name expected on the control plane's certificate. |
| `MOQOM_CONTROL_CA` | The link authority, used to verify the control plane. |
| `MOQOM_CONTROL_TLS_CERT`, `MOQOM_CONTROL_TLS_KEY` | The worker's link client certificate and its key. |
| `MOQOM_CONTROL_CREDENTIAL_FILE` | The `is_recorder` account's credential. |
| `MOQOM_RELAY` | The relay to record through, as `host:port`. |
| `MOQOM_RELAY_NAME` | The relay's name. Defaults to the host part of `MOQOM_RELAY`. |
| `MOQOM_RELAY_CERT` | Pin the relay to this certificate instead of the system roots. |
| `MOQOM_RECORDER_KEY` | The ML-DSA-65 PKCS#8 key that the tokens are bound to. |
| `MOQOM_RECORDER_SPOOL` | Local directory where files are written before upload. |
| `MOQOM_RECORDER_SEGMENT_MIB` | Start a new file at the next group boundary past this size. |
| `MOQOM_WORKER_ID` | The worker's lease name: the pod's name. |

## What it writes

| Output | Contents |
| --- | --- |
| Archive (`.mqa`) | Always written. Every object exactly as it arrived, with markers for reconnects and departures. In an end-to-end encrypted room it is the only output, and it holds ciphertext. |
| CMAF (`.mp4`) | Written for rooms that are not encrypted, when the codec can be carried without transcoding (H.264, HEVC, Opus). |
| Manifest (`manifest-a{attempt}.json`) | One per attempt: tracks, counts, artifacts and their CRC32C, and how each track was joined. |

## Joining a room in progress

A subscription starts at the next group. Without a catch-up, a recorder that
joins mid-group would start every track part-way into the media. So:

- **Media tracks.** The first live object arrives at group `H`, object `k`. The
  recorder fetches the objects it missed from the relay's cache:
  - all of `H - 1` when `k` is 0;
  - objects `0` to `k - 1` of `H` otherwise.

  The fetch waits for that first object because a fetch sent when the
  subscription starts would stop at the live edge, and the rest of that group
  would be lost.
- **The catalog.** Fetched straight away, because an unchanged catalog is never
  sent again.

When the relay no longer holds the group, the track starts at the next group.
Each track's manifest entry has a `joins` list, one entry per session, that says
which case happened. The values are `track_start`, `caught_up`, `next_group` and
`mid_group`, and the fallback cases include a `reason`.

The client side of this is `Session::fetch` in `moqom-client`. It supports the
draft-19 joining fetch and standalone fetch, and draft-22's filtered fetch.

## Full rooms

Relays do not count the recorder against a room's ceiling, so a full room still
admits it and the recorder never takes a person's seat. A session counts as the
recorder only when both of these hold:

- its token's subject is `moqom-recorder`;
- it has no publish rights, no capabilities, and no owner, backstage or relay
  flag.

The check is `moqom_relay::scope::is_recorder`. A closed room still refuses the
recorder.

## Tests

```sh
cargo test -p moqom-recorder
```

`tests/record.rs` runs a relay in the same process and checks these cases:

- plaintext and encrypted rooms;
- a publisher leaving;
- catching up the group in flight;
- falling back to the next group when the relay keeps no cache;
- a full room that admits the recorder and still refuses a second person.

## Image

```sh
docker build -f Dockerfile.recorder -t moqom-recorder .   # from moqom-engine
```

For the dev deployment, see "Hosted recording in dev" in `moqom/deploy/README.md`.
