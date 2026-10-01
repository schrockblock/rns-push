# rns-push: a push-capable Reticulum hub — design

**Date:** 2026-10-01. **Scope:** a new Python package `rns-push` (own git repo at
`/Users/ell/development/python/rns-push`) that runs inside stock `rnsd` as an external interface
plugin and implements the hub side of the ReTiCA push design. **Counterpart:** the client design
`ReTiCaMsgr/docs/superpowers/specs/2026-10-01-push-relay-design.md` and the contract
`ReTiCAPush/docs/server-contract.md`, which this work revises (§7). **Depends on:** `rns` (PyPI,
stock), `h2`, `cryptography` (already an `rns` dependency).

## Goal

A Reticulum transport node that keeps a registered phone's TCP interface alive after its socket
dies, turns what it would have written to that socket into an APNs push, and routes the phone's
proof back to the sender, so a message sent to a sleeping ReTiCaMsgr user wakes them and the
sender gets an ordinary delivery proof. Success: a real device, socket down, is woken by APNs for
a message, and the sender's receipt goes DELIVERED.

Intended as an upstream candidate in plugin form: runs on stock RNS with no core changes, follows
RNS idioms (threads, `unittest`, `RNS.log`), adds no dependency to `rns` itself.

## Decisions taken while brainstorming

- **Packaging: pip package plus shim.** The RNS external-interface loader `exec`s a single file
  from `<configdir>/interfaces/<type>.py` with only `Interface` and `RNS` in its globals and reads
  `interface_class` (Reticulum.py:1060-1086). A one-line shim there imports the real classes from
  the installed `rns_push` package, which keeps normal modules, tests and declared dependencies.
- **APNs over `h2`.** APNs requires HTTP/2; the Python stdlib has none, and RNS itself only uses
  `urllib` (HTTP/1.1, in `rnodeconf`). `h2` is pure Python and small; the APNs client is a thin
  synchronous layer over one TLS socket, matching RNS's threads-not-asyncio style.
- **Registration over Reticulum, not HTTP.** The phone is already connected to the hub over
  Reticulum, and ReTiCA supports links, `identify` and requests (`LinkPlane.swift`,
  `LinkSession.swift`). Link identification authenticates the identity (no custom signing bytes,
  timestamps or replay window), the hub learns the exact interface to bind from the link, and the
  hub has no HTTP surface, TLS or proxy. This replaces contract §1; the contract stays labelled
  v1 (the client is still in development).
- **Proof return needs a redirect.** Stock RNS forwards a proof only when
  `packet.receiving_interface == reverse_entry[IDX_RT_OUTB_IF]` (Transport.py:2338-2347),
  popping the entry either way. The phone's proof arrives on a fresh spawned connection, not the
  dormant interface, so the plugin re-attributes it (§3.4). The original contract's claim that
  stock RNS routes proofs regardless of ingress was wrong.
- **Dormancy must keep the interface in `Transport.interfaces`.** The table cull (every 5 s)
  drops reverse, link and path entries whose interface is no longer in `Transport.interfaces`
  (Transport.py:686-801), and Transport never consults `.online`, only `.OUT`.
- **No IFAC on push hub interfaces.** A dormant interface must read the destination hash of the
  bytes it is handed, which IFAC masking hides. Configuring `ifac_*` on this interface is a
  startup error.
- **Known limits accepted for v1:** dormancy does not survive an rnsd restart, and a client's
  path expires after `DESTINATION_TIMEOUT` (one week) without a fresh announce. Pushing resumes
  when the app next connects and announces. Storing and replaying each client's last announce is
  the later fix.
- **APNs needs no hosted record.** Token auth is an ES256 JWT from the team's `.p8` key; the
  `apns-topic` must be a bundle id of that team. No domain verification is involved.

## 1. Package layout

```
rns-push/
  pyproject.toml            name "rns-push", requires-python >=3.8, deps: rns, h2
  rns_push/
    __init__.py
    packet.py               header parsing
    registry.py             Registry
    apns.py                 APNsClient, JWT signer
    dispatcher.py           PushDispatcher
    service.py              RegistrationService
    interface.py            PushTCPServerInterface, PushClientInterface
    cli.py                  `rns-push status`
  shim/PushTCPServerInterface.py
  tests/
    rnsconfig/              test RNS config (shared instance off, transport on), as in RNS's tests/
    test_packet.py  test_registry.py  test_apns.py  test_dispatcher.py
    test_service.py  test_interface.py  test_end_to_end.py
  docs/server-contract.md   copy of the revised contract (§7)
  README.md                 install, config, Apple key setup, limits
```

Shim:

```python
from rns_push.interface import PushTCPServerInterface
interface_class = PushTCPServerInterface
```

## 2. Components

### `packet.py`

`parse_header(raw: bytes) -> Header | None`. `Header` has `header_type` (1 or 2),
`packet_type` (DATA, ANNOUNCE, LINKREQUEST, PROOF), `ifac` (flag bit 0x80) and
`destination_hash` (16 bytes at `[2:18]` for HEADER_1, `[18:34]` for HEADER_2). Returns None
for input too short for its header type. Pure; constants taken from `RNS.Packet`.

### `registry.py` — `Registry`

- `Registration`: `destination_hash`, `identity_public_key` (64 bytes), `token` (bytes),
  `environment` (`"production"` | `"sandbox"`), `bundle_id`, `registered_at` (float).
- `Registry(path, clock=time.time)`: thread-safe (one lock).
  - `put(registration)` replaces any entry for the same destination hash, then persists.
  - `get(destination_hash)`, `remove(destination_hash) -> bool`, `all()`.
  - `expire() -> list[bytes]` removes entries with `registered_at` older than 30 days and returns
    their hashes.
  - `expires_at(registration) = registered_at + 30 days`.
  - `delivery_hash(identity) = RNS.Destination.hash(identity, "lxmf", "delivery")`.
- Persistence: JSON (bytes as hex) written to `path + ".tmp"` then `os.replace`. Load at
  construction; a missing file is empty; an unparsable file is renamed to
  `path + ".corrupt-<unix>"`, logged at ERROR, and the registry starts empty. A failed write is
  logged at ERROR; the in-memory state is kept.

### `apns.py`

- `JWTSigner(key_pem, key_id, team_id, clock)`: ES256 over `{"alg":"ES256","kid":key_id}` and
  `{"iss":team_id,"iat":now}` with `cryptography`; DER signature converted to raw `r‖s`. Cached
  for 50 minutes; `invalidate()` forces a re-sign.
- `APNsClient(signer, connect=...)`: one connection per environment, host
  `api.push.apple.com` or `api.sandbox.push.apple.com`, port 443, TLS with ALPN `h2`
  (`connect` is injectable so tests use a socketpair without TLS). Opened lazily; reopened after
  GOAWAY, a socket error, or 30 minutes idle.
- `send(environment, token_hex, topic, collapse_id, payload: bytes) -> Result` where `Result` is
  `(status: int, reason: str | None)`. `POST /3/device/<token_hex>` with headers
  `authorization: bearer <jwt>`, `apns-push-type: alert`, `apns-priority: 10`,
  `apns-topic`, `apns-collapse-id`. Reads the response status and, if non-200, the JSON `reason`.
  A transport failure returns `(0, "connection")`. Synchronous; called only from the dispatcher
  thread.

### `dispatcher.py` — `PushDispatcher`

- `PushDispatcher(registry, apns, on_unregistered, clock, start_thread=True)`.
  `on_unregistered(destination_hash)` is called when APNs rejects the token.
- `enqueue(destination_hash, raw)` is non-blocking: appends to a deque capped at 1024 entries
  (oldest dropped, logged at WARNING). Called from Transport threads.
- Worker thread, per destination:
  - The first packet opens a 500 ms window. The batch is flushed when the window closes, or
    immediately when adding a packet would exceed 8 packets or 3500 base64 characters (the
    overflowing packet starts the next batch).
  - Rate limit: at most 20 pushes per destination per sliding 60 s; a batch over the limit is
    dropped and logged at DEBUG.
  - At flush the registration is looked up; if gone, the batch is dropped.
  - Payload (compact JSON):
    `{"aps":{"alert":{"title":"New message"},"mutable-content":1,"content-available":1},"rns":{"v":1,"packets":[<base64>...]}}`.
    Topic = registration `bundle_id`, collapse id = destination hash hex.
- Response handling:

| response | action |
|---|---|
| 200 | done |
| 410, or 400 `BadDeviceToken`, or 400 `DeviceTokenNotForTopic` | `on_unregistered(hash)` |
| 403 `ExpiredProviderToken` | `signer.invalidate()`, retry once |
| 429, 5xx, `(0, "connection")` | retry once after 1 s, then drop |
| anything else | log at ERROR, drop |

- `stop()` ends the thread. Tests drive the worker with `start_thread=False` and a `step()` method
  plus a fake clock.

### `service.py` — `RegistrationService`

Constructed by the server interface once `RNS.Transport.identity` exists (interfaces are built
before `Transport.start`, Reticulum.py:341-347; a daemon thread polls every 0.5 s).

- Identity at `<storage>/rns_push/identity`, created with `RNS.Identity()` and `to_file` on first
  run.
- `RNS.Destination(identity, IN, SINGLE, "rnspush", "registration")`, announced at startup and
  every 30 minutes with `app_data = msgpack {"v": 1}`. The destination hash is logged at NOTICE.
- Request handlers `/register` and `/unregister`, `allow=ALLOW_ALL`. Each first resolves the
  link (`RNS.Transport` active links by `link_id`) and its `attached_interface`, then:
  - `remote_identity is None` → `{"ok": false, "error": "not_identified"}`.
  - More than 10 requests from this identity hash in the past hour → `rate_limited`.
  - `attached_interface` is not a `PushClientInterface` whose parent is this server →
    `not_direct`.
  - `/register`: data must be a map with `v == 1`, `token` bytes (1-100 bytes),
    `environment` in the two values, `bundle_id` str; else `bad_request`. `bundle_id` not in
    `allowed_bundle_ids` → `bundle_not_allowed`. Otherwise `registry.put(...)`,
    `server.bind(hash, attached_interface)`, respond
    `{"ok": true, "destination_hash": hash, "expires_at": int(expires_at)}`.
  - `/unregister`: `registry.remove(hash)`, `server.retire(hash)`, respond `{"ok": true}`
    whether or not an entry existed.
  - Any exception → logged at ERROR, `bad_request`.
- Announce handler, `aspect_filter = "lxmf.delivery"`: if the announced hash is registered and
  `RNS.Transport.path_table[hash][IDX_PT_RVCD_IF]` is one of this server's spawned
  `PushClientInterface`s, `server.bind(hash, that_interface)`. Exceptions logged.
- Hourly sweep: `registry.expire()`, `server.retire(h)` for each.

### `interface.py`

**`PushTCPServerInterface(TCPServerInterface)`**

- Reads the extra config keys (§4). Validates them, rejects any `ifac_*` key and a disabled
  transport, by raising `ValueError` with a clear message (RNS logs it and continues without the
  interface).
- Owns `Registry`, `APNsClient`, `PushDispatcher`, `RegistrationService`, and
  `bindings: dict[hash, PushClientInterface]` under a lock.
- `incoming_connection(handler)`: a copy of the stock method that constructs
  `PushClientInterface` instead of `TCPClientInterface`. The supported `rns` range is pinned in
  `pyproject.toml`; a small upstream PR adding a `spawned_interface_class` attribute would remove
  the copy.
- `bind(hash, iface)`: if another interface holds `hash`, unbind it (and `retire` it if dormant);
  set `iface.bound_hash = hash`; record the binding.
- `retire(hash)`: pop the binding; if that interface is dormant, call its `retire()`; if live,
  just clear `bound_hash`.
- `on_unregistered(hash)` (from the dispatcher): `registry.remove(hash)`, `retire(hash)`.

**`PushClientInterface(TCPClientInterface)`**

- Fields: `bound_hash: bytes | None = None`, `dormant: bool = False`.
- `teardown()`: unbound → stock. Bound → close the socket, `online = False`, `dormant = True`,
  keep `OUT = True`, stay in `Transport.interfaces` and in the parent's `spawned_interfaces`.
  Logged at INFO with the hash.
- `retire()`: `dormant = False`, `OUT = False`, remove from the parent's spawned list,
  `RNS.Transport.remove_interface(self)`. The cull clears its table entries.
- `process_outgoing(data)`: live → stock. Dormant → `parse_header(data)`; if the destination
  hash equals `bound_hash` and the type is DATA or LINKREQUEST, `dispatcher.enqueue(hash, data)`;
  otherwise drop. Never raises, never calls teardown.
- `process_incoming(data)`: if `parse_header(data)` is a PROOF and
  `RNS.Transport.reverse_table.get(header.destination_hash)` has an outbound interface that is a
  dormant `PushClientInterface` of the same server, `self.owner.inbound(data, that_interface)`;
  else `self.owner.inbound(data, self)`. Byte counters as stock.

### `cli.py`

`rns-push status [--config DIR]`: prints the registration destination hash (from the identity
file) and the number of live registrations (from `registrations.json`). Does not need rnsd.

## 3. Data flow

### 3.1 Register

Phone connects (spawned `PushClientInterface` A) → opens a link to `rnspush.registration`,
`identify`, `/register` → handler checks, `registry.put`, `bind(hash, A)` → response.

### 3.2 Socket closes

A's read loop ends → `teardown()` → A is bound, so dormant. Path to `hash` still points at A.

### 3.3 Message arrives

Sender's packet for `hash` → Transport forwards it via the path to A, adding a reverse entry
`(rcvd_if=sender side, outb_if=A)` → `Transport.transmit(A, raw)` → A dormant →
`dispatcher.enqueue` → batch → APNs.

### 3.4 Proof returns

The phone's extension opens a fresh connection (spawned B, unbound), writes the framed proof → B
`process_incoming` sees a PROOF whose reverse entry's outbound interface is dormant A →
`owner.inbound(data, A)` → Transport's check at Transport.py:2340 passes → forwarded to the sender
→ receipt DELIVERED. B closes and is torn down as stock.

### 3.5 Phone reconnects

New spawned C, the app announces `lxmf.delivery` → announce handler finds the path via C →
`bind(hash, C)` retires dormant A.

## 4. Configuration

```
[[Push Hub]]
  type = PushTCPServerInterface
  enabled = yes
  listen_ip = 0.0.0.0
  listen_port = 4242
  apns_key_file = /etc/rns-push/AuthKey_ABC123.p8
  apns_key_id = ABC123
  apns_team_id = TEAM123456
  allowed_bundle_ids = co.lithobyte.ReTiCaMsgr
```

- All stock `TCPServerInterface` keys apply except `ifac_*`.
- Required: `apns_key_file` (readable, a P-256 key), `apns_key_id`, `apns_team_id`,
  `allowed_bundle_ids` (comma-separated, at least one), and `enable_transport = yes` in
  `[reticulum]`. Missing or invalid → `ValueError`, interface not started.
- State: `<configdir>/storage/rns_push/identity` and `registrations.json`.

## 5. Errors

| situation | behaviour |
|---|---|
| Config invalid, IFAC set, transport off | `ValueError` at construction; RNS logs it and runs without this interface |
| `registrations.json` unparsable | renamed `.corrupt-<unix>`, start empty, ERROR log |
| Registry write fails | ERROR log, in-memory state kept |
| APNs unreachable or slow | dispatcher retries once, drops; Transport never blocks (enqueue only) |
| Dispatcher queue full | oldest dropped, WARNING log |
| APNs rejects the token | registration removed, dormant interface retired |
| Handler or announce-callback exception | logged; request answers `bad_request` |
| Push for a destination over the rate limit | dropped, DEBUG log |
| rnsd restarts | registrations survive; dormant interfaces do not (known limit) |

## 6. Testing

Stdlib `unittest`, run from the repo root with `python -m unittest`. Every new test is
mutation-verified in one batch per task with a named mutation per test, per the global rule.

- `test_packet`: HEADER_1 and HEADER_2 destination offsets; each packet type; IFAC flag; short
  input → None.
- `test_registry`: put/replace; get/remove; 30-day expiry with a fake clock; persistence round
  trip; corrupt file renamed and empty start; `delivery_hash` equals
  `RNS.Destination.hash(identity, "lxmf", "delivery")`.
- `test_apns`: the JWT verifies with the key's public half and carries `iss`, `iat`, `kid`;
  cached under 50 min, re-signed after or on `invalidate`; against an in-process `h2` server over
  a socketpair: method, path, all headers and body; non-200 reason parsed; a dropped connection
  returns `(0, "connection")` and the next send reconnects.
- `test_dispatcher` (fake clock, fake APNs): one packet flushes at 500 ms; 8 packets flush
  immediately; 3500-character cap splits; two destinations never share a push; payload JSON and
  headers exact; 21st push in a minute dropped; 410 and `BadDeviceToken` call `on_unregistered`;
  429 retried once; `ExpiredProviderToken` invalidates and retries; removed registration drops
  the batch; queue cap drops the oldest.
- `test_service` (real RNS from `tests/rnsconfig`, links on loopback): each error code
  (`not_identified`, `bad_request` variants, `bundle_not_allowed`, `not_direct`, `rate_limited`)
  and success with the exact response; `/unregister` removes and retires; announce handler binds
  and rebinds only for registered hashes on own spawned interfaces.
- `test_interface` (patched `Transport.add_interface`/`remove_interface`, fake tables):
  bound teardown goes dormant and stays in `Transport.interfaces`; unbound teardown is stock;
  dormant `process_outgoing` enqueues DATA and LINKREQUEST to the bound hash and drops announces,
  other hashes and link-id packets; live `process_outgoing` is stock; proof redirect to a dormant
  interface; proof with no reverse entry, or one pointing at a live interface, goes to self;
  rebind retires the old dormant interface; IFAC config raises.
- `test_end_to_end`: hub and sender as RNS instances on loopback with the fake APNs. A client
  connects to the hub, registers, disconnects; the sender sends a single-packet message to the
  client's delivery destination; the fake APNs receives a payload containing that packet; the
  test builds the implicit proof with the client identity and writes it framed over a fresh TCP
  connection; the sender's receipt reaches DELIVERED.
- Manual: a device against a hub with real APNs credentials.

## 7. Contract revision

`ReTiCAPush/docs/server-contract.md` is revised (kept as v1) to match this design: §1 becomes
registration over Reticulum (destination `rnspush.registration`, identified link, `/register` and
`/unregister` with msgpack bodies and the error codes above); §2 binds on successful
registration as well as announces, states that proof return requires the hub to re-attribute
proofs (stock RNS does not), states that push hub interfaces do not use IFAC, and lists the known
lifetime limits; §3 is unchanged; §4 describes when the client registers; §5 points at
`rns-push`. A copy lives in this repo at `docs/server-contract.md`. The client's
`PushRegistration`/`RegistrationClient` and its "Registration URL" setting are replaced by
link-based registration and a "Push hub destination" setting in a ReTiCAPush follow-up.

## Out of scope

Replaying stored announces to survive restarts or path expiry. IFAC. Android/FCM. Web push.
Metrics. Multiple APNs keys per hub. Any change to RNS core (beyond an optional upstream PR for a
`spawned_interface_class` hook). The client-side changes.
