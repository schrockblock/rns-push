# ReTiCA push hub — server contract (v1)

A push hub is a Reticulum transport node that can wake an iOS client with an Apple push when
the client's socket is down. The client (`ReTiCAPush`) never uploads messages: the hub already
sits on every path to the client, so it pushes the very bytes it would have written to the
client's socket. The client proves them back over a fresh socket, and the hub routes the proof
to the sender.

Everything here is normative for a hub a `ReTiCAPush` client can talk to. Registration happens
over Reticulum itself; the hub has no HTTP surface.

## 1. Registration

### 1.1 The hub's registration destination

The hub owns a long-lived Reticulum identity (separate from its transport identity) and a
destination:

```
RNS.Destination(hub_identity, IN, SINGLE, "rnspush", "registration")
```

- The hub announces it at startup and every 30 minutes. `app_data` is msgpack `{"v": 1}`.
- The client learns the destination hash from user configuration ("Push hub destination",
  32 hex characters, the way a propagation node is configured). A client may also adopt an
  `rnspush.registration` announce that arrives over its hub interface with `hops == 1`.
- The hub only accepts registrations over its own TCP server's spawned client connections (§1.4).

### 1.2 Flow

1. The client opens a Link to the registration destination.
2. Once the link is active, the client calls `identify` on it with its own identity (the
   identity whose `lxmf.delivery` destination is to be woken).
3. The client sends a link request (standard RNS request/response, request data and response
   are msgpack) to one of two paths:

| path | request data | success response |
|---|---|---|
| `/register` | `{"v": 1, "token": <bin>, "environment": <str>, "bundle_id": <str>}` | `{"ok": true, "destination_hash": <bin 16>, "expires_at": <int unix seconds>}` |
| `/unregister` | `{"v": 1}` | `{"ok": true}` |

- `token`: the APNs device token bytes (msgpack bin, not hex).
- `environment`: `"production"` or `"sandbox"`.
- `bundle_id`: the registering app's bundle identifier.
- Map keys are msgpack str.

4. The client tears the link down after the response (or on request timeout).

Failure response: `{"ok": false, "error": <str>}`, with `error` one of:

| error | meaning |
|---|---|
| `not_identified` | the link was not identified before the request |
| `bad_request` | data is not a map, `v` is not 1, a field is missing, the wrong type, or `environment` is not one of the two values |
| `bundle_not_allowed` | `bundle_id` is not in the hub's allow-list |
| `not_direct` | the link was not opened by the client itself over one of this hub's spawned client connections (for example, it was relayed through another Reticulum node) |
| `rate_limited` | more than 10 requests from this identity in the past hour, or (`/register` for an identity not yet registered) the hub already holds its maximum number of registrations |

A client treats any failure as "not registered" and surfaces the code.

### 1.3 Identity and destination

The hub authenticates the client by link identification only: the identity the link was
identified with is the identity being registered. There is no body signature and no timestamp;
the link's encryption and identification cover authenticity and replay.

The hub derives the destination to wake itself:
`RNS.Destination.hash(remote_identity, "lxmf", "delivery")`, i.e.
`identity_hash = SHA-256(public_key)[:16]`,
`destination_hash = SHA-256(SHA-256("lxmf.delivery")[:10] ‖ identity_hash)[:16]`.
It is returned in the `/register` response so the client can sanity-check it.

### 1.4 Server rules

- `/register` stores `destination_hash → (identity public key, token, environment, bundle_id,
  registered_at)`, replacing any existing entry for that hash (this is also how a token change
  is handled), and binds the connection the link arrived on (§2). A registration expires 30
  days after the last successful `/register`. Clients re-register at least daily while enabled.
- `/unregister` removes the entry and retires the client's dormant interface (§2). An unknown
  identity also answers `{"ok": true}`.
- An APNs `410 Unregistered`, `BadDeviceToken` or `DeviceTokenNotForTopic` response drops the
  entry and retires its dormant interface.
- The hub never needs the client's private key, its messages, or its socket address.

## 2. Transport behaviour

The hub runs a Reticulum transport node. Its TCP server interface is the hub the client dials
(the same host and port the client has configured as its node connection).

- **Binding.** A spawned client connection is bound to a registration when (a) a `/register`
  request succeeds on a link that arrived over it, or (b) a validated announce for a registered
  `destination_hash` arrives over it. Binding a registration to a new connection retires the
  previously bound one, dormant or not. So after a reconnect, the client's ordinary
  `lxmf.delivery` announce is enough to re-bind; it need not re-register.
- **Dormancy.** When a bound connection's socket closes, its interface stays attached to the
  transport, so the path table, the reverse table and the link table entries that reference it
  remain valid, and it becomes dormant. An unbound spawned interface behaves as stock: detached
  on close.
- **Pushing.** For every outgoing buffer the transport hands a dormant interface: if the
  packet's destination hash equals the bound `destination_hash` (this covers DATA and
  LINKREQUEST packets to the client's delivery destination), push the bytes **exactly as they
  would have hit the socket, before HDLC framing**. Drop any other buffer (announces, path
  requests, link packets addressed by link id, packets for other destinations), as the dead
  socket would have. Push hub interfaces do not use IFAC.
- **Proof return.** The client returns proofs on a fresh TCP connection that may never
  announce. Stock RNS does **not** route these: it forwards a proof only when it arrives on the
  interface the original packet was sent out on (the reverse-table entry's outbound interface),
  which here is the dormant interface, not the fresh connection. The hub must therefore accept a
  proof on any spawned connection and, when its reverse-table entry's outbound interface is a
  dormant push interface, process it as if it had arrived on that dormant interface.
- **Retries.** A sender retries a single-packet message every 10 s up to five times, each with a
  distinct packet hash, and its receipt for each attempt lives only 6 s plus 6 s per hop. Push
  every attempt. Use `apns-collapse-id` (§3) so the user sees one banner. A per-destination rate
  limit (suggested: 20 pushes per minute) protects the APNs quota.
- **Lifetime.** A dormant interface lives as long as its registration, subject to these known
  limits: dormancy does not survive a hub restart, and the client's path expires at the hub
  after a week without a fresh announce. In both cases pushing resumes the next time the app
  connects and announces.

## 3. Push shape

Headers: `apns-push-type: alert`, `apns-priority: 10`, `apns-topic: <bundle_id>`,
`apns-collapse-id: <destination_hash hex>`. Send to the APNs environment the registration named.

```json
{
  "aps": {
    "alert": { "title": "New message" },
    "mutable-content": 1,
    "content-available": 1
  },
  "rns": {
    "v": 1,
    "packets": ["<base64 raw packet>", "..."]
  }
}
```

- `aps.alert.title` is fixed by the server and never carries sender or content information.
  The client's service extension never changes it.
- Each entry of `packets` is one raw Reticulum packet (at most 500 bytes), base64 without line
  breaks.
- Packets to one destination that arrive within 500 ms may be batched into one push: at most 8
  packets and 3500 bytes of base64 in total (the APNs payload limit is 4 KB).
- Pushes for different registrations are never batched.
- `mutable-content: 1` runs the client's service extension, which stashes the packets and
  proves them. `content-available: 1` additionally asks iOS for a best-effort background wake of
  the app, which ingests the packets sooner. Both are required.

## 4. What the client does

For the hub author's mental model, not something the hub depends on:

1. While push is enabled, the app registers (§1.2) whenever it gets a device token that differs
   from the last registered one or the last registration is more than 24 hours old, and
   unregisters when the user turns push off.
2. On a push, the service extension decodes `rns.packets`, writes each packet to a shared
   inbox, signs an implicit proof (`Ed25519(packet_hash)` addressed to `packet_hash[:16]`) for
   every DATA packet addressed to the client's delivery hash, opens one TCP connection to the
   hub, writes the HDLC-framed proofs, closes. It never decrypts anything and never changes the
   notification.
3. The app, when it next runs (background wake, tap or launch), reconnects to the hub, announces,
   and feeds the inbox packets into its transport as if the socket had delivered them. That path
   decrypts, dedups and may send a second proof, which the sender ignores.

## 5. Reference implementation

The Python hub is `rns-push`: a pip package plus a one-line interface shim in the Reticulum
config's `interfaces/` directory. It provides `PushTCPServerInterface`, a `TCPServerInterface`
whose spawned interfaces implement binding, dormancy and proof return, the `rnspush.registration`
destination and its request handlers, and a token-based APNs client over HTTP/2. It runs on
stock RNS.
