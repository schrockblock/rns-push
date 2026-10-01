# rns-push

A push-capable hub for [Reticulum](https://reticulum.network). It runs inside stock `rnsd` as an
external interface plugin. When a registered iOS client's TCP connection drops, the hub keeps
the client's interface attached, pushes the packets it would have written to the socket through
Apple Push Notification service, and routes the proofs the client sends back to the original
sender. Senders need nothing and never know push was involved. The wire contract for clients is
in [docs/server-contract.md](docs/server-contract.md).

## Install

```
pip install rns-push
cp shim/PushTCPServerInterface.py ~/.reticulum/interfaces/
```

(Use your Reticulum config directory if it is not `~/.reticulum`.)

## Apple setup

In the Apple Developer portal, create an APNs authentication key (Keys → +, enable Apple Push
Notifications service). Download the `.p8` file once, and note its Key ID and your Team ID. The
app's bundle id must belong to that team. No server-side domain verification is needed.

## Configure

In the Reticulum `config`:

```
[reticulum]
  enable_transport = Yes

[interfaces]
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

All `TCPServerInterface` options work except IFAC (`network_name`, `passphrase`, `ifac_size`),
which this interface refuses. Transport must be enabled.

Start `rnsd`, then run `rns-push status` to print the registration destination hash. Clients
enter that hash as their push hub destination. State lives in `<config>/storage/rns_push/`.

## Known limits

- Dormant interfaces do not survive an `rnsd` restart. Pushing resumes the next time each
  client connects and announces.
- The hub forgets a client's path after a week without a fresh announce (Reticulum's
  destination timeout), with the same recovery.
- Notifications always read "New message". The hub never sees message content.
- A pushed link request only wakes the app. Link setup itself does not pass through the hub
  while the client is asleep, so the service extension cannot answer it. The app reconnects
  when woken, and the sender's retry then goes over the live connection. Single-packet
  messages are proved directly from the push.
- If the push hub interface is misconfigured (an unreadable APNs key, IFAC options set, or
  transport disabled), rnsd logs an error and starts without it rather than failing. Check the
  log after configuring.
