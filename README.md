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
rns-push install-shim
```

`install-shim` copies a small loader file into the `interfaces` directory of your Reticulum
config so `rnsd` can find the interface, and prints where it put it. It uses the same config
directory `rnsd` would; pass `--config DIR` if yours is elsewhere. Run it again after upgrading.

rns-push must be installed in the same Python environment as `rnsd`, because `rnsd` imports it.
If you installed Reticulum with pipx, add rns-push to that environment instead of using
`pip install`: `pipx inject --include-apps rns rns-push` (`--include-apps` also puts the
`rns-push` command on your PATH).

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
    # optional: destinations clients may register, as dotted aspects (default lxmf.delivery)
    push_aspects = lxmf.delivery, nbhd.sync
    # optional: per-bundle banner title, bundle=title (default "New message")
    alert_titles = co.lithobyte.Nbhd=Neighborhood activity
    # optional: lxmd's message store; a message that lands there for a registered client is pushed
    propagation_store = /data/lxmd/storage/lxmf/messagestore
```

All `TCPServerInterface` options work except IFAC (`network_name`, `passphrase`, `ifac_size`),
which this interface refuses. Transport must be enabled. The optional `max_registrations`
(default 10000) caps how many clients the hub keeps registered; once full, new clients are
refused with `rate_limited` until registrations expire or are removed.

Start `rnsd`, then run `rns-push status` to print the registration destination hash. Clients
enter that hash as their push hub destination. State lives in `<config>/storage/rns_push/`.

## Known limits

- Dormant interfaces do not survive an `rnsd` restart. Pushing resumes the next time each
  client connects and announces.
- The hub forgets a client's path after a week without a fresh announce (Reticulum's
  destination timeout in the default full interface mode; shorter in access-point or roaming
  mode), with the same recovery.
- Notifications always read "New message". The hub never sees message content.
- Link requests are pushed, but they only wake the app: the link handshake cannot complete
  while the app is asleep. Once the woken app reconnects to the hub, the sender's retry of the
  link request succeeds over the live connection. Single-packet messages, by contrast, are
  proved directly from the push.
- If the push hub interface is misconfigured (an unreadable APNs key, IFAC options set, or
  transport disabled), rnsd logs an error and starts without it rather than failing. Check the
  log after configuring.
