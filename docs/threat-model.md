# Threat model

Write down what is actually true, because the first question anyone competent will
ask is "what does the relay learn?" — and a project that overclaims here deserves
to lose.

## What we are protecting

A payjoin between a sender and a receiver who do not want:

1. a third party to learn that they transacted with each other,
2. a third party to be able to censor the payment,
3. the resulting on-chain transaction to be attributable via the
   common-input-ownership heuristic.

(3) is provided by Payjoin itself. (1) and (2) are what the transport is for.

## Actors

| Actor | Capability assumed |
|---|---|
| Relay operator | Sees every event it stores, its own TCP connections, timing |
| Network observer | Sees IP-level traffic to relays |
| Malicious sender | Wants to probe the receiver's UTXO set |
| Malicious receiver | Wants to steal funds or inflate the sender's fee |
| Chain analyst | Sees only the final transaction |

## What a relay learns

**Cannot see:** the PSBT, the amounts, the addresses, the participants' wallet
identities. Content is NIP-44 sealed inside a NIP-59 gift wrap.

**Can see:**

- That *some* kind-1059 event was addressed to *some* pubkey. The outer event is
  signed by a throwaway key generated fresh per message, so it is not linkable to
  a sender identity.
- The `p` tag, which is the receiver's **per-URI session key**. This is the main
  thing to get right: if a receiver reuses one session key across many payjoin
  URIs, that key becomes a persistent identifier and a relay can count how many
  payments that receiver is coordinating. **Generate a fresh session key per
  payjoin URI.**
- Event size, which currently correlates with PSBT size and so leaks input
  count. Padding is not implemented; see "Open problems".
- **The IP address of whoever connected.** This is the real leak.

`created_at` is randomized by NIP-59 up to two days in the past, so it is not a
send time and cannot be used directly for timing correlation.

## The IP leak, stated plainly

If the sender and receiver both connect to `relay.example` over clearnet, that
relay sees two IPs and two events correlated by the `p` tag. It does not learn who
they are, but it learns that those two network endpoints are talking.

This is exactly the leak OHTTP exists to close in BIP77, and **nostr does not
close it for us.** Mitigations, honestly ranked:

1. **Route relay connections over Tor.** Closes it properly. This is the intended
   deployment and should be the default before anyone calls this production-ready.
2. **Use disjoint relay sets.** Sender publishes to relays A and B, receiver reads
   from B and C. Only B sees both, and only if it correlates. Weak but free.
3. Nothing else. Do not pretend ephemeral keys solve an IP-layer problem.

## What a malicious sender can do

Probe the receiver's UTXO set: send many payjoin requests, watch which inputs the
receiver contributes, and learn its coins without ever broadcasting.

This is a Payjoin protocol concern, not a transport concern, and `payjoin`'s
receiver typestate machine handles it — `check_broadcast_suitability`,
`check_inputs_not_owned`, `check_no_inputs_seen_before`. **The binding layer must
not skip these steps.** `pjn-wallet` walks the full typestate deliberately for
this reason.

The transport does add one wrinkle: on nostr, sending is nearly free and
unauthenticated, so probing is cheaper than over HTTP where a receiver could rate
limit by IP. A production receiver wants a rate limit keyed on the sealed sender
pubkey, plus a cap on concurrent sessions.

## What a malicious receiver can do

Return a proposal that steals funds or inflates fees. Handled by
`V1Context::process_response` on the sender side, which validates the proposal
against the original before the sender signs. `pjn-wallet::process_proposal`
wraps exactly this and must run before signing.

## Open problems

- **Padding is not implemented.** Event size currently correlates with PSBT size,
  which leaks input count. BIP77 pads HPKE payloads to a fixed length for this
  reason; we should pad envelopes to fixed buckets.
- **No Tor by default.** See above. This is the biggest gap.
- **Session key reuse is not enforced in code.** Currently a caller *can* reuse a
  session key across URIs. The API should make that hard.
- **A receiver away for more than about an hour can miss a payload.** `recv`
  filters with `since = now - 49h`, but NIP-59 back-dates each gift wrap's
  `created_at` by up to 48 hours *from when it was published*. The worst case falls
  outside the window once the receiver returns more than an hour after the sender
  published, and the chance of a miss grows the longer it stays away. This
  contradicts the claim that a receiver can be offline for days, because gift wraps
  are kept for seven. The fix is to anchor the window to the session's creation
  time, less 48 hours, instead of to the current time. In the successful demo the
  receiver came back after 40 seconds, well inside the window.
- **No replay protection beyond NIP-40 expiration.** A relay could re-serve an old
  gift wrap; the payjoin state machine rejects stale PSBTs, but we have not
  audited that path.
- **Relay availability is a liveness assumption**, not a safety one. If every
  relay drops the event the payjoin simply does not complete, and the sender
  falls back to the original PSBT. That fallback is wired and was exercised in a
  live run: the sender timed out, declined to broadcast without
  `--fallback-on-failure`, and reported the fallback txid.

---

## Resolved: stored events were not being collected

**Status: fixed.** A receiver that was offline when the sender published could not
collect the payload when it came back. It resumed its session correctly and then
waited as though nothing were there.

The symptom had four causes. Three of them were hidden behind the first:

1. **`send()` ignored per-relay results.** `send_event` resolves `Ok` even when
   every relay refuses, so the sender reported a successful publish while nothing
   was stored. Once this reported honestly, the other three showed up one run at a
   time.
2. **Connections were never established.** `Client::connect()` only starts them,
   so every send raced a socket that wasn't open yet. Now `try_connect()` waits,
   with a timeout, and fails if no relay connects.
3. **TLS failed against every relay** on a machine whose antivirus intercepts
   HTTPS. Bundled Mozilla roots rejected its root certificate with `UnknownIssuer`.
   Both `nostr-sdk` and `bdk_esplora` now use the system trust store.
4. **The sender's BIP78 parameters were dropped.** They travel in the request
   URL's query string, and that URL was being discarded as routing. The receiver
   then made changes the sender had not authorised, and validation rejected them.
   The envelope now carries the query.

`recv()` also fetches stored events explicitly before it waits for new ones,
instead of assuming a live subscription will replay them.

This was confirmed on-chain. The receiver was stopped, the sender published, then
the receiver was restarted, collected the payload, and completed the payjoin:
signet txid `7d55bfd7e4e95a4740462ba47df489a76dc48592de93cf051433877239647a17`,
block 3,416,929.

The diagnostic that separated these causes is kept in
`crates/pjn-transport/tests/backlog_diagnostic.rs`.
