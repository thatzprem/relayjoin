# Two-terminal signet demo

A complete payjoin between two wallets that never talk to each other directly,
with no payjoin directory, no OHTTP relay, and no server either party runs.

Takes about ten minutes, most of which is waiting for faucet coins.

## Setup

Build once:

```bash
cargo build --release
```

Generate a wallet for each side. Run this twice — once per terminal — and keep
the two outputs separate:

```bash
cargo run --release -p pjn-receiver -- keygen
```

It prints two `export` lines. Paste them into the matching terminal. Signet coins
have no value, so the key is printed in the clear; never reuse it on mainnet.

## Fund both wallets

This is the step people miss: **the receiver needs coins too.** A payjoin
receiver contributes one of its own UTXOs — that is the whole mechanism — so a
receiver with an empty wallet cannot do a payjoin at all.

In each terminal:

```bash
cargo run --release -p pjn-receiver -- status
```

Copy each `receive address` into <https://faucet.mutinynet.com> and wait for
confirmation. Re-run `status` until both show a non-zero balance and at least one
spendable UTXO.

## Terminal 1 — receiver

```bash
cargo run --release -p pjn-receiver -- serve --amount 50000
```

It prints a payjoin URI and then waits.

**You can close this terminal and come back.** Press Ctrl-C, re-run the same
command, and it reprints the *same* URI and picks up where it left off — the
session key, address and probing history are kept in `.pjn-session.json`. The
relays hold the sender's payload in the meantime. That is the property BIP77
needed a directory server for, and it is worth actually trying during the demo:
kill the receiver, send from terminal 2, then start the receiver again and watch
it collect a payload that arrived while it was gone.

`pjn-receiver reset` forgets the session, which permanently invalidates the URI
it printed.

The sender resumes the same way. Once it has published, you can close terminal 2
as well. Running `pjn-sender` again with no URI reloads the saved payment from
`.pjn-sender-session.json` and picks up the receiver's reply. It uses the same
nostr key and the same Original PSBT, so nothing is sent twice. If the payment
already settled on an earlier run, the sender sees that its coins are spent,
deletes the saved state, and does not broadcast again. `pjn-sender --abandon`
deletes a saved payment without broadcasting anything.

## Terminal 2 — sender

Paste the URI from terminal 1:

```bash
cargo run --release -p pjn-sender -- "bitcoin:tb1q...?amount=0.0005&pj=https://nostr.invalid/..."
```

The sender builds and signs a normal payment first — that transaction is the
fallback, and payjoin requires it to exist before the receiver will engage. Then
it publishes the Original PSBT, waits for the proposal, validates it, signs, and
broadcasts.

Add `--dry-run` to walk the whole protocol and broadcast nothing.

## What to look at

The finished transaction has **inputs from two different wallets**. Every
chain-analysis heuristic that assumes all inputs share an owner reads it wrong:
it will conclude the sender and receiver are the same entity, and that the
payment amount was something neither party ever sent.

Check it on <https://mutinynet.com>. Two inputs, two outputs, and no way to tell
from the chain which output was the payment.

## What the relays saw

Worth being precise, because it's the first question anyone asks:

- Two `kind:1059` gift wraps, each signed by a **throwaway key** generated for
  that single message
- A `p` tag naming the receiver's **per-URI session key**, not an identity
- Randomised `created_at`, so not a send time
- NIP-44 sealed content

What they *did* see is the IP address of whoever connected. Nostr does not close
that gap; Tor does. See [`../docs/threat-model.md`](../docs/threat-model.md) —
we don't claim otherwise.

## When it doesn't work

**"wallet has no UTXOs to contribute"** — the receiver isn't funded. See above.

**Sender times out** — the receiver isn't running, or the two are on disjoint
relay sets. Pass `--relays` to both with the same list. Note this failure is
*safe*: the sender still holds a signed fallback and can broadcast it with
`--fallback-on-failure`.

**"receiver's proposal failed validation"** — working as designed. The sender
refused to sign a rewrite it could not verify, and fell back. On signet this is
usually a fee-policy mismatch rather than an attack.
