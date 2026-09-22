# Relayjoin

**Asynchronous Payjoin over nostr, with no directory, no OHTTP relay, and no new infrastructure.**

Payjoin breaks the common-input-ownership heuristic — the assumption that every
input to a transaction belongs to one person. That assumption is the foundation
almost all chain surveillance is built on, and Payjoin makes it *false* rather
than merely noisy. It is the most impactful privacy technique Bitcoin can deploy
today.

It is also barely deployed, and the reason is plumbing.

## The problem

Payjoin is interactive: the receiver contributes an input, so the transaction is
built collaboratively. Plain Bitcoin needs no such handshake — you hand out an
address and can stay offline forever. Payjoin does.

**BIP78 (v1)** required the receiver to be running an HTTP endpoint at the moment
the sender pays: a public URL with TLS, or a Tor hidden service. Fine for a
merchant on a VPS. Impossible for a phone.

**BIP77 (v2)** made it asynchronous by adding a *Payjoin Directory* to hold the
encrypted payloads, with an *OHTTP relay* in front so the directory never learns
either party's IP. It works — and it reintroduces infrastructure. Somebody has to
run the directory. Somebody has to run the relay. Today that is a very short list
of operators, which is a centralization and censorship surface sitting underneath
a privacy protocol.

## The idea

Nostr relays already are the thing BIP77 had to build.

| What async payjoin needs | BIP77 builds it | Nostr already has it |
|---|---|---|
| Store-and-forward | Payjoin Directory | Relays, hundreds of operators |
| Payload encryption | HPKE | NIP-44 seal |
| Metadata / IP privacy | OHTTP relay | Ephemeral keys per message |

So we keep the **v1 protocol semantics** — simple, well-understood, and fully
exposed by `payjoin` 1.0.0's public API — and let **nostr carry the asynchrony**.
The receiver can be offline for a weekend and still complete the payjoin. Nobody
runs a server.

```
  sender                     nostr relays                    receiver
    │                                                            │
    │  gift wrap (NIP-59) ── Original PSBT ──▶  [stored]          │
    │                                              └──────────▶  │  (comes online)
    │                                                            │  adds an input,
    │                                                            │  signs
    │  ◀── [stored]  ◀────── Payjoin Proposal ── gift wrap        │
    │                                                            │
  validate, sign, broadcast
```

## Status

| Component | State |
|---|---|
| `pjn-transport` — NIP-59 gift-wrapped payjoin transport | **Verified against live public relays** |
| `pjn-wallet` — binding to the payjoin state machines | **Working end to end** |
| `pjn-receiver` — receiver daemon | **Built: URI, relay listen, full validation walk, signed proposal** |
| `pjn-sender` — sender CLI | **Built: URI parsing, proposal validation, fallback, resume after restart** |
| `pjn-theater` — live visual demo | **Built: a real payjoin driven end to end from the page, confirmed on-chain** |
| `site/index.html` — replay site | **Live at [relayjoin.vercel.app](https://relayjoin.vercel.app): a recording of a real run, played back in the browser. No server, no keys** |
| Live two-terminal signet demo | **Run end to end; confirmed on-chain** |

**A real payjoin has completed over public nostr relays, with the receiver
offline when the sender paid.** Signet txid
[`7d55bfd7e4e95a4740462ba47df489a76dc48592de93cf051433877239647a17`](https://mutinynet.com/tx/7d55bfd7e4e95a4740462ba47df489a76dc48592de93cf051433877239647a17),
confirmed in block 3,416,929:

```
INPUTS  (2)                                  OUTPUTS (2)
  tb1qtp82v...  100,000 sat  (receiver)        tb1q08zvq...   69,583 sat
  tb1qrdv0g...  100,000 sat  (sender)          tb1qrtrhj...  130,000 sat
```

Two inputs, two different owners. Any analyst applying the common-input-ownership
heuristic concludes one entity owns both and gets it wrong. The actual payment was
**30,000 sat** — a number that appears nowhere in the outputs.

The receiver was not running when the sender published. It was started afterwards,
resumed its session from disk, and collected the payload the relays had held.

**The transport claim is verified.** A gift-wrapped payjoin envelope round-trips
through real public relays (`relay.damus.io`, `nos.lol`) in ~4 seconds, and the
sealed sender key survives, which is what makes reply routing work without a
separate handshake. CI run
[34476319227](https://github.com/thatzprem/relayjoin/actions/runs/34476319227),
gift wrap `8da3a122ce630570efd435a3f8d60061fc8ff9e5ab5b715b153fdad45eebf804`.

45 unit tests pass plus that live test. The live test is `#[ignore]`d so it only
runs on demand:

```bash
cargo test -p pjn-transport --test roundtrip -- --ignored --nocapture
```

## Running it on Windows

Two environment gotchas cost real time here, both caused by local security
software rather than by the project:

**TLS interception.** AV products that scan HTTPS insert their own root
certificate. Libraries that ship Mozilla's root list reject it with
`UnknownIssuer`, which surfaced as "could not connect to any relay" and as an
Esplora sync failure. Both `nostr-sdk` and `bdk_esplora` are therefore configured
to use the **system trust store**, which is the right default for a wallet
regardless.

**Smart App Control.** While enforced, it blocks the unsigned build scripts cargo
generates (`secp256k1-sys`, `bitcoin-io`, `hex_lit`) with
`os error 4551`, and blocks freshly compiled test binaries too. It stopped
blocking this workspace once the binaries accumulated reputation, and the full
demo now builds and runs locally. If you hit it on a fresh machine, build under
WSL2 or in CI rather than disabling Smart App Control — turning it off is
**irreversible** without reinstalling Windows.

If cargo cannot reach crates.io with `CRYPT_E_NO_REVOCATION_CHECK`, that is the
same class of problem; `.cargo/config.toml` in this repo already disables the
revocation probe while leaving chain verification intact.

## Explaining it to other people

Two write-ups of the same project, pitched at different readers:

- [`docs/explainer.html`](docs/explainer.html) — plain English, no jargon. Why
  Bitcoin payments are public at all, and why letting the shop chip in a coin
  breaks the assumption surveillance runs on. Start here if Bitcoin is not your
  day job.
- [`docs/report.html`](docs/report.html) — the same real transaction rendered as
  a chain-analysis readout, with every conclusion the analyst would confidently
  draw and why each one is wrong. Toggles between the inferred reading and the
  true one.

Both are built from the actual signet payment in the Status table above, not from
worked examples.

## Threat model

Read [`docs/threat-model.md`](docs/threat-model.md) before claiming any privacy
property. The short version of what a relay can see:

- The outer gift wrap is signed by a **throwaway key per message**, so payloads
  cannot be linked to a persistent sender identity.
- The `p` tag addresses a **per-URI session key**, not a long-term identity.
- `created_at` is randomized by NIP-59, so it is not a send time.
- Content is NIP-44 sealed.

What a relay **can** still do is correlate by IP. Route over Tor for the real
thing. We do not claim otherwise.

## Prior art

Carrying payjoin over nostr is not a new idea, and this project builds on people
who tried it first:

- **[Postr](https://www.nobsbitcoin.com/postr-payjoin-nostr/)** (2023), a proof
  of concept that exchanged payjoin PSBTs as nostr direct messages.
- **[Unify Wallet](https://github.com/Fonta1n3/Unify-Wallet)** by Fonta1n3, a
  BIP78 payjoin wallet that coordinates over nostr using NIP-04 DMs.
- **Kukks** proposed `pjnpub=` and `pjnostrrelays=` URI parameters for reaching a
  payjoin receiver over nostr, and
  **[setavenger](https://gist.github.com/setavenger/ee45897489f52336ae8af8d7d4a1841d)**
  sketched a similar nostr-based design.
- **[Serverless Payjoin](https://gist.github.com/DanGould/243e418752fff760c9f6b23bba8a32f9)**
  by Dan Gould, the work that became BIP77, considered nostr as a transport.

What this project does differently:

- **Relays learn less.** NIP-04 shows every relay both parties' public keys and
  the real send time. Here each message is a NIP-59 gift wrap: signed by a
  throwaway key, with a randomized timestamp, and NIP-44 encrypted inside.
- **One key per payment request**, not a long-lived identity.
- **Either side can go offline and resume.** Both the receiver and the sender save
  their session, collect what arrived while they were away, and the sender refuses
  to pay twice.
- **The receiver runs every check** in Payjoin Dev Kit 1.0's typestate chain
  before it contributes a coin.

## Layout

```
crates/
  pjn-transport/   nostr gift-wrap transport — protocol-agnostic, opaque payloads
  pjn-wallet/      binds payjoin's state machines to that transport
  pjn-receiver/    receiver daemon CLI
  pjn-sender/      sender CLI
docs/              threat model, interop notes
demo/              two-terminal signet walkthrough
```

The seam between transport and protocol is deliberately narrow: `payjoin::Request`
exposes `body` as public bytes, and the receiver parses those same bytes back.
`pjn-transport` never learns what it is carrying, which is what would let the same
transport carry BIP77 HPKE payloads later.

## Built with

- [`payjoin`](https://crates.io/crates/payjoin) 1.0.0 — Payjoin Dev Kit
- [`nostr-sdk`](https://crates.io/crates/nostr-sdk) 0.45 — NIP-59 gift wrap
- `bitcoin` 0.32 / `bdk_wallet` 3.1

## License

MIT
