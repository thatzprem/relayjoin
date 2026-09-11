# payjoin-nostr

**Asynchronous Payjoin with no directory, no OHTTP relay, and no new infrastructure.**

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
| `pjn-sender` — sender CLI | **Built: URI parsing, proposal validation, fallback** |
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
[34476319227](https://github.com/thatzprem/payjoin-nostr/actions/runs/34476319227),
gift wrap `8da3a122ce630570efd435a3f8d60061fc8ff9e5ab5b715b153fdad45eebf804`.

25 unit tests pass plus that live test. Note that **nothing in this workspace can
be executed on the primary Windows dev machine** — Smart App Control blocks both
cargo's build scripts and the compiled test binaries — so CI is the source of
truth. The live test is `#[ignore]`d so it only runs on demand:

```bash
cargo test -p pjn-transport --test roundtrip -- --ignored --nocapture
```

## Known blocker: Smart App Control

This machine has **Windows Smart App Control enforced**, which blocks execution of
the unsigned build scripts cargo compiles. Anything pulling `secp256k1-sys`,
`bitcoin-io`, or `hex_lit` fails with:

```
An Application Control policy has blocked this file. (os error 4551)
```

It also blocks **every freshly built test binary**, including ones that ran
successfully minutes earlier, so no test in this workspace can be run locally. Moving `CARGO_TARGET_DIR` does not help — the policy is
not path-scoped.

### Fix: build in WSL2

Smart App Control does not apply inside the Linux VM, and the Bitcoin/Rust
toolchain is better supported there regardless. The WSL app package (2.3.26.0) is
already installed on this machine, but the Windows features behind it are not
enabled, which is what produces `REGDB_E_CLASS_NOT_REGISTERED`.

In an **Administrator** PowerShell:

```powershell
wsl --install -d Ubuntu
```

If that still reports "Class not registered", enable the features explicitly and
reboot:

```powershell
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

Then, inside Ubuntu:

```bash
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Work from the Linux filesystem (`~/payjoin-nostr`), not `/mnt/c` — cargo builds
are several times slower across the 9p mount.

Other options, if you'd rather not install WSL: build in CI/Docker (slow loop), or
turn Smart App Control off (Windows Security → App & browser control).
⚠️ Turning it off is **irreversible** — re-enabling requires reinstalling Windows.

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
