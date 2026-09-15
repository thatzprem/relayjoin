# Payjoin Theater

A live, visual demo of payjoin over nostr. One command starts a small server on
your machine that runs a real payer (Alice) and a real shop (Bob) against public
relays and signet, and shows every step of the protocol in the browser as it
happens.

Nothing on the page is scripted. Each sealed note, safety check and transaction
row appears because the code that produced it just finished. The first run made
signet transaction
[`3bf3169e…c7edef`](https://mutinynet.com/tx/3bf3169ea0b680f0c4bb7fa3ac7623eeb3eaa100ad01d1aebb4151fd1bc7edef),
confirmed in block 3,428,207.

## Run it

You need two signet wallets, one for each side. Run this twice and save the two
outputs as `alice.env` and `bob.env`:

```bash
cargo run -p pjn-receiver -- keygen
```

Fund both from <https://faucet.mutinynet.com>. **Bob needs coins too.** A payjoin
receiver has to add one of its own coins, so a Bob with an empty wallet cannot take
part at all.

Then start Theater:

```bash
demo/theater.sh alice.env bob.env
```

Open <http://127.0.0.1:7777>. Syncing both wallets takes a few seconds before the
page is ready.

## The five-step story

The strip across the top of the page highlights what to do next.

1. **Bob asks for a payment.** His request names a key made for this one payment.
2. **Switch Bob offline.** This is what makes the demo worth watching.
3. **Alice pays anyway.** A sealed note lands on the relay board and waits there.
   Nobody is listening for it.
4. **Bring Bob back online.** He picks up the note, runs his four checks, adds a
   coin, and sends his reply back. Alice checks his changes, signs, and broadcasts.
5. **See what the world sees.** The confirmed transaction appears, read the way a
   chain analyst reads it. Toggle to see what actually happened.

With the receiver offline, this payment would be impossible under BIP78. BIP77
makes it possible, but only by adding a directory server and an OHTTP relay. Here,
public relays that already exist do that job.

## What each part shows

**Relay board.** What the relays actually store, taken from the published event:

- kind 1059;
- the throwaway key that signed it, which is not the sender's;
- the fake timestamp NIP-59 wrote on it, next to when it was really sent;
- how many bytes of ciphertext it holds;
- which relays accepted it.

"Peek inside" shows what only the recipient can open. Each note links to a public
nostr viewer, so anyone can check that there is nothing more to see.

**Under the hood.** The protocol in the order it runs. Bob's four safety checks
appear one at a time, as his code passes each one.

**What the world sees.** The real transaction's inputs and outputs, with the
analyst's reading and the truth side by side. Who owns each coin comes from the
two wallets the server holds, not from a guess.

**Raw event log.** Every server event with a timestamp, for anyone who wants the
detail.

## Things to know before a live demo

- **It really spends signet coins.** Each run costs a few hundred sat in fees on top
  of the payment. Top up before recording.
- **Relays are flaky, and the page says so.** On the first run, relay.damus.io
  returned 503 and then timed out. Bob's reply was stored on the other two, and the
  page reported "2 of 3". A demo is more convincing when a failure shows up openly
  and the payment still completes.
- **It binds to 127.0.0.1 only.** The server holds both wallets' signing keys. Do
  not expose it on a network.
- **One payment request at a time.** Asking for a new payment clears the stage.
  "Reset stage" clears it without asking for a new one.
