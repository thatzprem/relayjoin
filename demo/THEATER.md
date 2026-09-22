# Payjoin Theater

A live, visual demo of payjoin over nostr. One command starts a small server on
your machine. It runs a real payer (Alice) and a real shop (Bob) against public
relays and signet, and walks you through the payment in the browser, one step at a
time.

Nothing on the page is scripted. Every locked note, safety check and transaction
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
part.

Start Theater:

```bash
demo/theater.sh alice.env bob.env
```

Open <http://127.0.0.1:7777>. Syncing both wallets takes a few seconds before the
page is ready.

## Using the page

The page is laid out top to bottom, in the order you need it.

**The five steps** across the top show where you are in the story.

**The scene** shows Alice, the public relays, and Bob. Bob has an online/offline
switch. When Alice pays, a locked note appears on the relays between them and
waits there until it is picked up. Click a note to see exactly what a relay stored.

**The Now panel** says in plain English what is happening, and gives you the one
button that moves the story on. Just keep pressing it:

1. **Create payment request.** Bob asks Alice for some bitcoin. The default is
   5,000 sat.
2. **Take Bob offline.** This is the point of the demo. Private payments like this
   normally need both people online at the same moment.
3. **Pay Bob.** Alice pays anyway. Her locked note lands on the relays, and nobody
   is listening.
4. **Bring Bob back online.** He picks up the note, checks it, adds one of his own
   coins, and replies. The panel ticks off each part as the code finishes it.
5. **Run it again**, once the payment is confirmed.

While work is under way, the panel shows a checklist of what is being done, with
each item ticking off as it completes.

**What the world sees** appears once Alice broadcasts. On one side is the reading
anyone looking at the blockchain arrives at: one person paid a large amount. On the
other is the truth: two people, and a payment amount that appears nowhere in the
transaction.

**Four collapsible sections** at the bottom hold the detail, for anyone who wants
it:

- **What the relays actually stored.** Each locked note as a relay operator sees
  it: an unknown sender, a deliberately fake timestamp, scrambled contents, and
  which relays kept it. This sits next to what is really inside, which only the
  recipient can read. Each note links to a public nostr viewer so you can check.
- **The transaction itself.** Every coin in and out. Switch between how an observer
  labels them and who really owns each one, taken from the two wallets and not
  guessed.
- **Every protocol step.** All eleven steps in the order the code ran them, with the
  real details.
- **Event log.** Raw messages from the server.

## The replay site

`site/index.html` is a recording of one real run, played back in the same page.
It is hosted at <https://payjoin-theater.vercel.app>.
It needs no server and holds no keys or coins, so it is safe to publish anywhere
static files are served. Nobody visiting it can spend anything, because there is
nothing there to spend.

It has play/pause, 1×/2×/4× speed, and a timeline with a marker for each of the
five steps. A caption says what the presenter clicked at each point. Long waits,
such as waiting for a block, are shortened, and the caption says by how much. The
payment it shows is a real transaction, linked to the block explorer. The links to
the locked notes on a nostr viewer stop working after 7 days, because the relays
are asked to delete them.

To record a new run and rebuild the page:

```bash
demo/theater.sh alice.env bob.env --record run.jsonl
```

Play the story once in the browser, then:

```bash
cargo run -p pjn-theater --bin pjn-replay -- run.jsonl --out site/index.html
```

The bundler refuses to build a page if the recording contains anything that looks
like key material. A recording only ever holds what the page shows, but a page that
will be published is checked anyway.

The bundler also ends the replay at the right moment. It cuts everything recorded
after the payment confirmed, but keeps the confirmation step and the balance update
that follow it. So you can keep clicking around after recording without spoiling
the ending.

On Windows with Smart App Control turned on, `pjn-replay.exe` may be blocked
(`os error 4551`) each time it is rebuilt, because every build is a new file with
no reputation yet. Building it in WSL2 or CI avoids that.

## Things to know before a live demo

- **It really spends signet coins.** Each run costs a few hundred sat in fees on top
  of the payment. Top up before recording.
- **Relays are flaky, and the page says so.** On the first run, relay.damus.io
  returned 503 and then timed out. Bob's reply was stored on the other two, and
  the page showed "2 of 3". A demo is more convincing when a failure shows up openly
  and the payment still completes.
- **If a step fails, nothing is lost.** The page says what went wrong. Alice still
  holds her signed backup payment. "Start again" resets the stage.
- **It binds to 127.0.0.1 only.** The server holds both wallets' signing keys. Do
  not expose it on a network.
- **Refreshing is safe.** A page opened mid-run catches up from the server.
