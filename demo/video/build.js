// Build the demo video from the replay page, with captions instead of a voice.
//
// Drives site/index.html in a headless Chromium browser, steps the replay
// timeline frame by frame (so timing is exact, not real-time), and pipes the
// screenshots to ffmpeg.
//
//   npm install
//   node build.js [out.mp4]
//
// BROWSER overrides the path to Edge or Chrome; FFMPEG overrides the ffmpeg
// binary, which otherwise must be on PATH.
const puppeteer = require("puppeteer-core");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("url");

const PAGE = pathToFileURL(path.resolve(__dirname, "../../site/index.html")).href;
const OUT = process.argv[2] || path.resolve(__dirname, "../../site/demo.mp4");
const FFMPEG = process.env.FFMPEG || "ffmpeg";
const BROWSER = process.env.BROWSER || [
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
].find((candidate) => fs.existsSync(candidate));
const W = 1600, H = 900, SCALE = 1.2, FPS = 30;

const OVERLAY_CSS = `
  .player { display: none !important; }
  /* Every frame re-renders the stage, so fades would be caught halfway. */
  *, *::before, *::after { transition: none !important; animation-duration: 0s !important; animation-delay: 0s !important; }
  #vid-caption {
    position: fixed; left: 50%; bottom: 34px; transform: translateX(-50%);
    width: min(1180px, calc(100vw - 80px)); box-sizing: border-box;
    background: rgba(8, 10, 14, 0.94); border: 1px solid rgba(255,255,255,0.08);
    border-left: 5px solid #e8a33d; border-radius: 12px;
    padding: 18px 26px; font-size: 25px; line-height: 1.4; color: #f2f2f2;
    box-shadow: 0 12px 40px rgba(0,0,0,0.5); z-index: 9998; font-weight: 500;
  }
  #vid-caption:empty { display: none; }
  #vid-caption b { color: #f0b85a; font-weight: 700; }
  #vid-card {
    position: fixed; inset: 0; z-index: 9999; background: var(--bg, #111318);
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    text-align: center; padding: 0 140px; gap: 22px; color: var(--ink, #f2f2f2);
  }
  #vid-card h1 { font-size: 88px; margin: 0; letter-spacing: -0.02em; }
  #vid-card h2 { font-size: 44px; margin: 0; line-height: 1.25; font-weight: 700; max-width: 1150px; }
  #vid-card p { font-size: 30px; margin: 0; line-height: 1.45; color: var(--soft, #b8bcc6); max-width: 1150px; }
  #vid-card .tag { font-size: 22px; letter-spacing: 0.14em; text-transform: uppercase; color: #e8a33d; font-weight: 700; }
  #vid-card .accent { color: #e8a33d; }
  #vid-card .links { font-size: 26px; line-height: 1.8; color: var(--ink, #f2f2f2); font-family: ui-monospace, Consolas, monospace; }
`;

(async () => {
  const ff = spawn(FFMPEG, [
    "-y", "-loglevel", "error",
    "-f", "image2pipe", "-framerate", String(FPS), "-c:v", "mjpeg", "-i", "-",
    "-vf", "scale=1920:1080:flags=lanczos",
    "-c:v", "libx264", "-preset", "slow", "-crf", "20", "-pix_fmt", "yuv420p",
    "-movflags", "+faststart", OUT,
  ], { stdio: ["pipe", "inherit", "inherit"] });
  const ffDone = new Promise((res, rej) => ff.on("close", (c) => (c === 0 ? res() : rej(new Error("ffmpeg exit " + c)))));

  const browser = await puppeteer.launch({
    executablePath: BROWSER,
    headless: true,
  });
  const page = await browser.newPage();
  await page.setViewport({ width: W, height: H, deviceScaleFactor: SCALE });
  await page.goto(PAGE, { waitUntil: "networkidle0" });
  await page.addStyleTag({ content: OVERLAY_CSS });
  await page.evaluate(() => {
    const cap = document.createElement("div");
    cap.id = "vid-caption";
    document.body.append(cap);
  });

  const total = await page.evaluate(() => Number(document.querySelector("input[type=range]").max));
  const marks = await page.evaluate(() =>
    [...document.querySelectorAll(".marker")].map((m) => parseFloat(m.style.left) / 100));
  console.log("replay length", total, "ms; steps at", marks.map((m) => Math.round(m * total)));

  let frames = 0;
  const write = async (buf) => {
    if (!ff.stdin.write(buf)) await new Promise((r) => ff.stdin.once("drain", r));
    frames++;
  };
  const shot = () => page.screenshot({ type: "jpeg", quality: 93 });
  const hold = async (sec) => { const b = await shot(); for (let i = 0; i < Math.round(sec * FPS); i++) await write(b); };
  const animate = async (sec, fn) => {
    const n = Math.max(1, Math.round(sec * FPS));
    for (let i = 1; i <= n; i++) { await fn(i / n); await write(await shot()); }
  };
  const ease = (t) => (t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);

  const caption = (html) => page.evaluate((h) => { document.getElementById("vid-caption").innerHTML = h; }, html);
  const seek = (ms) => page.evaluate((v) => {
    const r = document.querySelector("input[type=range]");
    r.value = String(v);
    r.dispatchEvent(new Event("input"));
  }, ms);
  const scrollY = () => page.evaluate(() => window.scrollY);
  const targetY = (selector, offset) => page.evaluate((s, o) => {
    const el = document.querySelector(s);
    return Math.max(0, el.getBoundingClientRect().top + window.scrollY - o);
  }, selector, offset);
  const scrollTo = (y) => page.evaluate((v) => window.scrollTo(0, v), y);
  const glide = async (sec, toY) => {
    const from = await scrollY();
    await animate(sec, (t) => scrollTo(from + (toY - from) * ease(t)));
  };
  const card = (html) => page.evaluate((h) => {
    let c = document.getElementById("vid-card");
    if (!c) { c = document.createElement("div"); c.id = "vid-card"; document.body.append(c); }
    c.innerHTML = h;
    c.style.opacity = "1";
  }, html);
  const cardOpacity = (o) => page.evaluate((v) => { const c = document.getElementById("vid-card"); if (c) c.style.opacity = String(v); }, o);
  const cardRemove = () => page.evaluate(() => document.getElementById("vid-card")?.remove());
  const fadeCardIn = (html, sec = 0.5) => card(html).then(() => animate(sec, (t) => cardOpacity(t)));
  const fadeCardOut = async (sec = 0.5) => { await animate(sec, (t) => cardOpacity(1 - t)); await cardRemove(); };
  const play = async (fromMs, toMs, sec) => {
    const stageY = await targetY(".stage-card", 16);
    await scrollTo(stageY);
    await animate(sec, (t) => seek(fromMs + (toMs - fromMs) * t).then(() => scrollTo(stageY)));
  };

  // 1. Title
  await seek(0);
  await card(`
    <div class="tag">BOSS Battle · Cypherpunk · Freedom Stack</div>
    <h1>Relay<span class="accent">join</span></h1>
    <p>Private Bitcoin payments that work<br>while the receiver is offline.</p>`);
  await hold(4.5);

  // 2. The problem
  await card(`
    <div class="tag">The problem</div>
    <h2>Chain analysis assumes every coin spent in a transaction belongs to <span class="accent">one person</span>.</h2>
    <p>Link one coin to you, and every coin spent beside it is linked too.</p>`);
  await hold(6.5);
  await card(`
    <div class="tag">The fix that already exists</div>
    <h2>Payjoin: the person being paid adds <span class="accent">one of their own coins</span>.</h2>
    <p>Now the transaction has two owners, the analyst's clustering is wrong,<br>and the amount paid appears nowhere on-chain.</p>`);
  await hold(7);
  await card(`
    <div class="tag">Why nobody uses it</div>
    <h2>Payjoin needs the receiver <span class="accent">online</span> at the moment of payment,<br>or a new directory server.</h2>
    <p>Relayjoin uses the nostr relays that already exist as the mailbox.<br>No server. Either side can be offline.</p>`);
  await hold(7.5);
  await card(`
    <div class="tag">What follows</div>
    <h2>A real payment on Bitcoin signet,<br>recorded on 22 September 2026.</h2>
    <p>Every step you see was produced by the running code.</p>`);
  await hold(4);
  await fadeCardOut(0.6);

  // 3. The replay. Times are positions on this recording's timeline (ms). Bob
  // starts offline by default; the presenter switched him on at 4.9 s and off
  // again at 9.9 s, so the story is cut to skip that first offline stretch.
  const BOB_ON = 4960, BOB_OFF = 9950, PAY = 14950, BOB_BACK = 25770, REPLY_IN = 32245;
  await caption("<b>Bob</b> runs a shop. He wants <b>Alice</b> to pay him 5,000 sat, privately.");
  await play(0, 700, 3);
  await caption("Bob's payment request points at <b>nostr relays</b>, not at a server of his.");
  await play(BOB_ON, BOB_OFF - 50, 7);
  await caption("<b>Bob goes offline.</b> With ordinary payjoin, the payment would stop here.");
  await play(BOB_OFF, PAY - 50, 6);
  await caption("<b>Alice pays anyway.</b> Her signed proposal is sealed in a NIP-59 gift wrap and left on three public relays.");
  await play(PAY, BOB_BACK - 50, 11);
  await hold(1.5);

  // 3b. What a relay actually learns
  await page.evaluate(() => { document.getElementById("d-relays").open = true; });
  await caption("This is <b>everything a relay operator learns</b>: a key used once, a deliberately fake timestamp, and 4 KB of scrambled data.");
  await glide(1.2, await targetY("#d-relays", 40));
  await hold(7.5);
  await caption("Only Bob can open it. Inside: Alice's signed payment, plus her limits on what he may change.");
  await hold(4.5);
  await glide(1.0, await targetY(".stage-card", 16));
  await page.evaluate(() => { document.getElementById("d-relays").open = false; });

  await caption("<b>Bob comes back online.</b> He collects the note, runs every safety check, adds <b>one of his own coins</b>, and replies the same way.");
  await play(BOB_BACK, REPLY_IN, 11);
  await caption("<b>Alice</b> checks what Bob changed, signs, and broadcasts. A block confirms it.");
  await play(REPLY_IN, total, 10);
  await hold(1.5);

  // 4. What the world sees
  await caption("");
  await glide(1.4, await targetY("#result", 330));
  await caption("<b>What the world sees:</b> one person paying. <b>What really happened:</b> two people, and 5,000 sat that appears nowhere on-chain.");
  await hold(9);

  await page.evaluate(() => { document.getElementById("d-tx").open = true; });
  await caption("The transaction itself: two inputs from <b>two different owners</b>, taken from both wallets, not guessed.");
  await glide(1.2, await targetY("#d-tx", 40));
  await hold(7);
  await caption("");

  // 5. Close
  await fadeCardIn(`
    <div class="tag">Relayjoin</div>
    <h2>Payjoin over nostr.<br><span class="accent">No directory. No server. Either side can be offline.</span></h2>
    <p>Rust · Payjoin Dev Kit 1.0 · BDK · nostr-sdk · NIP-59 gift wraps · NIP-44</p>
    <div class="links">
      relayjoin.vercel.app<br>
      github.com/thatzprem/relayjoin<br>
      signet tx f41f341e…19b9 · block 3,446,434
    </div>`, 0.7);
  await hold(8);

  await browser.close();
  ff.stdin.end();
  await ffDone;
  console.log(`wrote ${OUT}: ${frames} frames, ${(frames / FPS).toFixed(1)} s`);
})().catch((e) => { console.error(e); process.exit(1); });
