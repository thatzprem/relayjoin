//! Build a static replay page from a Theater recording.
//!
//! A recording is the exact stream of events one real run sent to the page, with
//! timestamps, captured by `pjn-theater --record`. This tool injects it into the
//! same page Theater serves. When the page finds a recording, it plays it back
//! instead of connecting to a server.
//!
//! The output is a single HTML file with no server, no wallet and no keys. It can
//! be hosted anywhere that serves static files, and nobody visiting it can spend
//! anything, because there is nothing there to spend.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{json, Value};

/// Strings that must never appear in a published page.
///
/// The recording format never contains key material. A replay is published to
/// the open internet, though, so this is checked rather than assumed.
const FORBIDDEN: &[&str] = &[
    "tprv",
    "xprv",
    "secret_key",
    "session_secret",
    "PJN_DESCRIPTOR",
];

#[derive(Parser)]
#[command(
    name = "pjn-replay",
    about = "Turn a Relayjoin Theater recording into a static replay page"
)]
struct Cli {
    /// JSON-lines recording written by `pjn-theater --record`.
    recording: PathBuf,

    /// Where to write the page.
    #[arg(long, default_value = "site/index.html")]
    out: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let raw = fs::read_to_string(&cli.recording)
        .with_context(|| format!("reading {}", cli.recording.display()))?;

    let mut header = None;
    let mut events = Vec::new();
    for (number, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .with_context(|| format!("line {} of the recording is not JSON", number + 1))?;
        match value.get("recording") {
            Some(found) => header = Some(found.clone()),
            None => events.push(value),
        }
    }
    let header = header
        .context("the recording has no header line; was it written by pjn-theater --record?")?;
    anyhow::ensure!(!events.is_empty(), "the recording has no events");

    let dropped = trim_to_story_end(&mut events);
    if dropped > 0 {
        println!("Left out {dropped} event(s) recorded after the payment confirmed.");
    }

    let payload = serde_json::to_string(&json!({ "header": header, "events": events }))?;
    for needle in FORBIDDEN {
        anyhow::ensure!(
            !payload.contains(needle),
            "the recording contains {needle:?}; refusing to build a page that could publish it"
        );
    }
    // The data is inlined inside a <script> tag. A less-than sign can only occur
    // inside a JSON string, where its unicode escape means the same thing, so
    // escaping every one guarantees the data cannot close the tag early.
    let payload = payload.replace('<', "\\u003c");

    let page = include_str!("../../static/index.html");
    let script_body = page
        .find("(() => {")
        .context("could not find the page script")?;
    let script_tag = page[..script_body]
        .rfind("<script>")
        .context("could not find the page script tag")?;

    let mut out = String::with_capacity(page.len() + payload.len() + 64);
    out.push_str(&page[..script_tag]);
    out.push_str("<script>window.PJN_REPLAY = ");
    out.push_str(&payload);
    out.push_str(";</script>\n");
    out.push_str(&page[script_tag..]);
    let out = out.replacen(
        "<title>Relayjoin Theater</title>",
        "<title>Relayjoin Theater Replay</title>",
        1,
    );

    if let Some(dir) = cli.out.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
    }
    fs::write(&cli.out, &out).with_context(|| format!("writing {}", cli.out.display()))?;

    println!(
        "Wrote {} ({} events, {} KB). It needs no server and holds no keys.",
        cli.out.display(),
        events.len(),
        out.len() / 1024
    );
    Ok(())
}

/// Cut events recorded after the story ends, and return how many were cut.
///
/// The story ends once the confirm step is done and the page has received the
/// balances that follow it. Anything later is someone clicking around after the
/// fact. Cutting at the `confirmed` event alone is not enough: the server sends
/// it before marking the step done, so the replay would end on "waiting for a
/// block" for a payment that had already confirmed.
fn trim_to_story_end(events: &mut Vec<Value>) -> usize {
    let is = |event: &Value, key: &str, value: &str| event["data"][key] == value;
    let Some(confirm_done) = events
        .iter()
        .position(|e| is(e, "type", "step") && is(e, "id", "confirm") && is(e, "status", "done"))
    else {
        return 0;
    };
    let end = events[confirm_done + 1..]
        .iter()
        .position(|e| is(e, "type", "state"))
        .map_or(confirm_done, |offset| confirm_done + 1 + offset);
    let dropped = events.len() - (end + 1);
    events.truncate(end + 1);
    dropped
}

#[cfg(test)]
mod tests {
    use super::trim_to_story_end;
    use serde_json::{json, Value};

    fn event(data: Value) -> Value {
        json!({ "t": 0, "data": data })
    }

    #[test]
    fn keeps_the_balances_that_follow_the_confirmation() {
        let mut events = vec![
            event(json!({ "type": "confirmed", "height": 1 })),
            event(json!({ "type": "step", "id": "confirm", "status": "done" })),
            event(json!({ "type": "state", "paid": true })),
            event(json!({ "type": "log", "text": "someone clicked afterwards" })),
        ];
        assert_eq!(trim_to_story_end(&mut events), 1);
        assert_eq!(events.len(), 3);
        assert_eq!(events[2]["data"]["type"], "state");
    }

    #[test]
    fn does_not_cut_at_the_confirmed_event_before_the_step_is_done() {
        let mut events = vec![
            event(json!({ "type": "confirmed", "height": 1 })),
            event(json!({ "type": "step", "id": "confirm", "status": "done" })),
        ];
        assert_eq!(trim_to_story_end(&mut events), 0);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn leaves_an_unfinished_story_alone() {
        let mut events = vec![event(
            json!({ "type": "step", "id": "invoice", "status": "done" }),
        )];
        assert_eq!(trim_to_story_end(&mut events), 0);
        assert_eq!(events.len(), 1);
    }
}
