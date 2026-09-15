//! Diagnostic for the stored-event backlog bug.
//!
//! Splits one question into three, because "the receiver didn't get it" has at
//! least three distinct causes and guessing between them is wasteful:
//!
//! 1. Did the relays store the event at all?
//! 2. Does our `recv` filter match it?
//! 3. Does `recv` actually deliver a stored event, or only live ones?
//!
//! Ignored by default; needs network.
//!
//! ```text
//! PJN_EVENT_ID=<hex> PJN_SESSION_PUBKEY=<hex> \
//!   cargo test -p pjn-transport --test backlog_diagnostic -- --ignored --nocapture
//! ```

use std::time::Duration;

use nostr_sdk::prelude::*;

fn relays() -> Vec<String> {
    std::env::var("PJN_RELAYS")
        .unwrap_or_else(|_| "wss://relay.damus.io,wss://nos.lol".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

async fn connect() -> Client {
    let client = Client::new();
    for url in relays() {
        client.add_relay(url.as_str()).await.expect("add relay");
    }
    client.connect().await;
    // Give both connections a moment before issuing a REQ.
    tokio::time::sleep(Duration::from_secs(3)).await;
    client
}

#[tokio::test]
#[ignore = "requires network"]
async fn is_the_event_still_on_the_relays() {
    let Ok(event_id) = std::env::var("PJN_EVENT_ID") else {
        eprintln!("set PJN_EVENT_ID to the gift wrap id to look for");
        return;
    };
    let id = EventId::from_hex(&event_id).expect("PJN_EVENT_ID must be 64 hex chars");

    let client = connect().await;
    let found = client
        .fetch_events(Filter::new().id(id))
        .timeout(Duration::from_secs(20))
        .await
        .expect("fetch by id");

    eprintln!("--- Q1: do the relays still have this event? ---");
    eprintln!("event {event_id}: {} copies returned", found.len());
    for event in &found {
        eprintln!(
            "  kind={} created_at={} (secs {}) p_tags={:?}",
            event.kind.as_u16(),
            event.created_at.as_secs(),
            event.created_at.as_secs(),
            event
                .tags
                .iter()
                .filter_map(|t| t.content())
                .collect::<Vec<_>>()
        );
    }
    client.shutdown().await;

    assert!(
        !found.is_empty(),
        "relays no longer hold the event; the bug is retention, not retrieval"
    );
}

#[tokio::test]
#[ignore = "requires network"]
async fn does_our_recv_filter_match_the_backlog() {
    let Ok(pubkey) = std::env::var("PJN_SESSION_PUBKEY") else {
        eprintln!("set PJN_SESSION_PUBKEY to the receiver's session key");
        return;
    };
    let pk = PublicKey::from_hex(&pubkey).expect("PJN_SESSION_PUBKEY must be 64 hex chars");

    let client = connect().await;

    // The now-relative bound recv USED to build, kept deliberately: a narrow miss
    // here is the since-window bug. recv now uses
    // pjn_transport::backlog_since(session creation time).
    let since = Timestamp::now() - Duration::from_secs(2 * 24 * 3600 + 3600);
    let narrow = Filter::new().kind(Kind::GiftWrap).pubkey(pk).since(since);

    // The same filter with no time bound, to isolate `since` as the culprit.
    let wide = Filter::new().kind(Kind::GiftWrap).pubkey(pk);

    let narrow_hits = client
        .fetch_events(narrow)
        .timeout(Duration::from_secs(20))
        .await
        .expect("fetch narrow");
    let wide_hits = client
        .fetch_events(wide)
        .timeout(Duration::from_secs(20))
        .await
        .expect("fetch wide");

    eprintln!("--- Q2: does our filter match what is stored? ---");
    eprintln!(
        "with since={} : {} events",
        since.as_secs(),
        narrow_hits.len()
    );
    eprintln!("without since  : {} events", wide_hits.len());

    for event in &wide_hits {
        let in_window = event.created_at >= since;
        eprintln!(
            "  id={} created_at={} in_since_window={}",
            event.id,
            event.created_at.as_secs(),
            in_window
        );
    }

    client.shutdown().await;

    if wide_hits.len() > narrow_hits.len() {
        panic!(
            "the `since` bound is dropping {} stored event(s): gift wraps randomise \
             created_at up to 2 days into the PAST of publish time, so a fixed \
             now-relative window slides off them as time passes",
            wide_hits.len() - narrow_hits.len()
        );
    }
    assert!(
        !wide_hits.is_empty(),
        "no gift wraps addressed to this key are stored on any relay"
    );
}

#[tokio::test]
#[ignore = "requires network"]
async fn does_a_subscription_deliver_stored_events_as_notifications() {
    use futures_util::StreamExt;

    let Ok(pubkey) = std::env::var("PJN_SESSION_PUBKEY") else {
        eprintln!("set PJN_SESSION_PUBKEY to the receiver's session key");
        return;
    };
    let pk = PublicKey::from_hex(&pubkey).expect("PJN_SESSION_PUBKEY must be 64 hex chars");

    let client = connect().await;

    // Stream first, then REQ — the ordering NostrTransport::recv now uses.
    let mut notifications = client.notifications();
    client
        .subscribe(Filter::new().kind(Kind::GiftWrap).pubkey(pk))
        .await
        .expect("subscribe");

    eprintln!("--- Q3: does a live subscription surface the backlog? ---");
    let mut seen = 0usize;
    let deadline = tokio::time::sleep(Duration::from_secs(25));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = &mut deadline => break,
            maybe = notifications.next() => {
                let Some(notification) = maybe else { break };
                if let ClientNotification::Event { event, .. } = notification {
                    seen += 1;
                    eprintln!("  notification: id={} kind={}", event.id, event.kind.as_u16());
                }
            }
        }
    }

    client.shutdown().await;
    eprintln!("stored events delivered as notifications: {seen}");

    assert!(
        seen > 0,
        "a subscription matching stored events produced no Event notifications — \
         recv must fetch the backlog explicitly rather than relying on the stream"
    );
}
