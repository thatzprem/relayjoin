//! Live round-trip against real nostr relays.
//!
//! Ignored by default: it needs network, and it publishes (encrypted, expiring)
//! events to public relays. Run it deliberately:
//!
//! ```text
//! cargo test -p pjn-transport --test roundtrip -- --ignored --nocapture
//! ```

use std::time::Duration;

use pjn_transport::{Leg, NostrTransport, PayjoinEnvelope};

fn relays() -> Vec<String> {
    std::env::var("PJN_RELAYS")
        .unwrap_or_else(|_| "wss://relay.damus.io,wss://nos.lol".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[tokio::test]
#[ignore = "requires network and publishes to public relays"]
async fn original_psbt_round_trips_through_public_relays() {
    let relays = relays();
    eprintln!("using relays: {relays:?}");

    // Receiver publishes this key in its payjoin URI; sender stays anonymous.
    let receiver = NostrTransport::ephemeral(&relays)
        .await
        .expect("receiver connect");
    let receiver_pk = receiver.public_key();
    eprintln!("receiver session key: {receiver_pk}");

    // Start listening before anything is sent, the way a real receiver daemon does.
    let listener = tokio::spawn(async move {
        let got = receiver.recv(Duration::from_secs(45)).await;
        receiver.shutdown().await;
        got
    });

    // Give the REQ time to land on both relays before we publish.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let sender = NostrTransport::ephemeral(&relays)
        .await
        .expect("sender connect");
    let sender_pk = sender.public_key();
    let envelope = PayjoinEnvelope {
        leg: Leg::OriginalPsbt,
        session: "roundtrip-test".to_string(),
        payload: b"not-a-real-psbt-but-opaque-to-the-transport".to_vec(),
    };
    let event_id = sender.send(receiver_pk, &envelope).await.expect("send");
    eprintln!("published gift wrap {event_id}");
    sender.shutdown().await;

    let received = listener
        .await
        .expect("listener task")
        .expect("recv did not error")
        .expect("a payjoin envelope arrived before the timeout");

    let (peer, got) = received;
    assert_eq!(got.payload, envelope.payload, "payload survived the relay");
    assert_eq!(got.session, "roundtrip-test");
    assert_eq!(got.leg, Leg::OriginalPsbt);

    // The sealed sender key is what makes reply routing work without a separate
    // handshake. If this ever regresses, the receiver cannot answer at all.
    assert_eq!(
        peer, sender_pk,
        "sealed sender key must match the real sender so the proposal can be routed back"
    );
}
