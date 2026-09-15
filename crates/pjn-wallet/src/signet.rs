//! A BDK-backed signet wallet implementing [`ReceiverWallet`].
//!
//! Esplora rather than a full node, so the demo runs anywhere without a 30 GB
//! initial block download. That choice costs us one thing, documented honestly in
//! [`SignetWallet::can_broadcast`]: Esplora has no `testmempoolaccept`, so our
//! broadcast-suitability check is weaker than a node-backed receiver's would be.

use anyhow::{Context, Result};
use bdk_esplora::esplora_client;
use bdk_esplora::EsploraExt;
use bdk_wallet::bitcoin::{Network, OutPoint, Psbt, Script, Transaction, TxIn, TxOut};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use payjoin::receive::InputPair;
use payjoin::ImplementationError;

use crate::receiver::ReceiverWallet;

/// How far past the last used address to scan before concluding a keychain is done.
const STOP_GAP: usize = 20;
/// Concurrent Esplora requests. Public instances rate limit, so keep this modest.
const PARALLEL_REQUESTS: usize = 4;

pub struct SignetWallet {
    wallet: Wallet,
    client: esplora_client::BlockingClient,
}

impl SignetWallet {
    /// Build a wallet from an external and internal descriptor.
    ///
    /// Descriptors carry their own network, so a mainnet descriptor passed here is
    /// rejected rather than silently treated as signet — worth being strict about,
    /// since the failure mode is spending real money in a demo.
    pub fn new(descriptor: &str, change_descriptor: &str, esplora_url: &str) -> Result<Self> {
        let wallet = Wallet::create(descriptor.to_string(), change_descriptor.to_string())
            .network(Network::Signet)
            .create_wallet_no_persist()
            .context("building signet wallet from descriptors")?;

        // build_blocking() is infallible; the URL is only contacted on first use.
        let client = esplora_client::Builder::new(esplora_url).build_blocking();

        Ok(Self { wallet, client })
    }

    /// Full scan: discovers history for a wallet we know nothing about yet.
    pub fn full_scan(&mut self) -> Result<()> {
        let request = self.wallet.start_full_scan();
        let update = self
            .client
            .full_scan(request, STOP_GAP, PARALLEL_REQUESTS)
            .context("esplora full scan")?;
        self.wallet
            .apply_update(update)
            .context("applying full scan to wallet")?;
        Ok(())
    }

    /// Incremental sync of already-revealed scripts.
    pub fn sync(&mut self) -> Result<()> {
        let request = self.wallet.start_sync_with_revealed_spks();
        let update = self
            .client
            .sync(request, PARALLEL_REQUESTS)
            .context("esplora sync")?;
        self.wallet
            .apply_update(update)
            .context("applying sync to wallet")?;
        Ok(())
    }

    /// Reveal the next unused receiving address.
    pub fn next_address(&mut self) -> bdk_wallet::AddressInfo {
        self.wallet.reveal_next_address(KeychainKind::External)
    }

    pub fn balance(&self) -> bdk_wallet::Balance {
        self.wallet.balance()
    }

    pub fn spendable_utxo_count(&self) -> usize {
        self.wallet.list_unspent().count()
    }

    /// Whether `outpoint` is one of our coins and still unspent, as of the last sync.
    ///
    /// Esplora reports mempool transactions, so a coin spent by a broadcast that has
    /// not confirmed yet already reads as spent here. That is what a resumed payment
    /// needs to avoid spending the same coins twice.
    pub fn is_unspent(&self, outpoint: OutPoint) -> bool {
        self.wallet
            .list_unspent()
            .any(|utxo| utxo.outpoint == outpoint)
    }

    /// Whether `script` pays one of this wallet's addresses.
    pub fn owns_script(&self, script: &Script) -> bool {
        self.wallet.is_mine(script.into())
    }

    /// Block height `txid` confirmed at, or `None` while it is still unconfirmed.
    pub fn confirmation_height(&self, txid: &bdk_wallet::bitcoin::Txid) -> Result<Option<u32>> {
        let status = self
            .client
            .get_tx_status(txid)
            .context("checking transaction status")?;
        Ok(if status.confirmed {
            status.block_height
        } else {
            None
        })
    }

    /// Broadcast a finished transaction.
    pub fn broadcast(&self, tx: &Transaction) -> Result<()> {
        self.client
            .broadcast(tx)
            .context("broadcasting transaction")
    }

    /// Build and sign the Original PSBT a payjoin sender starts from.
    ///
    /// BIP78 requires this to be fully signed and broadcastable before it is
    /// shown to the receiver. That is what makes it a usable fallback, and it is
    /// also what stops a sender from using payjoin requests to probe a receiver's
    /// UTXO set for free — the sender has to commit real, spendable coins first.
    pub fn create_original_psbt(
        &mut self,
        recipient: &bdk_wallet::bitcoin::Address,
        amount: bdk_wallet::bitcoin::Amount,
        fee_rate: bdk_wallet::bitcoin::FeeRate,
    ) -> Result<Psbt> {
        let mut psbt = {
            let mut builder = self.wallet.build_tx();
            builder
                .add_recipient(recipient.script_pubkey(), amount)
                .fee_rate(fee_rate);
            builder
                .finish()
                .context("building the original transaction")?
        };

        let finalized = self
            .wallet
            .sign(&mut psbt, SignOptions::default())
            .context("signing the original PSBT")?;
        anyhow::ensure!(
            finalized,
            "could not fully sign the original PSBT — payjoin requires a \
             broadcastable original before the receiver will engage"
        );
        Ok(psbt)
    }

    /// Sign our inputs in a validated Payjoin Proposal and extract the final tx.
    ///
    /// Only ever call this on a PSBT that has been through
    /// [`crate::sender::validate_proposal`]. The receiver rewrote this
    /// transaction, and signing an unvalidated rewrite is how a sender loses
    /// money.
    pub fn finalize_payjoin(&self, psbt: &Psbt) -> Result<Transaction> {
        let mut psbt = psbt.clone();
        let options = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };
        self.wallet
            .sign(&mut psbt, options)
            .context("signing the payjoin proposal")?;

        psbt.clone()
            .extract_tx()
            .context("extracting the final payjoin transaction")
    }

    /// Build the [`InputPair`] payjoin needs from one of our UTXOs.
    ///
    /// Only `witness_utxo` is populated, which is correct for the segwit
    /// descriptors this wallet is built for and would be wrong for legacy inputs.
    /// A legacy-capable receiver has to supply `non_witness_utxo` (the whole
    /// previous transaction) instead.
    fn to_input_pair(outpoint: OutPoint, txout: TxOut) -> Result<InputPair, ImplementationError> {
        let txin = TxIn {
            previous_output: outpoint,
            ..Default::default()
        };
        let psbtin = bdk_wallet::bitcoin::psbt::Input {
            witness_utxo: Some(txout),
            ..Default::default()
        };
        InputPair::new(txin, psbtin, None).map_err(ImplementationError::new)
    }
}

impl ReceiverWallet for SignetWallet {
    /// Whether the Original PSBT could be broadcast as a fallback.
    ///
    /// **This is weaker than it should be.** A node-backed receiver calls
    /// `testmempoolaccept` and gets a real answer. Esplora offers no equivalent,
    /// so we verify only what we can see locally: that the transaction is
    /// structurally sane and spends no output we already know to be spent.
    ///
    /// The gap matters. A sender could offer an Original PSBT that looks fine here
    /// but would be rejected by the network, and we would contribute an input to a
    /// payjoin whose fallback can never confirm. Point a real node at this before
    /// treating the receiver as production-ready; see `docs/threat-model.md`.
    fn can_broadcast(&self, tx: &Transaction) -> Result<bool, ImplementationError> {
        if tx.input.is_empty() || tx.output.is_empty() {
            return Ok(false);
        }
        // Any input we can see as already spent means this cannot confirm.
        for txin in &tx.input {
            if let Some(utxo) = self.wallet.get_utxo(txin.previous_output) {
                if utxo.is_spent {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn is_owned(&self, outpoint: &OutPoint) -> Result<bool, ImplementationError> {
        Ok(self.wallet.get_utxo(*outpoint).is_some())
    }

    fn is_receiver_output(&self, script: &Script) -> Result<bool, ImplementationError> {
        Ok(self.wallet.is_mine(script.into()))
    }

    fn candidate_inputs(&self) -> Result<Vec<InputPair>, ImplementationError> {
        self.wallet
            .list_unspent()
            .filter(|utxo| !utxo.is_spent)
            .map(|utxo| Self::to_input_pair(utxo.outpoint, utxo.txout))
            .collect()
    }

    /// Sign our contributed inputs.
    ///
    /// BDK signs only what it holds keys for, so the sender's inputs are left
    /// untouched as a matter of capability rather than policy — we could not sign
    /// them if we wanted to.
    fn sign_psbt(&self, psbt: &Psbt) -> Result<Psbt, ImplementationError> {
        let mut psbt = psbt.clone();
        let options = SignOptions {
            // The sender's inputs carry witness_utxo without the full previous
            // transaction. Without this, BDK refuses to sign alongside them.
            trust_witness_utxo: true,
            ..Default::default()
        };
        self.wallet
            .sign(&mut psbt, options)
            .map_err(ImplementationError::new)?;
        Ok(psbt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bdk_wallet::bitcoin::bip32::Xpriv;

    /// The BIP32 test-vector-1 seed. Deriving the key here rather than pasting a
    /// literal keeps the test honest: a mistyped xprv would otherwise fail as a
    /// checksum error and look like a wallet bug.
    const SEED: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    fn descriptors_for(network: Network) -> (String, String) {
        let master = Xpriv::new_master(network, &SEED).expect("test vector seed is valid");
        (
            format!("wpkh({master}/84'/1'/0'/0/*)"),
            format!("wpkh({master}/84'/1'/0'/1/*)"),
        )
    }

    fn descriptors() -> (String, String) {
        descriptors_for(Network::Signet)
    }

    #[test]
    fn builds_a_signet_wallet_from_descriptors() {
        let (ext, int) = descriptors();
        // Esplora URL is not contacted at construction time.
        let wallet = SignetWallet::new(&ext, &int, "https://mutinynet.com/api");
        assert!(wallet.is_ok(), "{:?}", wallet.err());
    }

    #[test]
    fn a_fresh_wallet_has_no_candidate_inputs() {
        let (ext, int) = descriptors();
        let wallet = SignetWallet::new(&ext, &int, "https://mutinynet.com/api").unwrap();
        // An unsynced wallet must offer nothing rather than panicking; the
        // receiver turns this into a clear "no UTXOs to contribute" error.
        assert!(wallet.candidate_inputs().unwrap().is_empty());
    }

    #[test]
    fn rejects_a_structurally_empty_transaction() {
        let (ext, int) = descriptors();
        let wallet = SignetWallet::new(&ext, &int, "https://mutinynet.com/api").unwrap();
        let empty = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        assert!(!wallet.can_broadcast(&empty).unwrap());
    }

    #[test]
    fn mainnet_descriptors_are_rejected() {
        // Guards against a demo accidentally pointing at real money.
        let (ext, int) = descriptors_for(Network::Bitcoin);
        assert!(SignetWallet::new(&ext, &int, "https://mutinynet.com/api").is_err());
    }
}
