use crate::bitcoin::{
    mempool::{
        error::MemPoolError,
        get_address_txs::{get_addresses_txs, TxInfo},
        get_address_utxo::{get_addresses_utxos, UtxoInfo},
        post_transaction::post_transaction,
    },
    BitcoinMessage, UtxoState,
};
use crate::client::ClientFn;
use async_channel::{Receiver, Sender};
use miniscript::bitcoin::{Address, Network, Transaction};
use nostr_sdk::async_utility::tokio;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

#[allow(unused)]
pub struct MempoolClient {
    network: Network,
    sender: Sender<BitcoinMessage>,
    receiver: Receiver<BitcoinMessage>,
    utxos: HashMap<String, HashMap<UtxoInfo, UtxoState>>,
    loopback: Sender<BitcoinMessage>,
}

impl MempoolClient {
    pub fn start(mut self) {
        tokio::spawn(async move {
            self.run().await;
        });
    }

    fn send_to_gui(&mut self, msg: BitcoinMessage) {
        let sender = self.sender.clone();
        Self::send(sender, msg);
    }

    fn send(sender: Sender<BitcoinMessage>, msg: BitcoinMessage) {
        tokio::spawn(async move {
            if sender.send(msg).await.is_err() {
                log::error!("MempoolClient.send_to_gui() => Cannot send message to GUI!")
            }
        });
    }

    #[allow(unused)]
    pub fn get_addr_txs(&self, addr: Address) {
        let sender = self.loopback.clone();
        let network = self.network;
        tokio::spawn(async move {
            let response = get_addresses_txs(addr, network).await;
            if sender
                .send(BitcoinMessage::GetAddressTxs(response))
                .await
                .is_err()
            {
                log::error!("MempoolClient.get_addr_txs() => cannot send response!")
            }
        });
    }

    fn handle_get_addr_txs_response(&mut self, response: Result<Vec<TxInfo>, MemPoolError>) {
        match response {
            Ok(r) => {
                let txs: Vec<_> = r.into_iter().map(Transaction::from).collect();
                self.send_to_gui(BitcoinMessage::ReceiveTransactions(txs))
            }
            Err(e) => {
                log::error!("get_addr_txs_response() fail: {:?}", e);
            }
        }
    }

    pub fn get_utxos(&self) {
        self.utxos.keys().for_each(|addr| {
            let addr = Address::from_str(addr)
                .expect("Should not fail parsing address")
                .assume_checked();
            self.get_addr_utxo(addr);
        });
    }

    pub fn get_addr_utxo(&self, addr: Address) {
        log::info!("get_addr_utxo({:?})", addr);
        let sender = self.loopback.clone();
        let network = self.network;
        tokio::spawn(async move {
            let response = get_addresses_utxos(addr, network).await;
            if sender
                .send(BitcoinMessage::GetAddressUtxos(response))
                .await
                .is_err()
            {
                log::error!("MempoolClient.get_addr_utxo() => cannot send response!")
            }
        });
    }

    fn handle_get_addr_utxos_response(&mut self, response: Result<Vec<UtxoInfo>, MemPoolError>) {
        let response = match response {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("Fail to get utxos: {:?}", e);
                self.send_to_gui(BitcoinMessage::UserInfoMessage(msg));
                return;
            }
        };

        response
            .into_iter()
            .for_each(|info| self.try_update_utxo(info));
    }

    fn try_update_utxo(&mut self, info: UtxoInfo) {
        if let Some(addr) = &info.address {
            // if address in our watchlist
            if self.utxos.contains_key(&addr.to_string()) {
                self.update_utxo(info);
            } else {
                log::error!("UtxoInfo Address does not mach our watchlist!")
            }
        } else {
            panic!("UtxoInfo should have an address!");
        }
    }

    fn update_utxo(&mut self, info: UtxoInfo) {
        let addr = info
            .address
            .clone()
            .expect("Should not miss address")
            .to_string();

        // TODO: find a way to detect Spent state
        let state = if info.status.confirmed {
            UtxoState::Confirmed
        } else {
            UtxoState::Unconfirmed
        };

        let gui_sender = self.sender.clone();
        if self.utxos.contains_key(&addr) {
            self.utxos.entry(addr).and_modify(|entry| {
                match entry.entry(info.clone()) {
                    Entry::Occupied(mut utxo) => {
                        match (utxo.get().clone(), &state) {
                            (UtxoState::Unconfirmed, UtxoState::Confirmed) => {
                                Self::send(
                                    gui_sender.clone(),
                                    BitcoinMessage::UtxoConfirmed(info.clone()),
                                );
                                utxo.insert(state);
                            }
                            (UtxoState::Confirmed, UtxoState::Spent) => {
                                Self::send(
                                    gui_sender.clone(),
                                    BitcoinMessage::UtxoSpent(info.clone()),
                                );
                                panic!("not yet implemented")
                                // TODO
                            }
                            (UtxoState::Unconfirmed, UtxoState::Unconfirmed) => { /* do nothing */ }
                            (entry, state) => {
                                log::debug!("Entry:{:?}, UtxoState:{:?}", entry, state);
                                // panic!("Should be filtered out early!")
                            }
                        }
                    }
                    Entry::Vacant(entry) => {
                        match &state {
                            UtxoState::Unconfirmed => {
                                Self::send(
                                    gui_sender.clone(),
                                    BitcoinMessage::UtxoReceived(info.clone()),
                                );
                            }
                            UtxoState::Confirmed => {
                                Self::send(
                                    gui_sender.clone(),
                                    BitcoinMessage::UtxoReceived(info.clone()),
                                );
                                Self::send(
                                    gui_sender.clone(),
                                    BitcoinMessage::UtxoConfirmed(info.clone()),
                                );
                            }
                            _ => {
                                // panic!("Should be sorted out early")
                            }
                        }
                        entry.insert(state);
                    }
                }
            });
        }
    }

    pub fn broadcast_tx(&self, tx: Transaction) {
        let sender = self.loopback.clone();
        let network = self.network;
        tokio::spawn(async move {
            let response = post_transaction(tx, network).await;
            if sender
                .send(BitcoinMessage::PostBroadcastTx(response))
                .await
                .is_err()
            {
                log::error!("MempoolClient.get_addr_utxo() => cannot send response!")
            }
        });
    }

    fn handle_broadcast_tx_response(&mut self, _response: Result<(), MemPoolError>) {
        // TODO
    }

    fn poll_later(&self) {
        let loopback = self.loopback.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if loopback.send(BitcoinMessage::Poll).await.is_err() {
                log::debug!("Fail to send Poll Message")
            };
        });
    }

    pub fn try_poll_mempool(&mut self) {
        log::info!("try_poll_mempool()");
        self.get_utxos();
    }
}

impl ClientFn<BitcoinMessage, Sender<BitcoinMessage>> for MempoolClient {
    fn new(
        sender: Sender<BitcoinMessage>,
        receiver: Receiver<BitcoinMessage>,
        loopback: Sender<BitcoinMessage>,
    ) -> Self {
        MempoolClient {
            network: Network::Signet,
            sender,
            receiver,
            utxos: HashMap::new(),
            loopback,
        }
    }

    async fn run(&mut self) {
        #[allow(clippy::empty_loop)]
        // start poll timer
        self.poll_later();
        loop {
            if let Ok(msg) = self.receiver.try_recv() {
                log::info!("MempoolClient.run() msg: {:?}", msg);
                match msg {
                    // From GUI
                    BitcoinMessage::WatchAddress(addr) => {
                        match self.utxos.entry(addr.to_string()) {
                            Entry::Occupied(_) => {
                                log::error!("Already watching address {:?}", addr);
                            }
                            Entry::Vacant(entry) => {
                                entry.insert(HashMap::new());
                            }
                        }
                    }
                    BitcoinMessage::Broadcast(tx) => {
                        self.broadcast_tx(tx);
                    }
                    BitcoinMessage::GetTransactions => {
                        for addr in self.utxos.keys() {
                            let address = Address::from_str(addr).unwrap().assume_checked();
                            self.get_addr_txs(address)
                        }
                    }

                    // Response from mempool.space request
                    BitcoinMessage::PostBroadcastTx(response) => {
                        self.handle_broadcast_tx_response(response);
                    }
                    BitcoinMessage::GetAddressTxs(response) => {
                        self.handle_get_addr_txs_response(response);
                    }
                    BitcoinMessage::GetAddressUtxos(response) => {
                        self.handle_get_addr_utxos_response(response);
                    }
                    //
                    BitcoinMessage::Poll => {
                        self.poll_later();
                        self.try_poll_mempool();
                    }
                    _ => {
                        log::error!("MempoolClient unhandled Message")
                    }
                }
            }

            tokio::time::sleep(Duration::from_nanos(10)).await;
        }
    }
}
