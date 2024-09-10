use crate::bitcoin::mempool::{
    error::MemPoolError, get_address_txs::TxInfo, get_address_utxo::UtxoInfo,
};
use crate::client::ClientFn;
use crate::gui::Message::BitcoinClientMsg;
use crate::gui::{Escrow, Message};
use crate::listener;
use miniscript::bitcoin::{Address, Transaction};

use self::mempool::client::MempoolClient;

pub mod bitcoind;
pub mod electrum;
pub mod mempool;

listener!(BitcoinListener, BitcoinMessage, Message, BitcoinClientMsg);

#[derive(Debug, Clone)]
#[allow(unused)]
pub enum BitcoinMessage {
    // From GUI
    WatchAddress(Address),
    Broadcast(Transaction),
    ReceiveTx(Transaction),
    GetTransactions,

    // To GUI
    UserInfoMessage(String),
    UtxoReceived(UtxoInfo),
    UtxoConfirmed(UtxoInfo),
    UtxoSpent(UtxoInfo),
    ReceiveTransactions(Vec<Transaction>),

    // Responses from mempool.space
    GetAddressUtxos(Result<Vec<UtxoInfo>, MemPoolError>),
    GetAddressTxs(Result<Vec<TxInfo>, MemPoolError>),
    PostBroadcastTx(Result<(), MemPoolError>),

    // Poll Timer
    Poll,
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub enum UtxoState {
    Unconfirmed,
    Confirmed,
    Spent,
    Unknown,
}

#[allow(unused)]
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TxOut {
    txid: String,
    vout: u32,
    value: i64,
}

pub enum BackendType {
    Mempool,
    Electrum,
    Bitcoind,
}

pub enum BackendClient {
    Mempool(MempoolClient),
    Electrum,
    Bitcoind,
}

pub struct BitcoinBackend {
    client: BackendClient,
    gui_sender: Option<Sender<BitcoinMessage>>,
    gui_receiver: Option<Receiver<BitcoinMessage>>,
}

impl BitcoinBackend {
    pub fn new(kind: BackendType) -> Self {
        let (bitcoin_sender, gui_bitcoin_receiver) = async_channel::unbounded();
        let (gui_bitcoin_sender, bitcoin_receiver) = async_channel::unbounded();

        match kind {
            BackendType::Mempool => {
                let client = MempoolClient::new(
                    bitcoin_sender,
                    bitcoin_receiver,
                    gui_bitcoin_sender.clone(),
                );
                let gui_sender = Some(gui_bitcoin_sender);
                let gui_receiver = Some(gui_bitcoin_receiver);
                BitcoinBackend {
                    client: BackendClient::Mempool(client),
                    gui_sender,
                    gui_receiver,
                }
            }
            BackendType::Electrum => todo!(),
            BackendType::Bitcoind => todo!(),
        }
    }

    pub fn gui_sender(&mut self) -> Sender<BitcoinMessage> {
        self.gui_sender.take().unwrap()
    }

    pub fn gui_receiver(&mut self) -> Receiver<BitcoinMessage> {
        self.gui_receiver.take().unwrap()
    }

    pub fn start(self) {
        match self.client {
            BackendClient::Mempool(client) => client.start(),
            BackendClient::Electrum => todo!(),
            BackendClient::Bitcoind => todo!(),
        }
    }
}
