use crate::bitcoin::{BitcoinListener, BitcoinMessage};
use crate::contract::{Contract, ContractId, ContractMessage};
use crate::hot_signer::TaprootHotSigner;
use crate::mempool_space_api::get_address_utxo::UtxoInfo;
use crate::nostr::{generate_npriv, key_from_npriv, NostrListener, NostrMessage};
use crate::wallet::{create_transaction, policy_to_taproot};
use async_channel::{Receiver, SendError, Sender};
use bip39::Mnemonic;
use bitcoin_amount::Amount;
use iced::alignment::Horizontal;
use iced::keyboard::key::Named;
use iced::keyboard::{Key, Modifiers};
use iced::widget::container::Appearance;
use iced::widget::qr_code::Data;
use iced::widget::text_editor::{Action, Content, Edit};
use iced::widget::{
    container, focus_next, focus_previous, row, scrollable, Button, Column, Container, PickList,
    QRCode, Row, Space, Text, TextEditor, TextInput,
};
use iced::{
    executor, keyboard, theme, Alignment, Application, Border, Color, Element, Event, Length,
    Renderer, Subscription, Theme,
};
use iced_runtime::Command;
use miniscript::bitcoin::hashes::Hash;
use miniscript::bitcoin::{Address, Network, Transaction};
use miniscript::psbt::PsbtExt;
use nostr_sdk::{Client, Keys, PublicKey, ToBech32};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Write;
use std::ops::Add;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

const MIN_AMOUNT: f64 = 0.01;

#[derive(Debug, Serialize, Deserialize)]
pub struct Identity {
    npriv: Option<String>,
    seed: Option<Mnemonic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractState {
    None,
    Offered,
    #[allow(unused)]
    Refused,
    Accepted,
    Funded,
    Locked,
    Unlocked,
    #[allow(unused)]
    InDispute,
}

#[allow(unused)]
pub enum User {
    Me,
    Other(String),
    Escrow(String),
}

#[allow(unused)]
pub struct ChatEntry {
    user: User,
    text: String,
}

#[allow(unused)]
#[derive(Debug, Clone, Copy)]
pub enum TimelockUnit {
    Day,
    Hour,
    Block,
}

impl Display for TimelockUnit {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TimelockUnit::Day => {
                write!(f, "Day")
            }
            TimelockUnit::Hour => {
                write!(f, "Hour")
            }
            TimelockUnit::Block => {
                write!(f, "Block")
            }
        }
    }
}

impl TryFrom<String> for TimelockUnit {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value {
            s if s.to_lowercase() == "day" => Ok(TimelockUnit::Day),
            s if s.to_lowercase() == "hour" => Ok(TimelockUnit::Hour),
            s if s.to_lowercase() == "block" => Ok(TimelockUnit::Block),
            _ => Err(()),
        }
    }
}

impl From<TimelockUnit> for u32 {
    fn from(value: TimelockUnit) -> u32 {
        match value {
            TimelockUnit::Day => 144,
            TimelockUnit::Hour => 6,
            TimelockUnit::Block => 1,
        }
    }
}

#[allow(unused)]
#[derive(Debug)]
pub struct Flags {
    pub nostr_sender: Sender<NostrMessage>,
    pub nostr_receiver: Receiver<NostrMessage>,
    pub bitcoin_sender: Sender<BitcoinMessage>,
    pub bitcoin_receiver: Receiver<BitcoinMessage>,
    pub network: Network,
}

#[allow(unused)]
#[derive(Debug, PartialEq, Eq)]
pub enum Side {
    Buyer,
    Seller,
    Escrow,
    None,
}

impl Display for Side {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Side::Buyer => write!(f, "buyer"),
            Side::Seller => write!(f, "seller"),
            Side::Escrow => write!(f, "escrow"),
            Side::None => write!(f, "none"),
        }
    }
}

#[allow(unused)]
pub struct Escrow {
    min_width: f32,
    min_height: f32,
    step: Step,
    npriv: String,
    npriv_error: Option<String>,
    nostr_keys: Option<Keys>,
    nostr_client: Option<Client>,
    nostr_receiver: Receiver<NostrMessage>,
    nostr_sender: Sender<NostrMessage>,
    bitcoin_receiver: Receiver<BitcoinMessage>,
    bitcoin_sender: Sender<BitcoinMessage>,
    connect_code: String,
    npub: String,
    peer_npub: Option<PublicKey>,
    peer_npub_str: String,
    contract: Option<Contract>,
    contract_state: ContractState,
    side: Side,
    chat_input: String,
    chat_history: Vec<ChatEntry>,
    total_amount: String,
    deposit_amount: String,
    timelock: String,
    contract_text: Content,
    timelock_unit: TimelockUnit,
    deposit_address: Option<String>,
    qr: Option<Data>,
    withdraw_address: String,
    received_utxos: Vec<UtxoInfo>,
    locked_utxos: Vec<UtxoInfo>,
    transactions: Vec<Transaction>,
    network: Network,
    hot_signer: Option<TaprootHotSigner>,
}

impl Escrow {
    fn send_nostr_msg(&self, msg: NostrMessage) {
        // log::debug!("Escrow.send_nostr_msg({:?})", msg);
        let sender = self.nostr_sender.clone();
        tokio::spawn(async move { sender.send(msg).await });
    }

    #[allow(unused)]
    fn send_bitcoin_msg(&self, msg: BitcoinMessage) {
        let sender = self.bitcoin_sender.clone();
        tokio::spawn(async move { sender.send(msg).await });
    }

    fn offer_contract(&mut self) {
        // log::debug!("offer_contract()");
        // generate a new contract
        let amount: f64 =
            FromStr::from_str(&self.total_amount).expect("Should be validated on input!");

        let deposit = f64::from_str(&self.deposit_amount)
            .ok()
            .map(Amount::from_btc);

        let peer_npub = self.peer_npub.expect("Should be catch early!");

        let my_npub = self
            .nostr_keys
            .as_ref()
            .expect("Should have keys")
            .public_key();

        // Build initial contract
        let mut contract = Contract::new(self.network)
            .buyer(peer_npub)
            .seller(my_npub)
            .amount(Amount::from_btc(amount))
            .deposit(deposit)
            .details(&self.contract_text.text());

        let timelock = u32::from_str(&self.timelock).ok();
        match timelock {
            Some(tl) if tl > 0 => {
                contract.set_timelock(tl, self.timelock_unit);
            }
            _ => {}
        }

        // TODO: Handle 3rd partys

        let keys = self.nostr_keys.as_ref().expect("Should have keys");
        contract.prepare_offer(keys).expect("Should not fail");

        let origin = contract.get_derivation_path().unwrap();
        let seller_signer = self.hot_signer.as_mut().unwrap();

        let seller_xpub = seller_signer.concrete_at(origin);

        contract.set_seller_xpub(seller_xpub);

        self.contract = Some(contract.clone());
        self.send_nostr_msg(NostrMessage::Contract(Box::new(ContractMessage::Offer(
            contract,
            self.peer_npub.expect("Cannot fail"),
        ))));
    }

    fn contract_offered(&mut self, contract: Contract, _peer: PublicKey) {
        // log::info!("Escrow.contract_offered({:?})", contract);
        // TODO: double check peer

        if self.contract_state != ContractState::None {
            return;
        }

        if !contract.check_seller_signature() {
            panic!(
                "Escrow.contract_offered() => Invalid or missing seller signature: {:?}",
                contract
            );
        }

        self.contract = Some(contract.clone());
        self.contract_state = ContractState::Offered;
        self.contract_text = Content::new();
        self.contract_text
            .perform(Action::Edit(Edit::Paste(Arc::new(contract.get_details()))));
        // self.total_amount = (contract.get_amount().into_inner() as f64 / 100000000.0).to_string();
        self.total_amount = (contract.get_amount().into_inner() as f64 / 100_000_000.0).to_string();
        self.deposit_amount = if let Some(deposit) = contract.get_deposit() {
            (deposit.into_inner() as f64 / 100_000_000.0).to_string()
        } else {
            "".to_string()
        };
        if let Some(timelock) = contract.get_timelock() {
            self.timelock = timelock.to_string();
        }
        self.timelock_unit = TimelockUnit::Block;
    }

    fn accept_contract(&mut self) {
        log::debug!("Escrow.accept_contract()");

        // log::info!("contract={:?}", self.contract);
        let contract = self.contract.as_mut().expect("Should have a contract!");

        let origin = contract.get_derivation_path().unwrap();
        let buyer_signer = self.hot_signer.as_mut().unwrap();

        let buyer_xpub = buyer_signer.concrete_at(origin);

        contract.set_buyer_xpub(buyer_xpub);

        let keys = self.nostr_keys.as_ref().unwrap();
        contract.accept_contract(keys).unwrap();

        let msg = NostrMessage::Contract(Box::new(ContractMessage::Accept(
            contract.clone(),
            self.peer_npub.unwrap(),
        )));
        self.send_nostr_msg(msg);

        self.contract_state = ContractState::Accepted;
        self.save_contract();
        // start watching address
        let addr = self.contract.as_ref().unwrap().get_address().unwrap();
        self.deposit_address = Some(addr.clone().to_string());
        self.qr = Some(Data::new(addr.clone().to_string()).unwrap());
        self.send_bitcoin_msg(BitcoinMessage::WatchAddress(addr));
    }

    fn contract_accepted(&mut self, contract: Contract) {
        log::debug!("Escrow.contract_accepted()");
        // TODO: double check id & peer
        if self.contract_state != ContractState::Offered {
            panic!("Escrow.contract_accepted() Wrong contract state");
        }

        if !contract.check_buyer_signature() {
            panic!("Escrow.contract_accepted_from_peer() => Invalid or missing signature!");
        }

        self.contract = Some(contract);
        self.contract_state = ContractState::Accepted;

        self.save_contract();

        // start watching address
        let addr = self.contract.as_ref().unwrap().get_address().unwrap();
        self.send_bitcoin_msg(BitcoinMessage::WatchAddress(addr));
    }

    fn refuse_contract(&mut self) {
        log::debug!("RefuseContract");
        if let (Some(contract), Some(keys)) = (self.contract.as_mut(), self.nostr_keys.as_ref()) {
            contract.refuse_contract(keys).unwrap();
            log::debug!("contract.get_id()={:?}", contract.get_id());
            log::debug!("self.peer_npub()={:?}", self.peer_npub);
            let id = contract.get_id().unwrap();
            let peer_npub = self.peer_npub.unwrap();
            let msg = NostrMessage::Contract(Box::new(ContractMessage::Refuse(id, peer_npub)));
            self.send_nostr_msg(msg);
            self.contract_state = ContractState::None;
        }
    }

    fn contract_refused(&mut self, id: ContractId, _peer: PublicKey) {
        // TODO: take a contract as arg instead and check signature w/ ContractState::Refused

        log::debug!("Escrow.contract_refused()");

        // TODO: check signature of refused contract
        if !(self.contract_state == ContractState::Offered && self.side == Side::Seller) {
            log::error!(
                "Escrow.contract_refused() => wrong state {:?} or side {:?}",
                &self.contract_state,
                &self.side,
            );
            return;
        }
        // TODO: double check peer & signature
        if let Some(contract) = &self.contract {
            if let Ok(cid) = contract.hash(crate::contract::ContractState::Refused) {
                if id == cid {
                    self.contract_state = ContractState::None;
                } else {
                    panic!("contract id does not match!");
                }
            } else {
                panic!("contract id missing");
            }
        } else {
            panic!("contract missing");
        }
    }

    fn get_transactions(&self) {
        self.send_bitcoin_msg(BitcoinMessage::GetTransactions);
    }

    fn receive_transactions(&mut self, txs: Vec<Transaction>) {
        self.transactions = txs;
        let address = Address::from_str(&self.withdraw_address).ok();
        if let (Some(addr), Some(preimage)) =
            (address, self.contract.as_ref().unwrap().get_preimage())
        {
            // TODO: check network
            let addr = addr.assume_checked();
            let preimage_slice = &preimage.try_into().unwrap();
            self.withdraw(preimage_slice, addr);
        }
    }

    fn withdraw(&mut self, preimage: &[u8; 32], address: Address) {
        let contract = self.contract.as_mut().unwrap();
        let hash = contract.get_buyer_hash().unwrap();
        let hash = miniscript::bitcoin::hashes::sha256::Hash::from_byte_array(hash);
        let utxos = self.locked_utxos.clone();

        let signer = self.hot_signer.as_mut().unwrap();

        let policy = contract.build_wallet_policy().unwrap();
        let descriptor = policy_to_taproot(policy, self.network).unwrap();
        let fingerprints = vec![signer.fingerprint()];
        let hash = (hash, preimage);

        //  FIXME: Handle fees
        let mut psbt = create_transaction(
            descriptor,
            fingerprints,
            Some(hash),
            None,
            address,
            utxos,
            // TODO: handle txs
            self.transactions.clone(),
            1,
            self.network,
        );

        signer.sign(&mut psbt);

        PsbtExt::finalize_mut(&mut psbt, signer.secp()).unwrap();
        self.save_contract();

        log::debug!("Finalized PSBT: {}", psbt);

        let tx = psbt.extract_tx_unchecked_fee_rate();

        self.send_bitcoin_msg(BitcoinMessage::Broadcast(tx))
    }

    fn unlock_contract(&mut self) {
        self.contract_state = ContractState::Unlocked;

        let (_, preimage) = self
            .contract
            .clone()
            .unwrap()
            .process_hash_preimage(self.nostr_keys.as_ref().unwrap())
            .unwrap();

        self.send_nostr_msg(NostrMessage::Contract(Box::new(ContractMessage::Unlock(
            self.contract
                .clone()
                .expect("Contract should not miss")
                .get_id()
                .expect("Id should not miss"),
            preimage,
            self.contract
                .clone()
                .expect("Contract should not miss")
                .get_buyer_pubkey()
                .expect("Id should not miss"),
        ))));
    }

    fn contract_unlocked(&mut self, preimage: &[u8; 32]) {
        self.contract_state = ContractState::Unlocked;
        self.contract.as_mut().unwrap().store_preimage(preimage);
        self.save_contract();
    }

    fn refund(&self) {}

    fn datadir() -> PathBuf {
        #[cfg(target_os = "linux")]
        let dir = {
            let mut dir = dirs::home_dir().unwrap();
            dir.push(".escrow");
            dir
        };

        #[cfg(not(target_os = "linux"))]
        let dir = {
            let mut dir = dirs::config_dir().unwrap();
            dir.push("Escrow");
            dir
        };

        Self::maybe_create_dir(&dir);

        dir
    }

    fn maybe_create_dir(dir: &PathBuf) {
        if !dir.exists() {
            #[cfg(unix)]
            {
                use std::fs::DirBuilder;
                use std::os::unix::fs::DirBuilderExt;

                let mut builder = DirBuilder::new();
                builder.mode(0o700).recursive(true).create(dir).unwrap();
            }

            #[cfg(not(unix))]
            std::fs::create_dir_all(dir).unwrap();
        }
    }

    fn nostr_fingerprint(&self) -> String {
        self.nostr_keys.as_ref().unwrap().public_key().to_string()[..10].to_string()
    }

    fn maybe_save_identity(&self) {
        let mut dir = Self::datadir();
        dir.push(self.nostr_fingerprint());

        Self::maybe_create_dir(&dir);

        dir.push("identity");

        if !dir.exists() {
            let mut identity_file = File::create(dir).unwrap();

            let identity = Identity {
                npriv: Some(
                    self.nostr_keys
                        .as_ref()
                        .unwrap()
                        .secret_key()
                        .unwrap()
                        .to_bech32()
                        .unwrap(),
                ),
                seed: self.hot_signer.as_ref().unwrap().mnemonic(),
            };

            let yaml_str = serde_yaml::to_string(&identity).unwrap();

            identity_file.write_all(yaml_str.as_bytes()).unwrap();
        }
    }

    fn save_contract(&self) {
        self.maybe_save_identity();

        let contract_name = self
            .contract
            .as_ref()
            .unwrap()
            .hash(crate::contract::ContractState::Accepted)
            .unwrap()
            .to_string()[..20]
            .to_string();

        let mut dir = Self::datadir();
        dir.push(self.nostr_fingerprint());
        dir.push("contracts");
        dir.push(self.side.to_string());

        Self::maybe_create_dir(&dir);

        dir.push(contract_name);

        let mut contract_file = File::create(dir).unwrap();

        let contract = self.contract.clone().unwrap();

        let yaml_str = serde_yaml::to_string(&contract).unwrap();

        contract_file.write_all(yaml_str.as_bytes()).unwrap();
    }

    fn is_contract_valid(&self) -> bool {
        if let Ok(amount) = f64::from_str(&self.total_amount) {
            if amount > MIN_AMOUNT {
                return true;
            }
        }
        false
    }

    fn user_info_message(&mut self, msg: String) {
        log::debug!("{}", msg);
    }

    fn utxo_received(&mut self, utxo: UtxoInfo) {
        self.received_utxos.push(utxo);
        self.update_utxo_state()
    }

    fn utxo_confirmed(&mut self, utxo: UtxoInfo) {
        // move utxo from received to locked
        self.received_utxos.retain(|x| x != &utxo);
        self.locked_utxos.push(utxo);

        self.update_utxo_state()
    }

    fn utxo_spent(&mut self, utxo: UtxoInfo) {
        // remove utxo
        self.locked_utxos.retain(|x| x != &utxo);

        self.update_utxo_state()
    }

    fn update_utxo_state(&mut self) {
        let received = self
            .received_utxos
            .iter()
            .fold(Amount::zero(), |sum, tx| sum.add(tx.amount()));

        let locked = self
            .locked_utxos
            .iter()
            .fold(Amount::zero(), |sum, tx| sum.add(tx.amount()));

        let contract_total = self.contract.as_ref().unwrap().get_amount();

        match self.contract_state {
            ContractState::Accepted => {
                if received >= contract_total {
                    self.contract_state = ContractState::Funded;
                }
            }
            ContractState::Funded => {
                if locked >= contract_total {
                    self.contract_state = ContractState::Locked;
                }
            }
            ContractState::Locked => {
                if locked == Amount::zero() {
                    self.contract_state = ContractState::Unlocked;
                }
            }

            _ => {}
        }
    }
}

impl Application for Escrow {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = Flags;

    fn new(args: Self::Flags) -> (Self, Command<Self::Message>) {
        let history = vec![ChatEntry {
            user: User::Other("Default".to_string()),
            text: "Send a message to your peer".to_string(),
        }];

        let signer = TaprootHotSigner::new(args.network);

        let escrow = Escrow {
            min_width: 950.0,
            min_height: 700.0,
            step: Step::NostrConnect,
            npriv: "".to_string(),
            npriv_error: None,
            nostr_keys: None,
            nostr_client: None,
            nostr_receiver: args.nostr_receiver,
            nostr_sender: args.nostr_sender,
            bitcoin_receiver: args.bitcoin_receiver,
            bitcoin_sender: args.bitcoin_sender,
            connect_code: "".to_string(),
            npub: "".to_string(),
            peer_npub: None,
            peer_npub_str: "".to_string(),
            contract: None,
            contract_state: ContractState::None,
            side: Side::None,
            chat_input: "".to_string(),
            chat_history: history,
            total_amount: "".to_string(),
            deposit_amount: "".to_string(),
            timelock: "".to_string(),
            contract_text: Content::with_text(""),
            timelock_unit: TimelockUnit::Day,
            deposit_address: None,
            qr: None,
            // qr: Some(Data::new("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh").unwrap()),
            withdraw_address: "".to_string(),
            received_utxos: vec![],
            network: args.network,
            locked_utxos: vec![],
            hot_signer: Some(signer),
            transactions: Vec::new(),
        };

        (escrow, Command::none())
    }

    fn title(&self) -> String {
        "Escrow".to_string()
    }

    fn update(&mut self, event: Message) -> Command<Message> {
        // log::error!("Escrow.update({:?})", &event);
        let edit = self.side == Side::Seller && self.contract_state == ContractState::None;
        match event {
            // nostr connect
            Message::Npriv(n) => {
                self.npriv = n;
            }
            Message::CreateNpriv => self.npriv = generate_npriv(),
            Message::ConnectNpriv => {
                if let Some(keys) = key_from_npriv(&self.npriv) {
                    self.nostr_keys = Some(keys.clone());
                    self.npub = keys.public_key().clone().to_bech32().unwrap();
                    self.step = Step::PeerConnect;
                    self.send_nostr_msg(NostrMessage::Connect(keys.clone()));
                } else {
                    self.npriv_error = Some(String::from("NPriv cannot be parsed!"))
                }
            }
            // peer connect
            Message::PeerNpub(n) => {
                self.peer_npub = Some(PublicKey::from_str(&n).unwrap());
                self.peer_npub_str = n;
            }
            Message::Code(code) => {
                self.connect_code = code;
            }
            Message::NostrClient(_client) => {}
            Message::ReceiveMode => {
                if let Ok(key) = PublicKey::from_str(&self.peer_npub_str) {
                    self.peer_npub = Some(key);
                    self.send_nostr_msg(NostrMessage::Peer(key));
                    self.step = Step::Main;
                    self.side = Side::Seller;
                    log::info!("Seller side");
                }
            }
            Message::SendMode => {
                if let Ok(key) = PublicKey::from_str(&self.peer_npub_str) {
                    self.send_nostr_msg(NostrMessage::Peer(key));
                    self.step = Step::Main;
                    self.side = Side::Buyer;
                    log::info!("Buyer side");
                }
            }
            // contract fields
            Message::Amount(s) => {
                // TODO: check sanity
                if edit {
                    self.total_amount = s;
                }
            }
            Message::Deposit(s) => {
                // TODO: check sanity
                if edit {
                    self.deposit_amount = s;
                }
            }
            Message::Timelock(s) => {
                // TODO: check sanity
                if edit {
                    self.timelock = s;
                }
            }
            Message::TimelockUnit(unit) => {
                if let Ok(unit) = TimelockUnit::try_from(unit) {
                    if self.side == Side::Seller && self.contract_state == ContractState::None {
                        self.timelock = "".to_string();
                        self.timelock_unit = unit;
                    }
                }
            }
            Message::ChatMsg(s) => {
                // TODO: set max length
                self.chat_input = s;
            }
            Message::ContractDetail(action) => {
                if edit {
                    self.contract_text.perform(action);
                }
            }
            Message::WithdrawAddress(addr) => {
                self.withdraw_address = addr;
            }
            Message::Withdraw => {
                // Get list of utxos first in order to withdraw
                self.get_transactions()
            }
            Message::SendChat => {
                if self.chat_input != *"" {
                    let msg = self.chat_input.clone();
                    self.chat_input = String::from("");
                    self.send_nostr_msg(NostrMessage::DmToPeer(msg));
                }
            }
            Message::NostrClientMsg(NostrMessage::DmToPeerSent(msg)) => {
                self.chat_history.push(ChatEntry {
                    user: User::Me,
                    text: msg,
                });
            }
            Message::NostrClientMsg(NostrMessage::DmFromPeer(msg)) => {
                self.chat_history.push(ChatEntry {
                    user: User::Other("peer".to_string()),
                    text: msg,
                });
            }
            // ContractMessages sent to peer
            Message::OfferContract => {
                log::debug!("OfferContract");
                self.offer_contract();
                self.contract_state = ContractState::Offered;
            }
            Message::RefuseContract => {
                self.refuse_contract();
            }
            Message::AcceptContract => {
                log::debug!("AcceptContract");
                self.accept_contract();
            }
            // debug => should received from bitcoin backend instead
            Message::TxBroadcasted => {
                // TODO: implement bitcoin backend
                self.contract_state = ContractState::Funded;

                self.send_nostr_msg(NostrMessage::Contract(Box::new(ContractMessage::Funded(
                    self.contract
                        .clone()
                        .expect("Contract should not miss")
                        .get_id()
                        .expect("Id should not miss"),
                    self.contract
                        .clone()
                        .expect("Contract should not miss")
                        .get_buyer_pubkey()
                        .expect("Id should not miss"),
                ))));
            }
            // debug => should received from bitcoin backend instead
            Message::TxMined => {
                // TODO: implement bitcoin backend
                self.contract_state = ContractState::Locked;

                self.send_nostr_msg(NostrMessage::Contract(Box::new(ContractMessage::Lock(
                    self.contract
                        .clone()
                        .expect("Contract should not miss")
                        .get_id()
                        .expect("Id should not miss"),
                    self.contract
                        .clone()
                        .expect("Contract should not miss")
                        .get_buyer_pubkey()
                        .expect("Id should not miss"),
                ))));
            }
            Message::UnlockFunds => {
                self.unlock_contract();
            }
            // Key pressed
            Message::TabPressed(modif) => {
                return if modif.shift() {
                    focus_previous()
                } else {
                    focus_next()
                }
            }
            // ContractMessages received from peer
            Message::NostrClientMsg(NostrMessage::Contract(msg)) => {
                match (&self.side, *msg.clone()) {
                    (Side::Buyer, ContractMessage::Offer(contract, peer)) => {
                        self.contract_offered(contract, peer);
                    }
                    (Side::Seller, ContractMessage::Accept(contract, _peer)) => {
                        self.contract_accepted(contract);
                    }
                    (Side::Seller, ContractMessage::Refuse(id, peer)) => {
                        self.contract_refused(id, peer);
                    }
                    // Debug
                    (Side::Seller, ContractMessage::Funded(_id, _peer)) => {
                        // TODO: sanity check id and peer (this message should arrive from our bitcoin backend)
                        self.contract_state = ContractState::Funded;
                    }
                    (Side::Seller, ContractMessage::Lock(_id, _peer)) => {
                        // TODO: sanity check id and peer (this message should arrive from our bitcoin backend)
                        self.contract_state = ContractState::Locked;
                    }
                    (Side::Seller, ContractMessage::Unlock(_contract_id, preimage, _peer)) => {
                        // TODO: sanity check id and peer
                        self.contract_unlocked(&preimage);
                    }
                    _ => {
                        log::error!(
                            "Escrow.update() => Unhandled (side={:?}, step={:?}, msg={:?})",
                            &self.side,
                            &self.contract_state,
                            *msg
                        );
                    }
                }
            }
            Message::BitcoinClientMsg(msg) => match msg {
                BitcoinMessage::UserInfoMessage(msg) => {
                    self.user_info_message(msg);
                }
                BitcoinMessage::UtxoReceived(txo) => {
                    self.utxo_received(txo);
                }
                BitcoinMessage::UtxoConfirmed(txo) => {
                    self.utxo_confirmed(txo);
                }
                BitcoinMessage::UtxoSpent(txo) => {
                    self.utxo_spent(txo);
                }
                BitcoinMessage::ReceiveTransactions(txs) => {
                    self.receive_transactions(txs);
                }
                _ => {}
            },
            _ => {}
        }
        Command::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let content = match self.step {
            Step::NostrConnect => connect_view(self),
            Step::PeerConnect => connect_peer_view(self),
            // Step::FundWallet => fund_wallet_view(self),
            Step::Main => main_view(self),
        };

        main_frame(content).into()
    }

    fn theme(&self) -> Self::Theme {
        Theme::Dark
    }

    fn subscription(&self) -> Subscription<Self::Message> {
        let subscriptions: Vec<Subscription<Message>> = vec![
            iced::event::listen_with(|event, _status| match event {
                // Event::Window(id, iced::window::Event::Resized { width, height }) => {
                //     Some(Message::WindowResized(id, width, height))
                // }
                Event::Keyboard(keyboard::Event::KeyPressed {
                    key: Key::Named(Named::Tab),
                    modifiers,
                    ..
                }) => Some(Message::TabPressed(modifiers)),
                _ => None,
            }),
            Subscription::from_recipe(NostrListener {
                receiver: self.nostr_receiver.clone(),
            }),
            Subscription::from_recipe(BitcoinListener {
                receiver: self.bitcoin_receiver.clone(),
            }),
        ];

        Subscription::batch(subscriptions)
    }
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub enum Message {
    NostrSend(Result<(), SendError<NostrMessage>>),

    CreateNpriv,
    ConnectNpriv,
    ReceiveMode,
    SendMode,
    OfferContract,
    AcceptContract,
    RefuseContract,
    UnlockPayment,
    Withdraw,
    SendChat,

    UpdateStep,
    WalletFunded,
    ContractReceived,
    ContractAccepted,
    TxUnconfirmed,
    TxConfirmed,
    Unlocked,
    Dispute,
    CheckAndBroadcast,

    Npriv(String),
    Npub(String),
    PeerNpub(String),
    Code(String),
    Amount(String),
    Deposit(String),
    Timelock(String),
    TimelockUnit(String),
    ContractDetail(Action),
    WithdrawAddress(String),
    ChatMsg(String),

    WindowResized(iced::window::Id, u32, u32),
    TabPressed(Modifiers),

    NostrClient(Option<Client>),
    NostrClientMsg(NostrMessage),
    BitcoinClientMsg(BitcoinMessage),

    ContractMsg(Box<ContractMessage>),

    // debug
    TxBroadcasted,
    TxMined,
    UnlockFunds,

    // Do nothing
    Nop(String),
}

enum Step {
    NostrConnect,
    PeerConnect,
    // FundWallet,
    Main,
}

fn connect_view(escrow: &Escrow) -> Element<Message> {
    let content = container(
        Column::new()
            .push(
                Row::new()
                    .push(Space::with_width(Length::Fill))
                    .push(
                        TextInput::new("Npriv", &escrow.npriv)
                            .on_input(Message::Npriv)
                            .width(600.0),
                    )
                    .push(Space::with_width(Length::Fill)),
            )
            .push(Text::new(if let Some(e) = &escrow.npriv_error {
                e
            } else {
                ""
            }))
            .push(Space::with_height(40.0))
            .push(
                Row::new()
                    .push(Space::with_width(Length::Fill))
                    .push(
                        Button::new(Text::new("Create").horizontal_alignment(Horizontal::Center))
                            .on_press(Message::CreateNpriv)
                            .width(130.0),
                    )
                    .push(Space::with_width(30.0))
                    .push(
                        Button::new(Text::new("Connect").horizontal_alignment(Horizontal::Center))
                            .on_press(Message::ConnectNpriv)
                            .width(130.0),
                    )
                    .push(Space::with_width(Length::Fill)),
            )
            .width(600),
    );

    content.into()
}

fn connect_peer_view(escrow: &Escrow) -> Element<Message> {
    let content = container(
        Column::new()
            .push(
                Row::new()
                    .push(Space::with_width(Length::Fill))
                    .push(
                        TextInput::new("", &escrow.npub)
                            .on_input(Message::Npub)
                            .width(600.0),
                    )
                    .push(Space::with_width(Length::Fill)),
            )
            .push(Space::with_height(5))
            .push(
                Row::new()
                    .push(Space::with_width(Length::Fill))
                    .push(
                        TextInput::new("", &escrow.peer_npub_str)
                            .on_input(Message::PeerNpub)
                            .width(600.0),
                    )
                    .push(Space::with_width(Length::Fill)),
            )
            .push(Space::with_height(40.0))
            .push(
                Row::new()
                    .push(Space::with_width(Length::Fill))
                    .push(
                        Button::new(Text::new("Receive").horizontal_alignment(Horizontal::Center))
                            .on_press(Message::ReceiveMode)
                            .width(130.0),
                    )
                    .push(Space::with_width(30.0))
                    .push(
                        Button::new(Text::new("Send").horizontal_alignment(Horizontal::Center))
                            .on_press(Message::SendMode)
                            .width(130.0),
                    )
                    .push(Space::with_width(Length::Fill)),
            )
            .width(600),
    );

    content.into()
}

fn qr_code(escrow: &Escrow) -> QRCode<Theme> {
    escrow
        .qr
        .as_ref()
        .map(|data| QRCode::new(data).cell_size(8))
        .expect("Adress QR should not fail")
}

fn main_view(escrow: &Escrow) -> Element<Message> {
    let content = container(
        row!(
            contract_column(escrow).width(400.0).height(900.0),
            Space::with_width(30.0),
            main_chat(escrow).width(400.0).height(900.0),
        )
        .align_items(Alignment::Center),
    );

    content.into()
}

fn main_chat(escrow: &Escrow) -> Column<Message> {
    let mut chat = Column::new().padding(15);

    for entry in &escrow.chat_history {
        chat = chat.push(chat_line(entry));
        chat = chat.push(Space::with_height(3.0));
    }

    let chat_box = Container::new(scrollable(chat).height(580))
        .style(chat_box)
        .padding(5);

    Column::new()
        .push(
            Row::new()
                .push(Space::with_width(Length::Fill))
                .push(Text::new("Chat").size(25.0))
                .push(Space::with_width(Length::Fill)),
        )
        .push(Space::with_height(20.0))
        .push(chat_box)
        .push(Space::with_height(5.0))
        .push(
            Row::new()
                .push(
                    TextInput::new("send message to peer...", &escrow.chat_input)
                        .on_input(Message::ChatMsg)
                        .on_submit(Message::SendChat)
                        .width(Length::Fill),
                )
                .push(Space::with_width(10.0))
                .push(Button::new(Text::new("Send")).on_press(Message::SendChat)),
        )
}

fn contract_column(escrow: &Escrow) -> Column<Message> {
    let side = &escrow.side;
    let step = &escrow.contract_state;
    log::info!("side={:?}, contract_state={:?}", side, step);

    let contract_title = match (side, step) {
        (Side::Seller, ContractState::None) => "Prepare escrow contract!",
        (Side::Seller, ContractState::Offered) => "Waiting your peer accept contract...",
        (Side::Seller, ContractState::Accepted) => "Contract accepted!",
        (Side::Seller, ContractState::Funded) => "Contract funded! (unconfirmed)",
        (Side::Seller, ContractState::Locked) => "Funds locked in escrow",
        (Side::Seller, ContractState::Unlocked) => "Funds unlocked!",
        (Side::Buyer, ContractState::None) => "Waiting for seller to create contract...",
        (Side::Buyer, ContractState::Offered) => "Seller want to offer you this contract:",
        (Side::Buyer, ContractState::Accepted) => "Fund contract!",
        (Side::Buyer, ContractState::Funded) => "Contract funded (unconfirmed)...",
        (Side::Buyer, ContractState::Locked) => "Funds locked in escrow!",
        (Side::Buyer, ContractState::Unlocked) => "Payment finalized",
        _ => "",
    };

    let send = escrow.is_contract_valid();

    let buttons = match (side, step) {
        (Side::Seller, ContractState::None) => btn_row(
            vec![(
                "Send contract!",
                if send {
                    Some(Message::OfferContract)
                } else {
                    None
                },
            )],
            false,
        ),
        (Side::Seller, ContractState::Locked) => {
            btn_row(vec![("Dispute", Some(Message::Dispute))], false)
        }
        (Side::Seller, ContractState::Unlocked) => {
            let addr_valid = Address::from_str(&escrow.withdraw_address).is_ok();
            let withdraw_action = if addr_valid {
                Some(Message::Withdraw)
            } else {
                None
            };
            btn_row(vec![("Withdraw", withdraw_action)], false)
        }
        (Side::Buyer, ContractState::Offered) => btn_row(
            vec![
                ("Refuse", Some(Message::RefuseContract)),
                ("Accept and pay", Some(Message::AcceptContract)),
            ],
            false,
        ),
        (Side::Buyer, ContractState::Accepted) => {
            btn_row(vec![("PSBT Broadcast", Some(Message::TxBroadcasted))], true)
        }
        (Side::Buyer, ContractState::Funded) => {
            btn_row(vec![("Tx mined", Some(Message::TxMined))], true)
        }
        (Side::Buyer, ContractState::Locked) => {
            btn_row(
                vec![("Unlock", Some(Message::UnlockFunds)), ("Dispute", None)], // Some(Message::Dispute)
                false,
            )
        }
        _ => {
            row!(Space::with_height(25))
        }
    };

    let content = match (side, step) {
        (Side::Seller, ContractState::Offered) | (Side::Buyer, ContractState::None) => None,
        (Side::Buyer, ContractState::Accepted) => Some(fund_contract(escrow)),
        _ => Some(contract(escrow)),
    };

    let display_withdraw =
        escrow.side == Side::Seller && escrow.contract_state == ContractState::Unlocked;
    let withdraw_input = if display_withdraw {
        Some(
            Row::new().push(
                TextInput::new("Enter an address to withdraw to", &escrow.withdraw_address)
                    .on_input(Message::WithdrawAddress),
            ),
        )
    } else {
        None
    };

    Column::new()
        .push(Space::with_height(Length::Fill))
        .push(Space::with_height(50))
        .push(
            Row::new()
                .push(Space::with_width(Length::Fill))
                .push(Text::new(contract_title).size(30))
                .push(Space::with_width(Length::Fill)),
        )
        .push(Space::with_height(40.0))
        .push_maybe(content)
        .push(Space::with_height(30.0))
        .push_maybe(withdraw_input)
        .push_maybe(if display_withdraw {
            Some(Space::with_height(30))
        } else {
            None
        })
        .push(buttons)
        .push(Space::with_height(Length::Fill))
}

fn contract(escrow: &Escrow) -> Column<Message> {
    let units = [
        TimelockUnit::Day.to_string(),
        TimelockUnit::Hour.to_string(),
        TimelockUnit::Block.to_string(),
    ];

    let (amount_placeholder, deposit_placeholder, timelock_placeholder) =
        if escrow.side == Side::Seller && escrow.contract_state == ContractState::None {
            ("0.04 BTC", "0.01 BTC", "65535")
        } else {
            ("", "", "")
        };

    Column::new()
        .push(
            Row::new()
                .push(Text::new("Total amount to receive"))
                .push(Space::with_width(Length::Fill))
                .push(
                    TextInput::new(amount_placeholder, &escrow.total_amount)
                        .on_input(Message::Amount)
                        .width(200.0),
                ),
        )
        .push(Space::with_height(30.0))
        .push(
            Row::new()
                .push(Text::new("Deposit"))
                .push(Space::with_width(Length::Fill))
                .push(
                    TextInput::new(deposit_placeholder, &escrow.deposit_amount)
                        .on_input(Message::Deposit)
                        .width(200.0),
                ),
        )
        .push(Space::with_height(30.0))
        .push(
            Row::new()
                .push(Text::new("Timelock"))
                .push(Space::with_width(Length::Fill))
                .push(
                    TextInput::new(timelock_placeholder, &escrow.timelock)
                        .on_input(Message::Timelock)
                        .width(110.0),
                )
                .push(Space::with_width(10.0))
                .push(
                    PickList::new(
                        units.clone(),
                        Some(escrow.timelock_unit.to_string()),
                        Message::TimelockUnit,
                    )
                    .width(80.0),
                ),
        )
        .push(Space::with_height(30.0))
        .push(
            TextEditor::new(&escrow.contract_text)
                .on_action(Message::ContractDetail)
                .height(250),
        )
}

#[allow(unused)]
fn message_box(text: &str) -> Column<Message> {
    Column::new().push(
        Row::new()
            .push(Space::with_width(Length::Fill))
            .push(
                container(Text::new(text))
                    .width(400)
                    .height(400)
                    .style(chat_box),
            )
            .push(Space::with_width(Length::Fill)),
    )
}

fn fund_contract(escrow: &Escrow) -> Column<Message> {
    Column::new()
        .push(
            Row::new()
                .push(Space::with_width(Length::Fill))
                .push(
                    container(qr_code(escrow))
                        .width(Length::Shrink)
                        .height(Length::Shrink)
                        .padding(25)
                        .style(chat_box),
                )
                .push(Space::with_width(Length::Fill)),
        )
        .push(Space::with_height(10))
        .push(TextInput::new("", escrow.deposit_address.as_ref().unwrap()).on_input(Message::Nop))
}

fn main_frame(element: Element<Message>) -> Column<Message> {
    let output: Column<Message, Theme, Renderer> = Column::new()
        .push(Space::with_height(Length::Fill))
        .push(
            Row::new()
                .push(Space::with_width(Length::Fill))
                .push(container(element))
                .push(Space::with_width(Length::Fill)),
        )
        .push(Space::with_height(Length::Fill))
        .padding(20.0);

    output
}

fn chat_line(entry: &ChatEntry) -> Container<Message> {
    let me = match &entry.user {
        User::Me => Some(Space::with_width(Length::Fill)),
        _ => None,
    };
    let other = match &entry.user {
        User::Me => None,
        _ => Some(Space::with_width(Length::Fill)),
    };

    let chat_style = if me.is_some() {
        chat_entry_me
    } else {
        chat_entry_other
    };

    let row = Row::new()
        .push_maybe(me)
        .push(
            Container::new(Text::new(&entry.text))
                .padding(5.0)
                .style(chat_style),
        )
        .push_maybe(other);

    Container::new(row)
}

pub fn chat_box(theme: &Theme) -> Appearance {
    let palette = theme.extended_palette();

    Appearance {
        background: Some(palette.background.weak.color.into()),
        border: Border::with_radius(10),
        ..Appearance::default()
    }
}

pub fn chat_entry_me(_: &Theme) -> Appearance {
    let red = Color::from_rgb8(250, 120, 120);
    let mut a = Appearance::default().with_background(red);
    a.border.radius = 4.into();
    a.text_color = Some(Color::BLACK);
    a
}

pub fn chat_entry_other(_: &Theme) -> Appearance {
    let blue = Color::from_rgb8(120, 235, 250);
    let mut a = Appearance::default().with_background(blue);
    a.border.radius = 4.into();
    a.text_color = Some(Color::BLACK);
    a
}

pub fn btn_row(labels: Vec<(&str, Option<Message>)>, debug: bool) -> Row<Message> {
    let mut btns = labels
        .into_iter()
        .map(|(label, msg)| {
            let mut btn: Button<Message> = Button::new(label).on_press_maybe(msg);
            if debug {
                btn = btn.style(theme::Button::Destructive);
            }
            btn
        })
        .collect::<Vec<_>>()
        .into_iter();

    let mut row = Row::new()
        .push(Space::with_width(Length::Fill))
        .push(btns.next().expect("At least one button"));

    for btn in btns {
        row = row.push(Space::with_width(30)).push(btn);
    }

    row.push(Space::with_width(Length::Fill))
}
