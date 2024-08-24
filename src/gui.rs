use crate::bitcoin::{BitcoinListener, BitcoinMessage};
use crate::contract::{Contract, ContractId, ContractMessage};
use crate::hot_signer::TaprootHotSigner;
use crate::mempool_space_api::get_address_utxo::UtxoInfo;
use crate::nostr::{generate_npriv, key_from_npriv, NostrListener, NostrMessage};
use crate::views::chat::{ChatEntry, User};
use crate::wallet::{create_transaction, policy_to_taproot};
use crate::{config, views};
use async_channel::{Receiver, SendError, Sender};
use bip39::Mnemonic;
use bitcoin_amount::Amount;
use iced::keyboard::key::Named;
use iced::keyboard::{Key, Modifiers};
use iced::widget::qr_code::Data;
use iced::widget::text_editor::{Action, Content, Edit};
use iced::widget::{focus_next, focus_previous};
use iced::{executor, keyboard, Application, Element, Event, Subscription, Theme};
use iced_runtime::Command;
use miniscript::bitcoin::hashes::Hash;
use miniscript::bitcoin::{Address, Network, Transaction};
use miniscript::psbt::PsbtExt;
use nostr_sdk::{Client, Keys, PublicKey, ToBech32};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::ops::Add;
use std::str::FromStr;
use std::sync::Arc;

const MIN_AMOUNT: f64 = 0.01;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub npriv: Option<String>,
    pub seed: Option<Mnemonic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub identity: Option<Identity>,
    pub contract: Option<(Contract, Side)>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Side {
    Buyer,
    Seller,
    #[allow(unused)]
    Escrow,
    None,
}

impl FromStr for Side {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_string().to_lowercase().as_str() {
            "buyer" => Self::Buyer,
            "seller" => Self::Seller,
            "escrow" => Self::Escrow,
            _ => Self::None,
        })
    }
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

    fn nostr_fingerprint(&self) -> String {
        self.nostr_keys.as_ref().unwrap().public_key().to_string()[..10].to_string()
    }

    fn identity(&self) -> Identity {
        Identity {
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
        }
    }

    fn save_contract(&self) {
        if let Some(contract) = &self.contract {
            config::maybe_save_contract(
                self.nostr_fingerprint(),
                self.identity(),
                self.side(),
                contract.clone(),
            );
        }
    }

    pub fn is_contract_valid(&self) -> bool {
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

    pub fn npub(&self) -> &str {
        &self.npub
    }

    pub fn npriv(&self) -> &str {
        &self.npriv
    }

    pub fn npriv_error(&self) -> Option<String> {
        self.npriv_error.clone()
    }

    pub fn peer_npub_str(&self) -> &str {
        &self.peer_npub_str
    }

    pub fn side(&self) -> Side {
        self.side
    }

    pub fn contract_state(&self) -> ContractState {
        self.contract_state
    }

    pub fn withdraw_address(&self) -> &str {
        &self.withdraw_address
    }

    pub fn total_amount(&self) -> &str {
        &self.total_amount
    }

    pub fn deposit_amount(&self) -> &str {
        &self.deposit_amount
    }

    pub fn timelock(&self) -> &str {
        &self.timelock
    }

    pub fn timelock_unit(&self) -> TimelockUnit {
        self.timelock_unit
    }

    pub fn contract_text(&self) -> &Content {
        &self.contract_text
    }

    pub fn deposit_address(&self) -> &Option<String> {
        &self.deposit_address
    }

    pub fn qr(&self) -> &Option<Data> {
        &self.qr
    }

    pub fn chat_history(&self) -> &Vec<ChatEntry> {
        &self.chat_history
    }

    pub fn chat_input(&self) -> &str {
        &self.chat_input
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

        fn hot_signer_from_identity(
            identity: Option<Identity>,
            network: Network,
        ) -> Option<TaprootHotSigner> {
            if let Some(identity) = identity {
                if let Some(mnemonic) = identity.seed {
                    return Some(TaprootHotSigner::new_from_mnemonics(
                        network,
                        &mnemonic.to_string(),
                    ));
                }
            }
            Some(TaprootHotSigner::new(network))
        }
        let hot_signer = hot_signer_from_identity(args.identity.clone(), args.network);

        fn nostr_keys_from_identity(identity: Option<Identity>) -> Option<Keys> {
            if let Some(identity) = identity {
                if let Some(npriv) = identity.npriv {
                    return Keys::parse(npriv).ok();
                }
            }
            None
        }

        let nostr_keys = nostr_keys_from_identity(args.identity);
        let (contract, side) = if let Some((contract, side)) = &args.contract {
            (Some(contract.clone()), *side)
        } else {
            (None, Side::None)
        };

        let peer_npub = if let Some(contract) = contract.as_ref() {
            match side {
                Side::Buyer => contract.get_seller_pubkey(),
                Side::Seller => contract.get_buyer_pubkey(),
                _ => None,
            }
        } else {
            None
        };

        let (step, contract_state) = {
            match (&nostr_keys, &peer_npub, &contract) {
                (Some(_), Some(_), Some(contract)) => {
                    let state = match contract.get_state() {
                        crate::contract::ContractState::Refused
                        | crate::contract::ContractState::Empty => ContractState::None,
                        crate::contract::ContractState::Offered => ContractState::Offered,
                        crate::contract::ContractState::Accepted => {
                            ContractState::Accepted
                            // TODO: Funded / Locked should be detected by checking utxos
                            // Detect unlock
                            // Detect Indispute
                        }
                    };

                    (Step::Main, state)
                }
                (Some(_), Some(_), None) => (Step::Main, ContractState::None),
                (Some(_), None, None) => (Step::PeerConnect, ContractState::None),
                _ => (Step::NostrConnect, ContractState::None),
            }
        };

        let escrow = Escrow {
            step,
            npriv: "".to_string(),
            npriv_error: None,
            nostr_keys,
            nostr_client: None,
            nostr_receiver: args.nostr_receiver,
            nostr_sender: args.nostr_sender,
            bitcoin_receiver: args.bitcoin_receiver,
            bitcoin_sender: args.bitcoin_sender,
            connect_code: "".to_string(),
            npub: "".to_string(),
            peer_npub,
            peer_npub_str: "".to_string(),
            contract,
            contract_state,
            side,
            chat_input: "".to_string(),
            chat_history: history,
            total_amount: "".to_string(),
            deposit_amount: "".to_string(),
            timelock: "".to_string(),
            contract_text: Content::with_text(""),
            timelock_unit: TimelockUnit::Day,
            deposit_address: None,
            qr: None,
            withdraw_address: "".to_string(),
            received_utxos: vec![],
            network: args.network,
            locked_utxos: vec![],
            hot_signer,
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
            Step::NostrConnect => views::connect::connect_view(self),
            Step::PeerConnect => views::connect::connect_peer_view(self),
            // Step::FundWallet => fund_wallet_view(self),
            Step::Main => views::main_view(self),
        };

        views::main_frame(content).into()
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
