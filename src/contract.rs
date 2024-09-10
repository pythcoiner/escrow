use crate::gui::TimelockUnit;
use crate::mempool_space_api::get_address_utxo::UtxoInfo;
use crate::wallet::{
    create_transaction, derive_xpub, encode_descriptor_pubkey, policy_to_taproot, MAX_DERIV,
};
use bitcoin_amount::{Amount, MIN};
use miniscript::bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use miniscript::bitcoin::hashes::{sha256, Hash, HashEngine};
use miniscript::bitcoin::{Address, Network, Psbt, Sequence, Transaction, TxOut};
use miniscript::descriptor::DescriptorXKey;
use miniscript::policy::Concrete;
use miniscript::DescriptorPublicKey;
use nostr_sdk::bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey as SecpKey, Secp256k1};
use nostr_sdk::secp256k1::Parity;
use nostr_sdk::{Keys, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

pub type ContractId = sha256::Hash;
pub type Peer = PublicKey;

pub const SATOSHIS_PER_BITCOIN: f64 = 100_000_000.0;

pub fn to_miniscript_amount(amount: Amount) -> miniscript::bitcoin::Amount {
    miniscript::bitcoin::Amount::from_sat(amount.into_inner() as u64)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ContractState {
    Empty,
    Offered,
    Accepted,
    Refused,
}

#[allow(clippy::from_over_into)]
impl Into<[u8; 1]> for ContractState {
    fn into(self) -> [u8; 1] {
        match self {
            ContractState::Empty => [0x00],
            ContractState::Offered => [0x01],
            ContractState::Accepted => [0x02],
            ContractState::Refused => [0x04],
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ContractType {
    P2P,
    Thresh,
    All,
}

impl From<ContractType> for [u8; 1] {
    fn from(value: ContractType) -> Self {
        match value {
            ContractType::P2P => [0x00],
            ContractType::Thresh => [0x01],
            ContractType::All => [0x02],
        }
    }
}
#[allow(unused)]
#[derive(Debug)]
pub enum ContractError {
    AmountZero,
    WrongAmount,
    NoBuyer,
    NoSeller,
    No3rdParty,
    SerializationError,
    DeserializationError,
    SecretKeyMissing,
    CannotConvertPrivKey,
    CannotHashMessage,
    UnknownSigner,
    SameBuyerAndSeller,
    SellerXpubNeeded,
    BuyerXpubNeeded,
    BuyerHashNeeded,
    AddressMissing,
    CannotParseAddress,
    WrongAddressNetwork,
    BuyerPrivMissing,
    FailBuildPolicy,
    FailBuildDescriptor,
    FailDeriveAddress,
    SellerXpubMissing,
    BuyerXpubMissing,
    ThirdPartyMissing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dispute {
    pub seller_amount: Amount,
    pub seller_address: Option<String>,
    pub buyer_address: Option<String>,
    pub psbt: Option<Psbt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DisputeState {
    Offered,
    Accepted,
    Refused,
    Unknown,
}

impl Dispute {
    pub fn new() -> Self {
        Self {
            seller_amount: Amount::zero(),
            seller_address: None,
            buyer_address: None,
            psbt: None,
        }
    }

    pub fn state(&self) -> DisputeState {
        match (
            self.seller_address.is_some(),
            self.buyer_address.is_some(),
            self.psbt.is_some(),
        ) {
            (true, true, true) => DisputeState::Accepted,
            (true, false, false) => DisputeState::Offered,
            (false, false, false) => DisputeState::Refused,
            _ => DisputeState::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    version: u32,
    id: Option<ContractId>,
    state: ContractState,
    contract_type: ContractType,
    total_amount: Amount,
    deposit: Option<Amount>,
    details: String,
    buyer: Option<PublicKey>,  // Nostr PubKey
    seller: Option<PublicKey>, // Nostr PubKey
    buyer_signature: Option<Signature>,
    seller_signature: Option<Signature>,
    contract_policy: ContractPolicy,
    preimage: Option<Vec<u8>>,
    received_utxos: Vec<UtxoInfo>,
    locked_utxos: Vec<UtxoInfo>,
    dispute: Option<Dispute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractPolicy {
    contract_id: Option<ContractId>,
    amount: Option<Amount>,
    deposit: Option<Amount>,
    timelock: Option<u32>,
    buyer_xpub: Option<DescriptorPublicKey>,
    buyer_hash: Option<[u8; 32]>,
    seller_xpub: Option<DescriptorPublicKey>,
    address_path: Option<Vec<ChildNumber>>,
    thirds_partys: HashMap<PublicKey, DescriptorPublicKey>,
    // Address does not implement Serialize/Deserialize
    address: Option<String>,
    network: Network,
}

impl ContractPolicy {
    pub fn new(network: Network) -> Self {
        ContractPolicy {
            contract_id: None,
            amount: None,
            deposit: None,
            timelock: None,
            buyer_xpub: None,
            buyer_hash: None,
            seller_xpub: None,
            address_path: None,
            thirds_partys: HashMap::new(),
            address: None,
            network,
        }
    }

    pub fn set_addr_path(&mut self, path: Vec<ChildNumber>) {
        self.address_path = Some(path);
    }

    pub fn get_addr_path(&self) -> Option<Vec<ChildNumber>> {
        self.address_path.clone()
    }
}

impl Contract {
    // Chainable
    pub fn new(network: Network) -> Self {
        Contract {
            version: 0,
            id: None,
            state: ContractState::Empty,
            contract_type: ContractType::P2P,
            total_amount: MIN,
            deposit: None,
            details: "".to_string(),
            buyer: None,
            seller: None,
            buyer_signature: None,
            seller_signature: None,
            contract_policy: ContractPolicy::new(network),
            preimage: None,
            dispute: None,
            received_utxos: Vec::new(),
            locked_utxos: Vec::new(),
        }
    }

    pub fn buyer(mut self, buyer: PublicKey) -> Self {
        if self.buyer.is_none() {
            self.buyer = Some(buyer);
        } else {
            panic!("Contract.set_buyer() => buyer can be set only once!");
        }
        self
    }

    pub fn seller(mut self, seller: PublicKey) -> Self {
        if self.seller.is_none() {
            self.seller = Some(seller);
        } else {
            panic!("Contract.set_seller() => seller can be set only once!");
        }
        self
    }

    pub fn amount(mut self, amount: Amount) -> Self {
        self.set_amount(amount);
        self
    }

    pub fn deposit(mut self, deposit: Option<Amount>) -> Self {
        if let Some(deposit) = deposit {
            self.set_deposit(deposit);
        }
        self
    }

    pub fn timelock(mut self, timelock: u32, unit: TimelockUnit) -> Self {
        self.set_timelock(timelock, unit);
        self
    }

    pub fn details(mut self, details: &str) -> Self {
        self.details = details.to_string();
        self
    }

    // Setters
    pub fn set_seller_xpub(&mut self, xpub: DescriptorPublicKey) {
        if self.contract_policy.seller_xpub.is_none() {
            self.contract_policy.seller_xpub = Some(xpub)
        } else {
            panic!("Contract.set_seller_xpub() => seller Xpub cannot be changed!");
        }
    }

    pub fn set_buyer_xpub(&mut self, xpub: DescriptorPublicKey) {
        if self.contract_policy.buyer_xpub.is_none() {
            self.contract_policy.buyer_xpub = Some(xpub)
        } else {
            panic!("Contract.set_buyer_xpub() => buyer Xpub cannot be changed!");
        }
    }

    fn add_3rd_party(&mut self, nostr_key: PublicKey, xpub: DescriptorPublicKey) {
        match self.contract_policy.thirds_partys.entry(nostr_key) {
            Entry::Occupied(_) => {
                panic!("Contract.add_3rd_party() => Duplicated 3rd party!")
            }
            Entry::Vacant(e) => {
                e.insert(xpub);
            }
        }
    }

    fn set_state(&mut self, state: ContractState) {
        self.state = state;
    }

    fn set_details(&mut self, details: String) {
        self.details = details;
    }

    fn set_amount(&mut self, amount: Amount) {
        self.total_amount = amount;
        self.contract_policy.amount = Some(self.total_amount);
    }

    fn set_deposit(&mut self, deposit: Amount) {
        match (self.total_amount, deposit) {
            (amount, _) if amount == Amount::zero() => {
                panic!("Contract.deposit() => Contract.total_amount should be defined first!")
            }
            (amount, deposit) if deposit >= amount => {
                panic!("Contract.deposit() => Contract.deposit should be lower than Contract.total_amount!")
            }

            (_, deposit) => {
                self.deposit = Some(deposit);
                self.contract_policy.deposit = Some(deposit)
            }
        }
    }

    pub fn set_timelock(&mut self, mut timelock: u32, unit: TimelockUnit) {
        let unit: u32 = unit.into();
        timelock *= unit;

        self.contract_policy.timelock = Some(timelock);
    }

    fn set_id(&mut self, id: ContractId) {
        self.id = Some(id);
        self.contract_policy.contract_id = Some(id);
    }

    fn set_buyer_hash(&mut self, hash: [u8; 32]) {
        self.contract_policy.buyer_hash = Some(hash);
    }

    fn set_address(&mut self, addr: Address) {
        self.contract_policy.address = Some(addr.to_string());
    }

    pub fn maybe_create_dispute(&mut self) {
        if self.dispute.is_none() {
            self.dispute = Some(Dispute::new());
        }
    }

    pub fn clear_dispute(&mut self) {
        self.dispute = None;
    }

    pub fn receive_dispute_offer(&mut self, dispute: Dispute) {
        if let DisputeState::Offered = dispute.state() {
            self.dispute = Some(dispute);
        }
    }

    pub fn set_dispute_amount(&mut self, amount: Amount) {
        self.maybe_create_dispute();
        self.dispute
            .as_mut()
            .expect("Should have a dispute")
            .seller_amount = amount;
    }

    pub fn set_dispute_seller_address(&mut self, address: String) {
        self.maybe_create_dispute();
        self.dispute
            .as_mut()
            .expect("Should have a dispute")
            .seller_address = Some(address);
    }

    pub fn set_dispute_buyer_address(&mut self, address: String) {
        self.maybe_create_dispute();
        self.dispute
            .as_mut()
            .expect("Should have a dispute")
            .buyer_address = Some(address);
    }

    pub fn update_dispute_psbt(&mut self, psbt: Psbt) {
        if let Some(dispute) = self.dispute.as_mut() {
            dispute.psbt = Some(psbt);
        }
    }

    pub fn store_preimage(&mut self, preimage: &[u8; 32]) {
        let preimage = preimage.to_vec();
        self.preimage = Some(preimage);
    }

    pub fn get_preimage(&self) -> Option<Vec<u8>> {
        self.preimage.clone()
    }

    // Getters
    fn id(&self) -> Option<ContractId> {
        self.hash(self.state).ok()
    }

    pub fn get_id(&self) -> Option<ContractId> {
        self.id()
    }

    pub fn get_state(&self) -> ContractState {
        self.state
    }

    pub fn get_contract_type(&self) -> ContractType {
        self.contract_type
    }

    pub fn get_amount(&self) -> Amount {
        self.total_amount
    }
    // self.total_amount = (contract.get_amount().into_inner() as f64 / 100_000_000.0).to_string();

    pub fn get_amount_str(&self) -> String {
        (self.total_amount.into_inner() as f64 / SATOSHIS_PER_BITCOIN).to_string()
    }

    pub fn get_deposit(&self) -> Option<Amount> {
        self.deposit
    }

    pub fn get_deposit_str(&self) -> String {
        if let Some(deposit) = self.deposit {
            (deposit.into_inner() as f64 / SATOSHIS_PER_BITCOIN).to_string()
        } else {
            "0".to_string()
        }
    }

    pub fn get_details(&self) -> String {
        self.details.clone()
    }

    pub fn get_buyer_pubkey(&self) -> Option<PublicKey> {
        self.buyer
    }

    pub fn get_seller_pubkey(&self) -> Option<PublicKey> {
        self.seller
    }

    pub fn get_timelock(&self) -> Option<u32> {
        self.contract_policy.timelock
    }

    pub fn get_buyer_xpub(&self) -> Option<DescriptorPublicKey> {
        self.contract_policy.buyer_xpub.clone()
    }

    pub fn get_buyer_fingerprint(&self) -> Option<Fingerprint> {
        self.get_buyer_xpub().map(|p| match p {
            DescriptorPublicKey::XPub(DescriptorXKey { origin, .. }) => {
                if let Some((fg, _)) = origin {
                    fg
                } else {
                    panic!("Must have an origin")
                }
            }
            _ => unreachable!("Must be an XPub"),
        })
    }

    pub fn get_seller_xpub(&self) -> Option<DescriptorPublicKey> {
        self.contract_policy.seller_xpub.clone()
    }

    pub fn get_seller_fingerprint(&self) -> Option<Fingerprint> {
        self.get_seller_xpub().map(|p| match p {
            DescriptorPublicKey::XPub(DescriptorXKey { origin, .. }) => {
                if let Some((fg, _)) = origin {
                    fg
                } else {
                    panic!("Must have an origin")
                }
            }
            _ => unreachable!("Must be an XPub"),
        })
    }

    pub fn get_buyer_hash(&self) -> Option<[u8; 32]> {
        self.contract_policy.buyer_hash
    }

    pub fn get_thirds_partys(&self) -> Vec<PublicKey> {
        self.contract_policy.thirds_partys.keys().copied().collect()
    }

    // pub fn get_3rd_party_xpub(&self, pubkey: &PublicKey) -> Option<DescriptorPublicKey> {
    //     self.contract_policy.thirds_partys.get(pubkey).copied()
    // }

    pub fn get_address(&self) -> Option<Address> {
        self.contract_policy.address.as_ref().map(|addr| {
            Address::from_str(addr)
                .expect("Should not fail parsing address")
                .assume_checked()
        })
    }

    pub fn get_contract_policy(&self) -> &ContractPolicy {
        &self.contract_policy
    }

    pub fn get_received_utxo_amount(&self) -> Amount {
        self.received_utxos
            .iter()
            .fold(Amount::zero(), |sum, tx| sum + tx.amount())
    }

    pub fn get_locked_utxo_amount(&self) -> Amount {
        self.locked_utxos
            .iter()
            .fold(Amount::zero(), |sum, tx| sum + tx.amount())
    }

    pub fn get_locked_utxos(&self) -> Vec<UtxoInfo> {
        self.locked_utxos.clone()
    }

    pub fn utxo_received(&mut self, utxo: UtxoInfo) {
        self.received_utxos.push(utxo);
    }

    pub fn utxo_confirmed(&mut self, utxo: UtxoInfo) {
        // move utxo from received to locked
        self.received_utxos.retain(|x| x != &utxo);
        self.locked_utxos.push(utxo);
    }

    pub fn utxo_spent(&mut self, utxo: UtxoInfo) {
        // remove utxo
        self.locked_utxos.retain(|x| x != &utxo);
    }

    pub fn dispute(&self) -> &Option<Dispute> {
        &self.dispute
    }

    pub fn dispute_seller_amount(&self) -> Option<Amount> {
        self.dispute.as_ref().map(|dispute| dispute.seller_amount)
    }

    pub fn dispute_buyer_amount(&self) -> Option<Amount> {
        self.dispute_seller_amount()
            .map(|amount| self.get_locked_utxo_amount() - amount)
    }

    pub fn dispute_seller_address(&self) -> Option<Address> {
        if let Some(dispute) = &self.dispute {
            Address::from_str(
                dispute
                    .seller_address
                    .as_ref()
                    .expect("Must have an address"),
            )
            .map(|a| a.assume_checked())
            .ok()
        } else {
            None
        }
    }

    pub fn dispute_buyer_address(&self) -> Option<Address> {
        if let Some(dispute) = &self.dispute {
            Address::from_str(
                dispute
                    .buyer_address
                    .as_ref()
                    .expect("Must have an address"),
            )
            .map(|a| a.assume_checked())
            .ok()
        } else {
            None
        }
    }

    pub fn to_json(&self) -> Result<String, ContractError> {
        serde_json::to_string(&self).map_err(|_| ContractError::SerializationError)
    }

    pub fn from_json(data: &str) -> Result<Self, ContractError> {
        serde_json::from_str(data).map_err(|_| ContractError::DeserializationError)
    }

    // Process fn
    pub fn hash(&self, state: ContractState) -> Result<ContractId, ContractError> {
        if self.total_amount == Amount::zero() {
            Err(ContractError::AmountZero)
        } else if self.buyer.is_none() {
            Err(ContractError::NoBuyer)
        } else if self.seller.is_none() {
            Err(ContractError::NoSeller)
        } else if self.deposit.is_some() && self.deposit.unwrap() >= self.total_amount {
            Err(ContractError::WrongAmount)
        } else if state == ContractState::Accepted && self.contract_policy.seller_xpub.is_none() {
            Err(ContractError::SellerXpubNeeded)
        } else if state == ContractState::Accepted && self.contract_policy.buyer_xpub.is_none() {
            Err(ContractError::BuyerXpubNeeded)
        } else if state == ContractState::Accepted && self.contract_policy.buyer_hash.is_none() {
            Err(ContractError::BuyerHashNeeded)
        } else {
            // Hash the serialized contract
            let mut engine = sha256::HashEngine::default();

            // contract state
            let data: [u8; 1] = state.into();
            engine.input(&data);

            // contract type
            let data: [u8; 1] = self.contract_type.into();
            engine.input(&data);

            // total amount
            let data = self.total_amount.into_inner().to_le_bytes();
            engine.input(&data);

            // deposit
            let data = if let Some(deposit) = &self.deposit {
                (*deposit).into_inner().to_le_bytes()
            } else {
                [0; 8]
            };
            engine.input(&data);

            // timelock
            let data = if let Some(timelock) = self.contract_policy.timelock {
                timelock.to_le_bytes()
            } else {
                [0; 4]
            };

            engine.input(&data);
            // contract details
            let data = self.details.clone();
            engine.input(data.as_bytes());

            // buyer
            let data = self.buyer.expect("Cannot fail").to_bytes();
            engine.input(&data);

            // seller
            let data = self.seller.expect("Cannot fail!").to_bytes();
            engine.input(&data);

            if state == ContractState::Accepted {
                let addr = Address::from_str(
                    self.contract_policy
                        .address
                        .as_ref()
                        .ok_or(ContractError::AddressMissing)?,
                )
                .map_err(|_| ContractError::CannotParseAddress)?;
                let addr = if !addr.is_valid_for_network(self.contract_policy.network) {
                    return Err(ContractError::WrongAddressNetwork);
                } else {
                    addr.assume_checked()
                };

                // seller xpub
                let data = self
                    .contract_policy
                    .seller_xpub
                    .clone()
                    .expect("Cannot fail");
                let data = encode_descriptor_pubkey(&data);
                engine.input(&data);

                // buyer xpub
                let data = self
                    .contract_policy
                    .buyer_xpub
                    .clone()
                    .expect("Cannot fail!");
                let data = encode_descriptor_pubkey(&data);
                engine.input(&data);

                // buyer hash
                let data = self.contract_policy.buyer_hash.expect("Cannot fail!");
                engine.input(data.as_slice());

                // address
                let data = addr.to_string();
                engine.input(data.as_bytes());
            }

            // 3rd partys
            self.contract_policy
                .thirds_partys
                .iter()
                .for_each(|(npub, xpub)| {
                    let data = npub.to_bytes();
                    engine.input(&data);
                    let data = encode_descriptor_pubkey(xpub);
                    engine.input(&data);
                });

            Ok(sha256::Hash::from_engine(engine))
        }
    }

    fn sign(&mut self, id: &ContractId, key: &Keys) -> Result<Signature, ContractError> {
        let priv_key = key
            .secret_key()
            .map_err(|_| ContractError::SecretKeyMissing)?;

        // Create a message from the hash for signing
        let message =
            Message::from_slice(id.as_ref()).map_err(|_| ContractError::CannotHashMessage)?;

        // Sign
        let secp = nostr_sdk::bitcoin::secp256k1::Secp256k1::signing_only();

        Ok(secp.sign_ecdsa(&message, priv_key))
    }

    fn check_signature(
        &self,
        state: ContractState,
        signature: &Option<Signature>,
        public_key: &Option<PublicKey>,
    ) -> bool {
        log::debug!("Contract.check_signature()");

        let id = match self.hash(state) {
            Ok(id) => id,
            Err(e) => {
                log::error!("Contract.check_signature() => Fail to get hash: {:?}", e);
                return false;
            }
        };

        let message = match Message::from_slice(id.as_ref()) {
            Ok(r) => r,
            Err(e) => {
                log::error!(
                    "Contract.check_signature() Fail Message::from_slice(): {:?}",
                    e
                );
                return false;
            }
        };

        if let (Some(signature), Some(buyer)) = (signature.as_ref(), public_key.as_ref()) {
            let pub_even = SecpKey::from_x_only_public_key(**buyer, Parity::Even);
            let pub_odd = SecpKey::from_x_only_public_key(**buyer, Parity::Odd);

            let secp = Secp256k1::new();

            // TODO: is there a better way?
            let even_ok = secp.verify_ecdsa(&message, signature, &pub_even).is_ok();
            let odd_ok = secp.verify_ecdsa(&message, signature, &pub_odd).is_ok();

            even_ok || odd_ok
        } else {
            log::error!("Contract.check_signature() Signature not match!");
            false
        }
    }

    pub fn process_hash_preimage(
        &mut self,
        keys: &Keys,
    ) -> Result<(sha256::Hash, /* preimage */ [u8; 32]), ContractError> {
        log::info!("Contract.process_hash_preimage()");
        let raw_npriv = keys
            .secret_key()
            .map_err(|_| ContractError::BuyerPrivMissing)
            .unwrap()
            .secret_bytes();

        // We should always have 'Offered' state hash, fail otherwise if missing data
        let raw_contract = self.hash(ContractState::Offered).unwrap();

        // first round hashing npriv + hash contract to get preimage
        let mut engine = sha256::HashEngine::default();
        // add entropy from contract hash to avoid collision if several contracts from same npriv
        engine.input(raw_contract.as_ref());
        engine.input(&raw_npriv);

        let hash = sha256::Hash::from_engine(engine);
        let preimage: [u8; 32] = *hash.as_ref();

        let mut engine = sha256::HashEngine::default();
        engine.input(&preimage);
        let hash = sha256::Hash::from_engine(engine);
        let raw_hash = hash;
        let raw_hash: [u8; 32] = *raw_hash.as_ref();
        self.set_buyer_hash(raw_hash);

        Ok((hash, preimage))
    }

    pub fn get_derivation_path(&mut self) -> Result<DerivationPath, ContractError> {
        let hash = self.hash(ContractState::Offered)?;
        let raw_hash: [u8; 32] = *hash.as_ref();

        let indexes = raw_hash
            .chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()) % MAX_DERIV)
            .collect::<Vec<_>>();

        let xpub_path = indexes.as_slice()[..6]
            .iter()
            .copied()
            .map(|i| ChildNumber::from_hardened_idx(i).unwrap())
            .collect::<Vec<_>>();

        let address_path = indexes.as_slice()[6..8]
            .iter()
            .copied()
            .map(|i| ChildNumber::from_normal_idx(i).unwrap())
            .collect::<Vec<_>>();

        self.contract_policy.set_addr_path(address_path);

        Ok(DerivationPath::from(xpub_path))
    }

    #[allow(unused)]
    pub fn build_wallet_policy(
        &mut self,
    ) -> Result<Arc<Concrete<DescriptorPublicKey>>, ContractError> {
        log::debug!("Contract.build_wallet_policy()");
        let xpub_path = self.get_derivation_path()?;

        let hash = self.get_buyer_hash().unwrap();
        let hash = sha256::Hash::from_byte_array(hash);

        // policy from preimage hash
        let hash_policy = Arc::new(Concrete::<DescriptorPublicKey>::Sha256(hash));

        let addr_path = self.contract_policy.get_addr_path().unwrap();

        // seller Xpub
        let seller_xpub = self
            .contract_policy
            .seller_xpub
            .clone()
            .ok_or(ContractError::SellerXpubMissing)?;

        let seller1 = derive_xpub(seller_xpub.clone(), addr_path.clone(), None);
        let seller2 = derive_xpub(seller_xpub.clone(), addr_path.clone(), Some(1));
        let seller3 = derive_xpub(seller_xpub.clone(), addr_path.clone(), Some(2));

        let seller_policy = Arc::new(Concrete::Key(seller1));

        // Path 1
        let path1 = Arc::new(Concrete::And(vec![seller_policy, hash_policy]));

        // buyer Xpub
        let buyer_xpub = self
            .contract_policy
            .buyer_xpub
            .clone()
            .ok_or(ContractError::BuyerXpubMissing)?;
        let buyer = derive_xpub(buyer_xpub.clone(), addr_path.clone(), None);
        let buyer1 = derive_xpub(buyer_xpub.clone(), addr_path, Some(1));

        let buyer_policy = Arc::new(Concrete::Key(buyer));
        let seller_policy = Arc::new(Concrete::Key(seller2));

        // Path 2
        let path2 = Arc::new(Concrete::And(vec![
            buyer_policy.clone(),
            seller_policy.clone(),
        ]));

        // 3rd partys
        let path_2 = if let Some(timelock) = self.contract_policy.timelock {
            if self.contract_policy.thirds_partys.is_empty() {
                return Err(ContractError::ThirdPartyMissing);
            }

            let mut v = self
                .contract_policy
                .thirds_partys
                .clone()
                .into_values()
                .collect::<Vec<DescriptorPublicKey>>();
            v.push(buyer_xpub);
            v.push(seller_xpub);

            // FIXME: Should we hardcode/force 3rd party's derivation path???
            //  If so, we need to double check when we import
            // 3rd party derivation path
            let buddy_path = DerivationPath::from_str("m/48'/0'/0'/99'").unwrap();

            let mut v = v
                .into_iter()
                // in order to avoid 3rd party to sign all dispute w/ the same private key
                // we append the contract derivation path
                .map(|xpub| Arc::new(Concrete::Key(xpub)))
                .collect::<Vec<Arc<Concrete<DescriptorPublicKey>>>>();

            v.push(Arc::new(Concrete::Older(Sequence(timelock))));

            let path3 = Arc::new(Concrete::Threshold(v.len() - 1, v));
            Arc::new(Concrete::Or(vec![(99, path2), (1, path3)]))
        } else {
            path2
        };

        let policy = Arc::new(Concrete::Or(vec![(1, path1), (1, path_2)]));
        let descriptor = policy_to_taproot(policy.clone(), self.contract_policy.network).unwrap();

        log::debug!("Descriptor: {}", descriptor.to_string());

        let address = descriptor.address(self.contract_policy.network).unwrap();

        self.set_address(address);
        Ok(policy)
    }

    // User fn

    pub fn check_buyer_signature(&self) -> bool {
        let check =
            self.check_signature(ContractState::Accepted, &self.buyer_signature, &self.buyer);
        log::debug!("Contract.check_buyer_signature() = {}", check);
        check
    }

    pub fn check_seller_signature(&self) -> bool {
        let check =
            self.check_signature(ContractState::Offered, &self.seller_signature, &self.seller);
        log::debug!("Contract.check_seller_signature() = {}", check);
        check
    }

    pub fn prepare_offer(&mut self, keys: &Keys) -> Result<(), ContractError> {
        self.set_state(ContractState::Offered);
        let id = self.hash(ContractState::Offered)?;
        let signature = self.sign(&id, keys)?;
        self.set_id(id);
        self.seller_signature = Some(signature);

        Ok(())
    }

    pub fn accept_contract(&mut self, keys: &Keys) -> Result<(), ContractError> {
        let preimage = self.process_hash_preimage(keys).unwrap();

        let policy = self.build_wallet_policy().unwrap();

        self.set_state(ContractState::Accepted);

        let id = self.hash(ContractState::Accepted).unwrap();
        let signature = self.sign(&id, keys)?;
        self.set_id(id);
        self.buyer_signature = Some(signature);

        Ok(())
    }

    pub fn refuse_contract(&mut self, keys: &Keys) -> Result<(), ContractError> {
        self.set_state(ContractState::Refused);
        let id = self.hash(self.state)?;
        let signature = self.sign(&id, keys)?;
        self.set_id(id);
        log::debug!("self.get_id()={:?}", self.get_id());
        self.buyer_signature = Some(signature);
        Ok(())
    }

    pub fn craft_withdraw_psbt(
        &mut self,
        preimage: &[u8; 32],
        transactions: Vec<Transaction>,
        fingerprint: Fingerprint,
        address: Address,
        network: Network,
        fees: u64,
    ) -> Result<Psbt, ContractError> {
        let hash = self
            .get_buyer_hash()
            .ok_or(ContractError::BuyerHashNeeded)?;
        let hash = miniscript::bitcoin::hashes::sha256::Hash::from_byte_array(hash);
        let utxos = self.get_locked_utxos();

        let policy = self.build_wallet_policy().unwrap();
        let descriptor = policy_to_taproot(policy, network).unwrap();
        let fingerprints = vec![fingerprint];
        let hash = (hash, preimage);

        let contract_addr = descriptor.address(network).unwrap();

        // Check destination != contract address
        if address == contract_addr {
            panic!("We should not let user relock funds!")
        }

        // Process the total amount
        let total_amount = utxos.iter().fold(0i64, |a, e| a + e.value);
        let total_amount = miniscript::bitcoin::Amount::from_sat(total_amount as u64);

        // Populate Tx Outputs w/ destination infos
        let outputs = vec![TxOut {
            value: total_amount,
            script_pubkey: address.into(),
        }];

        Ok(create_transaction(
            descriptor,
            fingerprints,
            Some(hash),
            None,
            utxos,
            transactions,
            outputs,
            fees,
        ))
    }

    pub fn craft_dispute_psbt(
        &mut self,
        transactions: Vec<Transaction>,
        fingerprints: Vec<Fingerprint>,
        outputs: Vec<TxOut>,
        network: Network,
        fees: u64,
    ) -> Result<Psbt, ContractError> {
        let utxos = self.get_locked_utxos();

        let policy = self.build_wallet_policy().unwrap();
        let descriptor = policy_to_taproot(policy, network).unwrap();

        // Process the total amount
        let total_amount = utxos.iter().fold(0i64, |a, e| a + e.value);

        let total_outputs = outputs
            .iter()
            .fold(0i64, |sum, output| sum + (output.value.to_sat() as i64));

        // FIXME: move this sanity check to create_transaction()
        assert!(total_outputs <= total_amount);

        Ok(create_transaction(
            descriptor,
            fingerprints,
            None,
            None,
            utxos,
            transactions,
            outputs,
            fees,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContractMessage {
    Offer(Contract, Peer),
    Refuse(ContractId, Peer),
    Accept(Contract, Peer),
    Funded(ContractId, Peer),
    Lock(ContractId, Peer),
    Unlock(ContractId, [u8; 32], Peer),
    Dispute(ContractId, Peer, Dispute),
}

#[cfg(test)]
mod tests {

    use miniscript::{
        bitcoin::{consensus::serialize, Transaction},
        psbt::PsbtExt,
    };

    use crate::{
        hot_signer::TaprootHotSigner,
        mempool_space_api::{get_address_txs::TxInfo, get_address_utxo::UtxoInfo},
        wallet::create_transaction,
    };

    use super::*;

    #[test]
    fn base_contract() {
        // create buyer/seller identity
        let buyer =
            Keys::from_str("nsec10qd3qz7lt7cpr6ay4fk4hfw9l63mmfw7lcmp6gcjz0tfpa6jpw6qkw2cy6")
                .unwrap();
        let seller =
            Keys::from_str("nsec133anjcqpashjv9ycxuvrfp0s2yhdpkddr3q2hlrzlht225uvyh5sm6hltk")
                .unwrap();

        let buyer_signer = TaprootHotSigner::new_from_mnemonics(
            Network::Signet,
            "biology art involve pole square feed mass adjust popular cruise amused range",
        );

        let seller_signer = TaprootHotSigner::new_from_mnemonics(
            Network::Signet,
            "inhale island kitten badge season evoke heavy remain artwork hybrid soup math",
        );

        // prepare contract
        let amount = Amount::from_sat(10_000_000);
        let mut contract = Contract::new(Network::Signet)
            .buyer(buyer.public_key())
            .seller(seller.public_key())
            .amount(amount)
            .details("some contract description....");

        // seller prepare & sign offer
        contract.prepare_offer(&seller).unwrap();

        // derive seller xpub
        let origin = contract.get_derivation_path().unwrap();

        let seller_xpub = seller_signer.concrete_at(origin.clone());

        // add seller xpub to contract
        contract.set_seller_xpub(seller_xpub);

        // Contract is send to buyer

        // Buyer receive contract

        // Buyer check contract hash and signature

        // derive buyer xpub
        let buyer_xpub = buyer_signer.concrete_at(origin.clone());

        // add buyer xpub to contract
        contract.set_buyer_xpub(buyer_xpub);

        // Buyer process policy, address, accept & sign contract
        contract.accept_contract(&buyer).unwrap();

        let address = contract.get_address().unwrap();
        assert_eq!(
            address.to_string(),
            "tb1pmdjk00kq5w9sl035w2xh96fzq79dxgz33z9qt9qx9njrxv3qgt9q0zqe2y".to_string()
        );

        // Buyer send accepted contract to seller

        // payment is done on-chain
        const UTXOS: &str = r#"
            [
                {
                    "txid":"367291bffd21db82bc80ea62193065a9a8ce9ba9b1467b6d19ad71bdecff438d",
                    "vout":1,
                    "value":2000000,
                    "status":{
                        "confirmed":true,
                        "block_height":198345,
                        "block_hash":"0000011be4c9a13ad3ffc8f255a0da9bc40c84d363d9ef03626c2d92ecb4e6b2",
                        "block_time":1717394043
                    }
                }
            ]
        "#;

        let utxos: Vec<UtxoInfo> = serde_json::from_str(UTXOS).unwrap();

        const TXS: &str = r#"
            [
                {
                    "txid":"367291bffd21db82bc80ea62193065a9a8ce9ba9b1467b6d19ad71bdecff438d",
                    "version":2,
                    "locktime":198344,
                    "vin":[
                        {
                            "txid":"723232b2a59617c470ae8f6f9736592235a0fdaae7896788bc1503d56b2d50fb",
                            "vout":0,
                            "prevout":{
                                "scriptpubkey":"76a9147233fb1d220a5c1d55ac5fe461f2aaa26feae54588ac",
                                "scriptpubkey_asm":"OP_DUP OP_HASH160 OP_PUSHBYTES_20 7233fb1d220a5c1d55ac5fe461f2aaa26feae545 OP_EQUALVERIFY OP_CHECKSIG",
                                "scriptpubkey_type":"p2pkh",
                                "scriptpubkey_address":"mqvobcuU1K8ZhEuuMQd4ztq611WYpqPAUn",
                                "value":4999635
                            },
                            "scriptsig":"47304402201bb80468498f5909577ea09e954384c18d34370f66a55d3173f50cd888c2bd37022062f97c3c3650d7c1f7f511ea1d244d0a5f65bd58f6c15d95a75b178cdd97123401210264bba522150343c8d1f63d312b5ffed0d37366969bbf1c7e1f8897962fc5ac7f",
                            "scriptsig_asm":"OP_PUSHBYTES_71 304402201bb80468498f5909577ea09e954384c18d34370f66a55d3173f50cd888c2bd37022062f97c3c3650d7c1f7f511ea1d244d0a5f65bd58f6c15d95a75b178cdd97123401 OP_PUSHBYTES_33 0264bba522150343c8d1f63d312b5ffed0d37366969bbf1c7e1f8897962fc5ac7f",
                            "is_coinbase":false,
                            "sequence":4294967293
                        }
                    ],
                    "vout":[
                        {
                            "scriptpubkey":"76a914f9b5f0ab67c5fcc3a35c9bf646d45febb4591bf788ac",
                            "scriptpubkey_asm":"OP_DUP OP_HASH160 OP_PUSHBYTES_20 f9b5f0ab67c5fcc3a35c9bf646d45febb4591bf7 OP_EQUALVERIFY OP_CHECKSIG",
                            "scriptpubkey_type":"p2pkh",
                            "scriptpubkey_address":"n4HJWEukUAKRxYE4D6FzaZgZUck6kMzLgC",
                            "value":2999400
                        },
                        {
                            "scriptpubkey":"5120db6567bec0a38b0fbe34728d72e922078ad32051888a0594062ce433322042ca",
                            "scriptpubkey_asm":"OP_PUSHNUM_1 OP_PUSHBYTES_32 db6567bec0a38b0fbe34728d72e922078ad32051888a0594062ce433322042ca",
                            "scriptpubkey_type":"v1_p2tr",
                            "scriptpubkey_address":"tb1pmdjk00kq5w9sl035w2xh96fzq79dxgz33z9qt9qx9njrxv3qgt9q0zqe2y",
                            "value":2000000
                        }
                    ],
                    "size":234,
                    "weight":936,
                    "sigops":4,
                    "fee":235,
                    "status":{
                        "confirmed":true,
                        "block_height":198345,
                        "block_hash":"0000011be4c9a13ad3ffc8f255a0da9bc40c84d363d9ef03626c2d92ecb4e6b2",
                        "block_time":1717394043
                    }
                }
            ]

        "#;

        let txs: Vec<TxInfo> = serde_json::from_str(TXS).unwrap();
        let txs = txs.into_iter().map(Transaction::from).collect::<Vec<_>>();

        // funds lock on contract

        // contract execution

        // Buyer unlock contract by sending hash preimage
        let (hash, preimage) = contract.process_hash_preimage(&buyer).unwrap();

        // seller prepare spend tx
        let policy = contract.build_wallet_policy().unwrap();
        let descriptor = policy_to_taproot(policy, Network::Signet).unwrap();

        let destination =
            Address::from_str("tb1pumxwrsecqr672a6l0cqcttn7303eraa25ckf8zea9k59yzng5asq5cgnxf")
                .unwrap()
                .assume_checked();

        let fingerprints = vec![seller_signer.fingerprint()];
        let hash = Some((hash, &preimage));

        // Process the total amount
        let total_amount = utxos.iter().fold(0i64, |a, e| a + e.value);
        let total_amount = miniscript::bitcoin::Amount::from_sat(total_amount as u64);

        // Populate Tx Outputs w/ destination infos
        let outputs = vec![TxOut {
            value: total_amount,
            script_pubkey: destination.into(),
        }];

        let mut psbt =
            create_transaction(descriptor, fingerprints, hash, None, utxos, txs, outputs, 1);

        // seller sign tx
        seller_signer.sign(&mut psbt);

        // println!("PSBT: {}", psbt);

        // seller finalyze psbt
        PsbtExt::finalize_mut(&mut psbt, seller_signer.secp()).unwrap();

        let tx = psbt.extract_tx_unchecked_fee_rate();

        let serialized = serialize(&tx);
        let hex_tx = hex::encode(serialized);

        println!("tx: {}", hex_tx);

        // seller can now broadcast psbt
    }
}
