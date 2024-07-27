use miniscript::{
    bitcoin::{
        absolute::{Height, LockTime},
        bip32::{self, ChildNumber, DerivationPath, Fingerprint, Xpub},
        hashes::{sha256, Hash},
        secp256k1, Amount, Network, Psbt, Sequence, Transaction, TxIn, TxOut, Txid,
    },
    descriptor::{self, DescriptorXKey, Wildcard},
    policy::Concrete,
    psbt::PsbtInputExt,
    DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, ForEachKey,
};
use std::{collections::BTreeMap, str::FromStr, sync::Arc};

use crate::mempool_space_api::get_address_utxo::UtxoInfo;

pub(crate) const MAX_DERIV: u32 = (2u64.pow(31) - 1) as u32;

#[derive(Debug)]
#[allow(unused)]
pub enum WalletError {
    ContractIdMissing,
    BuyerXpubMissing,
    SellerXpubMissing,
    ThirdPartyMissing,
    BuyerPrivMissing,
    FailCompilingPolicy,
    LocalValidityCheckFailed,
    ConvertToDescriptorFail,
    InvalidPolicy,
    DerivationFail,
    AddressFail,
}

pub fn derive_xpub(
    xpub: DescriptorPublicKey,
    mut deriv_path: Vec<ChildNumber>,
    offset: Option<u32>,
) -> DescriptorPublicKey {
    if let DescriptorPublicKey::XPub(mut xpub) = xpub {
        assert!(deriv_path.len() == 2);

        // apply offset
        if let Some(offset) = offset {
            deriv_path[1] = ((u32::from(deriv_path[1]) + offset) % MAX_DERIV).into();
        }

        xpub.derivation_path = DerivationPath::from(deriv_path);

        DescriptorPublicKey::XPub(xpub)
    } else {
        panic!("Xpub should be of type DescriptorPublicKey::XPub!");
    }
}

pub fn xpub_to_concrete(
    fingerprint: Fingerprint,
    mut xpub: Xpub,
    xpub_path: &DerivationPath,
) -> DescriptorPublicKey {
    xpub.parent_fingerprint = fingerprint;
    let key = DescriptorXKey {
        origin: Some((fingerprint, xpub_path.clone())),
        xkey: xpub,
        derivation_path: DerivationPath::default(),
        wildcard: Wildcard::None,
    };

    DescriptorPublicKey::XPub(key)
}

pub fn encode_descriptor_pubkey(key: &DescriptorPublicKey) -> [u8; 78] {
    if let DescriptorPublicKey::XPub(k) = key {
        let key = k.xkey;
        key.encode()
    } else {
        panic!("Should be an DescriptorPublicKey::XPub");
    }
}

// TODO: fn to check address from seller side

// pub fn policy_to_segwit(
//     policy: Arc<Concrete<DescriptorPublicKey>>,
// ) -> Result<Descriptor<DescriptorPublicKey>, WalletError> {
//     let compiled = policy
//         .compile::<Segwitv0>()
//         .map_err(|_| WalletError::FailCompilingPolicy)?;
//
//     Segwitv0::check_local_policy_validity(&compiled)
//         .map_err(|_| WalletError::LocalValidityCheckFailed)?;
//
//     let descriptor =
//         descriptor::Wsh::new(compiled).map_err(|_| WalletError::ConvertToDescriptorFail)?;
//
//     Ok(Descriptor::Wsh(descriptor))
// }

fn get_xkey(desc_key: &DescriptorPublicKey) -> Option<&Xpub> {
    if let DescriptorPublicKey::XPub(DescriptorXKey { xkey, .. }) = desc_key {
        Some(xkey)
    } else {
        None
    }
}

// From Liana Wallet: liana/src/descriptor/analysis.rs
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs:
// > One example of such a point is H =
// > lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0) which is constructed
// > by taking the hash of the standard uncompressed encoding of the secp256k1 base point G as X
// > coordinate.
fn bip341_nums() -> secp256k1::PublicKey {
    secp256k1::PublicKey::from_str(
        "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .expect("Valid pubkey: NUMS from BIP341")
}

// Inspired from Liana Wallet: liana/src/descriptor/analysis.rs
// Construct an unspendable key to be used as internal key in a Taproot descriptor, in a way which
// could eventually be standardized into wallet policies for a signer to display to the user
// "UNSPENDABLE" upon registration (instead of a meaningless key).
// See https://delvingbitcoin.org/t/unspendable-keys-in-descriptors/304/21.
//
// Returns `None` if:
// - The given descriptor does not contain a Taptree with at least a key in each leaf.
// - The keys contained in the descriptor aren't all `DescriptorPublicKey::Single`.
fn unspendable_internal_xpub(
    desc: &descriptor::Tr<DescriptorPublicKey>,
    network: Network,
) -> Option<Xpub> {
    let tap_tree = desc.tap_tree().as_ref().unwrap();

    // Compute the chaincode to use for the xpub. This is the sha256() of the concatenation of all
    // the xpubs' pubkey part in the Taptree.
    let concat = tap_tree
        .iter()
        .flat_map(|(_, ms)| ms.iter_pk())
        .try_fold(Vec::new(), |mut acc, pk| {
            let xkey = get_xkey(&pk).unwrap();
            acc.extend_from_slice(&xkey.public_key.serialize());
            Some(acc)
        })
        .unwrap();
    let chain_code = bip32::ChainCode::from(sha256::Hash::hash(&concat).as_ref());

    // Construct the unspendable key. The pubkey part is always BIP341's NUMS.
    let public_key = bip341_nums();
    Some(Xpub {
        public_key,
        chain_code,
        depth: 0,
        parent_fingerprint: [0; 4].into(),
        child_number: 0.into(),
        network,
    })
}

fn unspendable_internal_key(
    descriptor: &descriptor::Tr<descriptor::DescriptorPublicKey>,
    network: Network,
) -> Option<descriptor::DescriptorPublicKey> {
    let child = ChildNumber::from_normal_idx(0).unwrap();
    let deriv = DerivationPath::from(vec![child]);
    Some(descriptor::DescriptorPublicKey::XPub(
        descriptor::DescriptorXKey {
            origin: None,
            xkey: unspendable_internal_xpub(descriptor, network)?,
            derivation_path: deriv,
            wildcard: Wildcard::None,
        },
    ))
}

pub fn policy_to_taproot(
    policy: Arc<Concrete<DescriptorPublicKey>>,
    network: Network,
) -> Result<Descriptor<DefiniteDescriptorKey>, WalletError> {
    let dummy_internal_key = DescriptorPublicKey::XPub(descriptor::DescriptorXKey::<Xpub> {
        origin: None,
        xkey: Xpub {
            public_key: bip341_nums(),
            chain_code: [0; 32].into(),
            depth: 0,
            parent_fingerprint: [0; 4].into(),
            child_number: 0.into(),
            network,
        },
        derivation_path: vec![].into(),
        wildcard: Wildcard::None,
    });

    // We should add a dummy key in order to compile and then replace it w/ unspendable key
    // generated from the generated taptree

    // First round we generate taptree
    let tr_descriptor = policy
        .clone()
        .compile_tr(Some(dummy_internal_key.clone()))
        .unwrap();
    // .map_err(|_| WalletError::InvalidPolicy)?;

    let inner_desc = if let descriptor::Descriptor::Tr(ref d) = tr_descriptor {
        d
    } else {
        unreachable!()
    };

    // Build provably unspendable key fron previously generated taptree
    let unspendable_key = if inner_desc.internal_key() == &dummy_internal_key {
        unspendable_internal_key(inner_desc, network)
    } else {
        panic!("Internal key should still be dummy key as we do not have single key path!")
    };

    // Compile final descriptor
    let descriptor = policy
        .compile_tr(unspendable_key)
        .map_err(|_| WalletError::InvalidPolicy)?;

    // The descriptor should not have wildcard in order we can turn it into a DefiniteDescriptorKey
    assert!(!descriptor.has_wildcard());

    // As the descriptor does not have wildcard, no derivation happend, just turn into
    // DefiniteDescriptorKey
    descriptor
        .at_derivation_index(0)
        .map_err(|_| WalletError::InvalidPolicy)
}

// // Derive address using derivation path made of
// pub fn derive_address(
//     descriptor: Descriptor<DescriptorPublicKey>,
//     index: u32,
//     network: Network,
// ) -> Result<Address, WalletError> {
//     let desc = descriptor.into_single_descriptors().map_err(|e| {
//         log::error!("{:?}", e);
//         WalletError::DerivationFail
//     })?;
//     desc.first()
//         .expect("Should have 2 descriptors!")
//         .at_derivation_index(index)
//         .map_err(|e| {
//             log::error!("{:?}", e);
//             WalletError::DerivationFail
//         })?
//         .address(network)
//         .map_err(|_| WalletError::AddressFail)
// }

#[allow(clippy::too_many_arguments)]
pub fn create_transaction(
    descriptor: Descriptor<DefiniteDescriptorKey>,
    fingerprints: Vec<Fingerprint>,
    hash: Option<(sha256::Hash, &[u8; 32])>,
    timelock: Option<u32>,
    destination: miniscript::bitcoin::address::Address,
    utxos: Vec<UtxoInfo>,
    txs: Vec<Transaction>,
    fee_rate: u64,
    network: Network,
) -> Psbt {
    if fingerprints.is_empty() {
        panic!("Need at list one signer!")
    }

    let mut signing_fingerprints = Vec::<Fingerprint>::new();

    // check  if supplied fingerprints match w/ descriptor
    if let Descriptor::Tr(tr) = descriptor.clone() {
        // // check if we can sign w/ the internal key
        // let internal_fg = tr.internal_key().master_fingerprint();
        // if fingerprints.contains(&internal_fg) {
        //     signing_fingerprints.push(internal_fg);
        // } else {
        //     panic!("We should have an XPub type here!")
        // }

        // if we got the internal key we do not need others
        if signing_fingerprints.is_empty() {
            // Check fingerprint in taptree
            if tr.tap_tree().is_some() {
                tr.for_each_key(|k| {
                    let fg = k.master_fingerprint();
                    if fingerprints.contains(&fg) && !signing_fingerprints.contains(&fg) {
                        signing_fingerprints.push(fg);
                    }
                    // return true to iter over all keys
                    true
                });
            };
        }

        if signing_fingerprints.is_empty() {
            panic!("No key fingerprints matches with descriptor!");
        }
    } else {
        panic!("We expect a taproot descriptor!");
    }

    // TODO: if locktime passed, check if match w/ descriptor

    // Process the total amount
    let total_amount = utxos.iter().fold(0i64, |a, e| a + e.value);
    let total_amount = Amount::from_sat(total_amount as u64);

    let contract_addr = descriptor.address(network).unwrap();

    // Populate Tx inputs from UtxoInfos
    let inputs: Vec<TxIn> = utxos
        .clone()
        .into_iter()
        // NOTE: TxIn::from(UtxoInfo) assign a sequence value of ENABLE_RBF_NO_LOCKTIME
        .map(|i| {
            let mut tx_in = TxIn::from(i);
            // specify sequence if recovery path
            if let Some(tl) = timelock {
                tx_in.sequence = Sequence(tl);
            }
            tx_in
        })
        .collect();

    //Populate PSBT inputs w/ descriptors infos
    let mut psbt_inputs = Vec::new();
    for u in utxos {
        let txid = Txid::from_str(&u.txid).unwrap();
        let tx = txs.iter().find(|tx| tx.txid() == txid).unwrap();
        let mut inp = miniscript::bitcoin::psbt::Input::default();
        // Build spend info from descriptor
        inp.update_with_descriptor_unchecked(&descriptor).unwrap();
        // add hash + preimage
        if let Some((h, preimage)) = hash {
            inp.sha256_preimages.insert(h, preimage.to_vec());
        }
        let amount = u.amount().into_inner();
        let amount = miniscript::bitcoin::Amount::from_sat(amount as u64);
        let script_pubkey = tx.output[u.vout as usize].script_pubkey.clone();
        inp.witness_utxo = Some(TxOut {
            value: amount,
            script_pubkey,
        });

        psbt_inputs.push(inp);
    }

    // Check destination != contract address
    if destination == contract_addr {
        panic!("We should not let user relock funds!")
    }

    // Populate Tx Outputs w/ destination infos
    let outputs = vec![TxOut {
        value: total_amount,
        script_pubkey: destination.clone().into(),
    }];

    // Prepare PSBT outputs
    let psbt_out = miniscript::bitcoin::psbt::Output::default();
    let psbt_outputs = vec![psbt_out];

    // Pre-fill the Tx
    let mut tx = miniscript::bitcoin::Transaction {
        version: miniscript::bitcoin::transaction::Version::TWO,
        // TODO: add anti-fee-snipping
        lock_time: LockTime::Blocks(Height::ZERO),
        input: inputs,
        // we fill output in order to get the weight, will replace w/ amount - fee later
        output: outputs,
    };

    // process fee amount
    // FIXME: The fee amount is wrong
    let wu = tx.weight().to_wu();
    let fee_sats = Amount::from_sat(wu * fee_rate);

    let outputs = vec![TxOut {
        value: total_amount - fee_sats,
        script_pubkey: destination.into(),
    }];

    // replace outputs w/ final amount w/ fees decreased
    tx.output = outputs;

    // Return an PSBT (Tx only)
    Psbt {
        unsigned_tx: tx,
        version: 0,
        xpub: BTreeMap::new(),
        proprietary: BTreeMap::new(),
        unknown: BTreeMap::new(),
        inputs: psbt_inputs,
        outputs: psbt_outputs,
    }

    // FIXME: Add some sanity checks on the generated output
}
