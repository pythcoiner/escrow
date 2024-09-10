use bip39::Mnemonic;
use miniscript::bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use miniscript::bitcoin::hashes::Hash;

use miniscript::bitcoin::secp256k1::All;
use miniscript::bitcoin::sighash;
use miniscript::bitcoin::{self, psbt, Psbt};
use miniscript::bitcoin::{bip32, secp256k1, Network, PrivateKey};
use miniscript::descriptor::DescriptorXKey;
use miniscript::DescriptorPublicKey;
use std::fmt::Debug;
use std::str::FromStr;

pub struct TaprootHotSigner {
    #[allow(unused)]
    key: PrivateKey,
    master_xpriv: Xpriv,
    fingerprint: bip32::Fingerprint,
    secp: secp256k1::Secp256k1<All>,
    mnemonic: Option<Mnemonic>,
}

impl Debug for TaprootHotSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaprootHotSigner")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

#[allow(unused)]
impl TaprootHotSigner {
    pub fn new_from_xpriv(network: Network, xpriv: Xpriv) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let fingerprint = xpriv.fingerprint(&secp);
        TaprootHotSigner {
            key: xpriv.to_priv(),
            master_xpriv: xpriv,
            fingerprint,
            secp,
            mnemonic: None,
        }
    }

    pub fn new(network: Network) -> Self {
        // TODO: add randomness generator
        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut signer = Self::new_from_mnemonics(network, &mnemonic.to_string());
        signer.mnemonic = Some(mnemonic);
        signer
    }

    pub fn new_from_mnemonics(network: Network, mnemonic: &str) -> Self {
        let mnemonic = Mnemonic::from_str(mnemonic).unwrap();
        let seed = mnemonic.to_seed("");
        let key = bip32::Xpriv::new_master(network, &seed).unwrap();
        Self::new_from_xpriv(network, key)
    }

    pub fn sign(&self, psbt: &mut Psbt) {
        let mut sighash_cache = sighash::SighashCache::new(&psbt.unsigned_tx);

        let prevouts = psbt
            .inputs
            .iter()
            .filter_map(|i| i.witness_utxo.clone())
            .collect::<Vec<_>>();

        for i in 0..psbt.inputs.len() {
            self.sign_input(&mut sighash_cache, &prevouts, &mut psbt.inputs[i], i);
        }
    }

    fn sign_input(
        &self,
        sighash_cache: &mut sighash::SighashCache<&bitcoin::Transaction>,
        prevouts: &[bitcoin::TxOut],
        psbt_in: &mut psbt::Input,
        input_index: usize,
    ) {
        let sighash_type = sighash::TapSighashType::Default;
        let prevouts = sighash::Prevouts::All(prevouts);

        // NOTE: the internal key should always be a dummy key, so it never had to be signalled for
        // signing

        // if psbt_in.tap_internal_key.is_some() {
        // }

        //  tap_key_origin() -> BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>
        for (pubkey, (leaf_hashes, (fingerprint, deriv_path))) in &psbt_in.tap_key_origins {
            if *fingerprint != self.fingerprint {
                continue;
            }

            leaf_hashes.iter().for_each(|lh| {
                let privkey = self.xpriv_at(deriv_path.clone()).to_priv();
                let key_pair = secp256k1::Keypair::from_secret_key(&self.secp, &privkey.inner);
                let sighash = sighash_cache
                    .taproot_script_spend_signature_hash(input_index, &prevouts, *lh, sighash_type)
                    .unwrap();
                let sighash = secp256k1::Message::from_digest_slice(sighash.as_byte_array())
                    .expect("SigHash is always 32 bytes!");
                let sig = self.secp.sign_schnorr_no_aux_rand(&sighash, &key_pair);
                let sig = bitcoin::taproot::Signature {
                    sig,
                    hash_ty: sighash_type,
                };
                psbt_in.tap_script_sigs.insert((*pubkey, *lh), sig);
            });
        }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    pub fn secp(&self) -> &secp256k1::Secp256k1<All> {
        &self.secp
    }

    pub fn xpriv_at(&self, path: DerivationPath) -> Xpriv {
        self.master_xpriv.derive_priv(self.secp(), &path).unwrap()
    }

    pub fn xpub_at(&self, path: DerivationPath) -> Xpub {
        let xpriv = self.xpriv_at(path);
        Xpub::from_priv(self.secp(), &xpriv)
    }

    pub fn concrete_at(&self, path: DerivationPath) -> DescriptorPublicKey {
        let xpub = self.xpub_at(path.clone());
        let key = DescriptorXKey {
            origin: Some((self.fingerprint(), path)),
            xkey: xpub,
            derivation_path: DerivationPath::default(),
            wildcard: miniscript::descriptor::Wildcard::None,
        };
        DescriptorPublicKey::XPub(key)
    }

    pub fn mnemonic(&self) -> Option<Mnemonic> {
        self.mnemonic.clone()
    }
}

#[cfg(test)]
mod tests {

    use miniscript::bitcoin::bip32::ChildNumber;

    use super::*;

    #[test]
    fn signer_from_mnemonic() {
        let mnemonic =
            "unknown salute trim jaguar edge domain enact shock wheat concert again artwork";
        let signer = TaprootHotSigner::new_from_mnemonics(Network::Signet, mnemonic);
        assert_eq!(
            signer.fingerprint(),
            Fingerprint::from_str("63114451").unwrap()
        );

        let _origin_xpub = signer.xpub_at(vec![ChildNumber::from_hardened_idx(48).unwrap()].into());
    }
}
