use std::str::FromStr;

use crate::mempool_space_api::error::MemPoolError;
use crate::mempool_space_api::{get_endpoint, NetworkApiUrl};
use miniscript::bitcoin::transaction::Version;
use miniscript::bitcoin::{
    absolute, Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use serde::{Deserialize, Serialize};

#[allow(unused)]
pub async fn get_addresses_txs(
    addr: Address,
    network: Network,
) -> Result<Vec<TxInfo>, MemPoolError> {
    let url = format!("{}address/{}/txs", network.url(), addr);
    get_endpoint::<Vec<TxInfo>>(&url).await
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Status {
    confirmed: bool,
    block_height: u32,
    block_hash: String,
    block_time: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Vin {
    txid: String,
    vout: u32,
    prevout: Vout,
    scriptsig: String,
    scriptsig_asm: String,
    witness: Option<Vec<String>>,
    is_coinbase: bool,
    sequence: u64,
}

impl From<Vin> for TxIn {
    fn from(value: Vin) -> Self {
        // TODO: double check how it's parsed in https://github.com/rust-bitcoin/rust-bitcoincore-rpc
        let witness = value
            .witness
            .map(|w| {
                let vec_u8: Vec<&[u8]> = w.iter().map(|s| s.as_bytes()).collect();
                let slices: &[&[u8]] = &vec_u8;
                Witness::from_slice(slices)
            })
            .unwrap_or_default();
        TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(&value.txid).unwrap(),
                vout: value.vout,
            },
            script_sig: ScriptBuf::from_hex(&value.scriptsig).unwrap(),
            sequence: miniscript::bitcoin::Sequence(value.sequence as u32),
            witness,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Vout {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: String,
    value: u64,
}

impl From<Vout> for TxOut {
    fn from(value: Vout) -> Self {
        TxOut {
            value: Amount::from_sat(value.value),
            script_pubkey: ScriptBuf::from_hex(&value.scriptpubkey).unwrap(),
        }
    }
}

// Transaction information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxInfo {
    txid: Txid,
    version: i32,
    locktime: u32,
    vin: Vec<Vin>,
    vout: Vec<Vout>,
    size: u32,
    weight: u32,
    sigops: u32,
    fee: u64,
    status: Status,
}

impl From<TxInfo> for miniscript::bitcoin::Transaction {
    fn from(value: TxInfo) -> Self {
        Transaction {
            version: Version(value.version),
            lock_time: absolute::LockTime::from_height(value.locktime).unwrap(),
            input: value.vin.into_iter().map(TxIn::from).collect(),
            output: value.vout.into_iter().map(TxOut::from).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // virgin address
    const SAMPLE_VIRGIN_JSON: &str = r#"
        []
    "#;

    const VIN: &str = r#"
        {
                    "txid": "eb5cd446e05a6f4a2e96ebb30f29be10ffe8668265d54e3c79cf59f0ec4f9a8d",
                    "vout": 0,
                    "prevout": {
                        "scriptpubkey": "5120c5a4be48d764bf2fc83c14cbce7c245c93b458c998753b4b3f871217854a18a8",
                        "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 c5a4be48d764bf2fc83c14cbce7c245c93b458c998753b4b3f871217854a18a8",
                        "scriptpubkey_type": "v1_p2tr",
                        "scriptpubkey_address": "tb1pckjtujxhvjljljpuzn9uulpytjfmgkxfnp6nkjelsufp0p22rz5q7j3jxl",
                        "value": 3264799
                    },
                    "scriptsig": "",
                    "scriptsig_asm": "",
                    "witness": [
                        "c0f3e0cbcfa97e1dbb3cabfd5f5d055a8dba983940f5b490353d51001b6d37dffa7b70a89d0f50b58c2ab344ad2bc80c901219692bc7a8a8e1831bec839d5491"
                    ],
                    "is_coinbase": false,
                    "sequence": 4294967293
                }
    "#;

    const VOUT: &str = r#"
        {
                    "scriptpubkey": "512045af714e89a708d5d3a43eece3af6617ea3d25098b42fa54acd8daf52a16fc10",
                    "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 45af714e89a708d5d3a43eece3af6617ea3d25098b42fa54acd8daf52a16fc10",
                    "scriptpubkey_type": "v1_p2tr",
                    "scriptpubkey_address": "tb1pgkhhzn5f5uydt5ay8mkw8tmxzl4r6fgf3dp0549vmrd022sklsgq4gv7tp",
                    "value": 582027
                }
    "#;

    const TXINFO: &str = r#"
        {
            "txid": "0497db9c55ff3511f6cd7d1a271d1e73837e26107f5e9e5fda413fafcf440dc9",
            "version": 2,
            "locktime": 191924,
            "vin": [
                {
                    "txid": "eb5cd446e05a6f4a2e96ebb30f29be10ffe8668265d54e3c79cf59f0ec4f9a8d",
                    "vout": 0,
                    "prevout": {
                        "scriptpubkey": "5120c5a4be48d764bf2fc83c14cbce7c245c93b458c998753b4b3f871217854a18a8",
                        "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 c5a4be48d764bf2fc83c14cbce7c245c93b458c998753b4b3f871217854a18a8",
                        "scriptpubkey_type": "v1_p2tr",
                        "scriptpubkey_address": "tb1pckjtujxhvjljljpuzn9uulpytjfmgkxfnp6nkjelsufp0p22rz5q7j3jxl",
                        "value": 3264799
                    },
                    "scriptsig": "",
                    "scriptsig_asm": "",
                    "witness": [
                        "c0f3e0cbcfa97e1dbb3cabfd5f5d055a8dba983940f5b490353d51001b6d37dffa7b70a89d0f50b58c2ab344ad2bc80c901219692bc7a8a8e1831bec839d5491"
                    ],
                    "is_coinbase": false,
                    "sequence": 4294967293
                },
                {
                    "txid": "7f17f278a5a0ffe0c9a17947517a637e1583e63d466e2d66b0b66e48499278e5",
                    "vout": 1,
                    "prevout": {
                        "scriptpubkey": "512068bc27436747815768cb7ba23695b7aad6ce9cc0702cd0b74ef02b03f7d85bd6",
                        "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 68bc27436747815768cb7ba23695b7aad6ce9cc0702cd0b74ef02b03f7d85bd6",
                        "scriptpubkey_type": "v1_p2tr",
                        "scriptpubkey_address": "tb1pdz7zwsm8g7q4w6xt0w3rd9dh4ttva8xqwqkdpd6w7q4s8a7ct0tqhzdpmw",
                        "value": 592176
                    },
                    "scriptsig": "",
                    "scriptsig_asm": "",
                    "witness": [
                        "dbaa796bd15e6a3ea990ab8590dae7b0707099c187644b94c6a8607e2d4f759a751cf610e79d0d72e580ca02a954f92db03e1ed873fc6d5bef6c8b21612f7c41"
                    ],
                    "is_coinbase": false,
                    "sequence": 4294967293
                }
            ],
            "vout": [
                {
                    "scriptpubkey": "512045af714e89a708d5d3a43eece3af6617ea3d25098b42fa54acd8daf52a16fc10",
                    "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 45af714e89a708d5d3a43eece3af6617ea3d25098b42fa54acd8daf52a16fc10",
                    "scriptpubkey_type": "v1_p2tr",
                    "scriptpubkey_address": "tb1pgkhhzn5f5uydt5ay8mkw8tmxzl4r6fgf3dp0549vmrd022sklsgq4gv7tp",
                    "value": 582027
                },
                {
                    "scriptpubkey": "5120e4a6dc7ed3f494c200fec97cef195c85194b4163e219727ceabdcf2c20914c1e",
                    "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 e4a6dc7ed3f494c200fec97cef195c85194b4163e219727ceabdcf2c20914c1e",
                    "scriptpubkey_type": "v1_p2tr",
                    "scriptpubkey_address": "tb1pujndclkn7j2vyq87e97w7x2us5v5kstrugvhyl82hh8jcgy3fs0qyv6k9c",
                    "value": 10000
                },
                {
                    "scriptpubkey": "51206b8b6138864a591069632d98e6ef78448ec6fafaf79b28823fa3d01647e61013",
                    "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 6b8b6138864a591069632d98e6ef78448ec6fafaf79b28823fa3d01647e61013",
                    "scriptpubkey_type": "v1_p2tr",
                    "scriptpubkey_address": "tb1pdw9kzwyxffv3q6tr9kvwdmmcgj8vd7h677dj3q3l50gpv3lxzqfsh2spg5",
                    "value": 3254650
                },
                {
                    "scriptpubkey": "51201a66ae3dd4b6a2287f494a9509fe3ddd4469cdf3cd3f57263a966ea430555156",
                    "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 1a66ae3dd4b6a2287f494a9509fe3ddd4469cdf3cd3f57263a966ea430555156",
                    "scriptpubkey_type": "v1_p2tr",
                    "scriptpubkey_address": "tb1prfn2u0w5k63zsl6ff22snl3am4zxnn0ne5l4wf36jeh2gvz429tq7edqx6",
                    "value": 10000
                }
            ],
            "size": 398,
            "weight": 1190,
            "sigops": 0,
            "fee": 298,
            "status": {
                "confirmed": true,
                "block_height": 191925,
                "block_hash": "000000b5a23effbaaa7074d098fec40ac1e8b2a9419b636c18a390099521b032",
                "block_time": 1713516451
            }
        }
    "#;

    const UNSPENT: &str = r#"
        [
    {
        "txid": "735d817405c1dd4d40dfbd1b477e943d796c5ae093de4e12b6de7dba3168ffd8",
        "version": 2,
        "locktime": 189930,
        "vin": [
            {
                "txid": "eee008839d2c6eaa4494a684d5958317923f7c25c3cc59377431f1853cc3a522",
                "vout": 0,
                "prevout": {
                    "scriptpubkey": "a914cebdd4609fb88bbc3a188c19d58f775e94ef333787",
                    "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 cebdd4609fb88bbc3a188c19d58f775e94ef3337 OP_EQUAL",
                    "scriptpubkey_type": "p2sh",
                    "scriptpubkey_address": "2NC6NbPjfvSpx6R9DgLRJG7eW8Xmk8BEaJo",
                    "value": 12339872
                },
                "scriptsig": "160014084955fea4360512e8fef2868929f4c5839555c0",
                "scriptsig_asm": "OP_PUSHBYTES_22 0014084955fea4360512e8fef2868929f4c5839555c0",
                "witness": [
                    "304402206878ca94ee7360e63f93c0d5c340f6acd00a4bcee5e708113d5e4f0c703b27b4022045e2064e365f3e69c2e72692d55380361a37b9bc388b93bd2f5a22ddd93d2c7c01",
                    "033e3fbbab1422c23e9c4801025e204d51d92b70c0f3327a6f00304315b264dc25"
                ],
                "is_coinbase": false,
                "sequence": 4294967293,
                "inner_redeemscript_asm": "OP_0 OP_PUSHBYTES_20 084955fea4360512e8fef2868929f4c5839555c0"
            }
        ],
        "vout": [
            {
                "scriptpubkey": "a914ad40ab3566005f6a017afd2b4e7ab0119eafc75d87",
                "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 ad40ab3566005f6a017afd2b4e7ab0119eafc75d OP_EQUAL",
                "scriptpubkey_type": "p2sh",
                "scriptpubkey_address": "2N93JMjfjPBAxsbuGDApYak8rTtDrvvC8hT",
                "value": 7339695
            },
            {
                "scriptpubkey": "00202a57454abd66f2ccdb9a5e9b6ead45891eed0bd008d7c3d1eb09327df8d64068",
                "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_32 2a57454abd66f2ccdb9a5e9b6ead45891eed0bd008d7c3d1eb09327df8d64068",
                "scriptpubkey_type": "v0_p2wsh",
                "scriptpubkey_address": "tb1q9ft52j4avmeveku6t6dkat293y0w6z7sprtu850tpye8m7xkgp5qkgsedc",
                "value": 5000000
            }
        ],
        "size": 258,
        "weight": 705,
        "sigops": 1,
        "fee": 177,
        "status": {
            "confirmed": true,
            "block_height": 189931,
            "block_hash": "000000a2e969d03fc6627e33919e6df4633457061f2396a4a4eee54d7eaa589b",
            "block_time": 1712284630
        }
    }
]
    "#;

    // spent adress
    const TXINFOS: &str = r#"
    [
        {
            "txid": "0497db9c55ff3511f6cd7d1a271d1e73837e26107f5e9e5fda413fafcf440dc9",
            "version": 2,
            "locktime": 191924,
            "vin": [
                {
                    "txid": "eb5cd446e05a6f4a2e96ebb30f29be10ffe8668265d54e3c79cf59f0ec4f9a8d",
                    "vout": 0,
                    "prevout": {
                        "scriptpubkey": "5120c5a4be48d764bf2fc83c14cbce7c245c93b458c998753b4b3f871217854a18a8",
                        "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 c5a4be48d764bf2fc83c14cbce7c245c93b458c998753b4b3f871217854a18a8",
                        "scriptpubkey_type": "v1_p2tr",
                        "scriptpubkey_address": "tb1pckjtujxhvjljljpuzn9uulpytjfmgkxfnp6nkjelsufp0p22rz5q7j3jxl",
                        "value": 3264799
                    },
                    "scriptsig": "",
                    "scriptsig_asm": "",
                    "witness": [
                        "c0f3e0cbcfa97e1dbb3cabfd5f5d055a8dba983940f5b490353d51001b6d37dffa7b70a89d0f50b58c2ab344ad2bc80c901219692bc7a8a8e1831bec839d5491"
                    ],
                    "is_coinbase": false,
                    "sequence": 4294967293
                },
                {
                    "txid": "7f17f278a5a0ffe0c9a17947517a637e1583e63d466e2d66b0b66e48499278e5",
                    "vout": 1,
                    "prevout": {
                        "scriptpubkey": "512068bc27436747815768cb7ba23695b7aad6ce9cc0702cd0b74ef02b03f7d85bd6",
                        "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 68bc27436747815768cb7ba23695b7aad6ce9cc0702cd0b74ef02b03f7d85bd6",
                        "scriptpubkey_type": "v1_p2tr",
                        "scriptpubkey_address": "tb1pdz7zwsm8g7q4w6xt0w3rd9dh4ttva8xqwqkdpd6w7q4s8a7ct0tqhzdpmw",
                        "value": 592176
                    },
                    "scriptsig": "",
                    "scriptsig_asm": "",
                    "witness": [
                        "dbaa796bd15e6a3ea990ab8590dae7b0707099c187644b94c6a8607e2d4f759a751cf610e79d0d72e580ca02a954f92db03e1ed873fc6d5bef6c8b21612f7c41"
                    ],
                    "is_coinbase": false,
                    "sequence": 4294967293
                }
            ],
            "vout": [
                {
                    "scriptpubkey": "512045af714e89a708d5d3a43eece3af6617ea3d25098b42fa54acd8daf52a16fc10",
                    "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 45af714e89a708d5d3a43eece3af6617ea3d25098b42fa54acd8daf52a16fc10",
                    "scriptpubkey_type": "v1_p2tr",
                    "scriptpubkey_address": "tb1pgkhhzn5f5uydt5ay8mkw8tmxzl4r6fgf3dp0549vmrd022sklsgq4gv7tp",
                    "value": 582027
                },
                {
                    "scriptpubkey": "5120e4a6dc7ed3f494c200fec97cef195c85194b4163e219727ceabdcf2c20914c1e",
                    "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 e4a6dc7ed3f494c200fec97cef195c85194b4163e219727ceabdcf2c20914c1e",
                    "scriptpubkey_type": "v1_p2tr",
                    "scriptpubkey_address": "tb1pujndclkn7j2vyq87e97w7x2us5v5kstrugvhyl82hh8jcgy3fs0qyv6k9c",
                    "value": 10000
                },
                {
                    "scriptpubkey": "51206b8b6138864a591069632d98e6ef78448ec6fafaf79b28823fa3d01647e61013",
                    "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 6b8b6138864a591069632d98e6ef78448ec6fafaf79b28823fa3d01647e61013",
                    "scriptpubkey_type": "v1_p2tr",
                    "scriptpubkey_address": "tb1pdw9kzwyxffv3q6tr9kvwdmmcgj8vd7h677dj3q3l50gpv3lxzqfsh2spg5",
                    "value": 3254650
                },
                {
                    "scriptpubkey": "51201a66ae3dd4b6a2287f494a9509fe3ddd4469cdf3cd3f57263a966ea430555156",
                    "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 1a66ae3dd4b6a2287f494a9509fe3ddd4469cdf3cd3f57263a966ea430555156",
                    "scriptpubkey_type": "v1_p2tr",
                    "scriptpubkey_address": "tb1prfn2u0w5k63zsl6ff22snl3am4zxnn0ne5l4wf36jeh2gvz429tq7edqx6",
                    "value": 10000
                }
            ],
            "size": 398,
            "weight": 1190,
            "sigops": 0,
            "fee": 298,
            "status": {
                "confirmed": true,
                "block_height": 191925,
                "block_hash": "000000b5a23effbaaa7074d098fec40ac1e8b2a9419b636c18a390099521b032",
                "block_time": 1713516451
            }
        }
    ]
    "#;

    #[test]
    fn test_deserialise_vin() {
        let vin: Result<Vin, serde_json::Error> = serde_json::from_str(VIN);
        assert!(vin.is_ok(), "Fail deserialise Vin")
    }

    #[test]
    fn test_deserialise_vout() {
        let vout: Result<Vout, serde_json::Error> = serde_json::from_str(VOUT);
        assert!(vout.is_ok(), "Fail deserialise Vout")
    }

    #[test]
    fn test_deserialise_txinfo() {
        let tx_info: Result<TxInfo, serde_json::Error> = serde_json::from_str(TXINFO);
        assert!(tx_info.is_ok(), "Fail deserialise TxInfo")
    }

    #[test]
    fn test_deserialise_txinfos() {
        let tx_infos: Result<Vec<TxInfo>, serde_json::Error> = serde_json::from_str(TXINFOS);
        assert!(tx_infos.is_ok(), "Fail deserialise TxInfo s")
    }

    #[tokio::test]
    async fn test_api_call_empty_address() {
        let addr = Address::from_str("2MzQiCkd7hPAYgHBrWefhD6bg92VpjssAFv")
            .unwrap()
            .assume_checked();
        let ret = get_addresses_txs(addr, Network::Signet).await;
        assert!(ret.is_ok());
    }
}
