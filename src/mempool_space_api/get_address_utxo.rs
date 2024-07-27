use std::str::FromStr;

use crate::mempool_space_api::error::MemPoolError;
use crate::mempool_space_api::{get_endpoint, NetworkApiUrl};
use bitcoin_amount::Amount;
use miniscript::bitcoin::{Address, Network, OutPoint, ScriptBuf, TxIn, Txid, Witness};
use serde::{Deserialize, Serialize};

#[allow(unused)]
pub async fn get_addresses_utxos(
    addr: Address,
    network: Network,
) -> Result<Vec<UtxoInfo>, MemPoolError> {
    let url = format!("{}address/{}/utxo", network.url(), addr);
    let response = get_endpoint::<Vec<UtxoInfo>>(&url).await?;

    let response = response
        .into_iter()
        .map(|mut info| {
            info.address = Some(addr.clone());
            info
        })
        .collect::<Vec<_>>();
    Ok(response)
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, PartialEq, Eq)]
pub struct UtxoInfo {
    #[serde(skip)]
    pub address: Option<Address>,
    pub txid: String,
    pub vout: u32,
    pub status: Status,
    pub value: i64,
}

impl UtxoInfo {
    pub fn amount(&self) -> Amount {
        Amount::from_sat(self.value)
    }
}

impl From<UtxoInfo> for TxIn {
    fn from(value: UtxoInfo) -> Self {
        TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(&value.txid).unwrap(),
                vout: value.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: miniscript::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct Status {
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
    pub block_time: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const EMPTY: &str = "[]";

    const UTXO_INFOS: &str = r#"
        [
            {
                "txid": "735d817405c1dd4d40dfbd1b477e943d796c5ae093de4e12b6de7dba3168ffd8",
                "vout": 0,
                "status": {
                    "confirmed": true,
                    "block_height": 189931,
                    "block_hash": "000000a2e969d03fc6627e33919e6df4633457061f2396a4a4eee54d7eaa589b",
                    "block_time": 1712284630
                },
                "value": 7339695
            }
        ]
    "#;

    #[test]
    fn test_deserialize_utxo_infos() {
        let infos: Result<Vec<UtxoInfo>, _> = serde_json::from_str(UTXO_INFOS);
        assert!(infos.is_ok());
        let infos = infos.unwrap();
        assert_eq!(infos.len(), 1);
        let infos = &infos[0];
        assert_eq!(
            infos.txid,
            "735d817405c1dd4d40dfbd1b477e943d796c5ae093de4e12b6de7dba3168ffd8"
        );
        assert!(infos.status.confirmed);
        assert_eq!(
            infos.status.block_hash,
            Some("000000a2e969d03fc6627e33919e6df4633457061f2396a4a4eee54d7eaa589b".to_string())
        );
        assert_eq!(infos.status.block_height, Some(189931));
        assert_eq!(infos.status.block_time, Some(1712284630));
        assert_eq!(infos.value, 7339695);
    }

    #[test]
    fn test_deserialize_utxo_empty() {
        let empty: Result<Vec<UtxoInfo>, _> = serde_json::from_str(EMPTY);
        assert!(empty.is_ok());
        assert!(empty.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_api_call() {
        let addr =
            Address::from_str("tb1p6srl98drx7j9hsrp0cmu9r2rl4gysqvegwltw07kl490hslgk6csmhrz7x")
                .unwrap()
                .assume_checked();
        let ret = get_addresses_utxos(addr, Network::Signet).await;
        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_api_call_empty_address() {
        let addr = Address::from_str("2MzQiCkd7hPAYgHBrWefhD6bg92VpjssAFv")
            .unwrap()
            .assume_checked();
        let ret = get_addresses_utxos(addr, Network::Signet).await;
        assert!(ret.is_ok());
    }
}
