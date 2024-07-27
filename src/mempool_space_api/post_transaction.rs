use crate::mempool_space_api::error::MemPoolError;
use crate::mempool_space_api::NetworkApiUrl;
use miniscript::bitcoin::consensus::encode::serialize_hex;
use miniscript::bitcoin::{Network, Transaction};

pub async fn post_transaction(tx: Transaction, network: Network) -> Result<(), MemPoolError> {
    let url = format!("{}tx", &network.url());
    let tx_id = tx.txid().to_string();
    let raw_tx = serialize_hex(&tx);
    let ret = reqwest::Client::new().post(url).body(raw_tx).send().await;
    match ret {
        Ok(r) => {
            if r.text()
                .await
                .map_err(|_| MemPoolError::DataDeserializeFail)?
                != tx_id
            {
                Err(MemPoolError::ApiRequestFail)
            } else {
                Ok(())
            }
        }
        Err(_) => Err(MemPoolError::ApiRequestFail),
    }
}
