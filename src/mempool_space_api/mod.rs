use crate::mempool_space_api::error::MemPoolError;
use miniscript::bitcoin::Network;
use reqwest::Response;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::future::Future;

pub mod error;
pub mod get_address_txs;
pub mod get_address_utxo;
pub mod post_transaction;

trait NetworkApiUrl {
    fn url(&self) -> &str;
}

impl NetworkApiUrl for Network {
    fn url(&self) -> &str {
        match self {
            Network::Bitcoin => "https://mempool.space/api/",
            Network::Testnet => "https://mempool.space/testnet/api/",
            Network::Signet => "https://mempool.space/signet/api/",
            _ => {
                panic!("Network not supported by mempool.space!")
            }
        }
    }
}

fn build_api_request(url: &str) -> impl Future<Output = Result<Response, reqwest::Error>> {
    reqwest::Client::new().get(url).send()
}

#[allow(unused)]
async fn get_endpoint<T>(url: &str) -> Result<T, MemPoolError>
where
    T: DeserializeOwned + Clone,
{
    let response = build_api_request(url)
        .await
        .map_err(|_| MemPoolError::ApiRequestFail)?;

    let response = response.json::<Value>().await.map_err(|e| {
        println!("Request fail: {:?}", e);
        MemPoolError::ResponseDeserializeFail
    })?;

    let output: T = serde_json::from_value(response).map_err(|e| {
        println!("Fail to deserialize data:{:?}", e);
        MemPoolError::DataDeserializeFail
    })?;

    Ok(output.clone())
}
