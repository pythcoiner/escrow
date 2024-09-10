use clap::Parser;

use crate::{
    config::{try_import_contract, try_import_indentity},
    contract::Contract,
    gui::{Identity, Side},
};

#[derive(Parser, Debug)]
pub struct Cli {
    /// The nostr identity fingerprint
    #[arg(short, long)]
    pub identity: Option<String>,
    /// The contract id (hash)
    #[arg(short, long)]
    pub contract: Option<String>,
    // /// The side (buyer/seller)
    // #[arg(short, long)]
    // side: Option<Side>,
}

impl Cli {
    pub fn identity(&self) -> Option<Identity> {
        if let Some(identity_str) = self.identity.as_ref() {
            return try_import_indentity(identity_str.to_string());
        }
        None
    }

    pub fn contract(&self) -> Option<(Contract, Side)> {
        if let (Some(identity), Some(contract)) = (self.identity.as_ref(), self.contract.as_ref()) {
            try_import_contract(contract.clone(), identity.clone())
        } else {
            None
        }
    }
}
