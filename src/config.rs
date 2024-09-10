use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

use crate::{
    contract::Contract,
    gui::{Identity, Side},
};

pub fn datadir() -> PathBuf {
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

    maybe_create_dir(&dir);

    dir
}

pub fn maybe_create_dir(dir: &PathBuf) {
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

pub fn maybe_save_identity(fingerprint: &str, identity: Identity) {
    let mut dir = datadir();
    dir.push(fingerprint);

    maybe_create_dir(&dir);

    dir.push("identity");

    if !dir.exists() {
        let mut identity_file = File::create(dir).unwrap();

        let yaml_str = serde_yaml::to_string(&identity).unwrap();

        identity_file.write_all(yaml_str.as_bytes()).unwrap();
    }
}

pub fn maybe_save_contract(
    fingerprint: String,
    identity: Identity,
    side: Side,
    contract: Contract,
) {
    maybe_save_identity(&fingerprint, identity);

    let contract_name = contract
        .hash(crate::contract::ContractState::Accepted)
        .unwrap()
        .to_string()[..20]
        .to_string();

    let mut dir = datadir();
    dir.push(&fingerprint);
    dir.push("contracts");
    dir.push(side.to_string());

    maybe_create_dir(&dir);

    dir.push(contract_name);

    let mut contract_file = File::create(dir).unwrap();

    let yaml_str = serde_yaml::to_string(&contract).unwrap();

    contract_file.write_all(yaml_str.as_bytes()).unwrap();
}

pub fn try_import_indentity(identity: String) -> Option<Identity> {
    let mut identity_path = datadir();
    identity_path.push(identity);
    identity_path.push("identity");
    if identity_path.exists() {
        if let Ok(file) = File::open(identity_path) {
            return serde_yaml::from_reader(file).ok();
        };
    }
    None
}

pub fn list_contracts(identity_fingerprint: String) -> Vec<(String, Side, PathBuf)> {
    let mut out = Vec::new();
    let mut contract_path = datadir();
    contract_path.push(identity_fingerprint);
    contract_path.push("contracts");

    let mut buyer_path = contract_path.clone();
    buyer_path.push("buyer");
    let mut seller_path = contract_path;
    seller_path.push("seller");

    fn fetch_contracts(path: PathBuf, side: Side) -> Vec<(String, Side, PathBuf)> {
        if let Ok(contracts) = fs::read_dir(path) {
            contracts
                .into_iter()
                .filter_map(|entry| {
                    if let Ok(entry) = entry {
                        if entry.path().is_file() {
                            let path = entry.path();
                            let id = path.file_name();
                            id.map(|id| (id.to_string_lossy().to_string(), side, path.clone()))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        }
    }
    out.append(&mut fetch_contracts(seller_path, Side::Seller));
    out.append(&mut fetch_contracts(buyer_path, Side::Buyer));

    out
}

pub fn try_import_contract(contract_id: String, fingerprint: String) -> Option<(Contract, Side)> {
    if try_import_indentity(fingerprint.clone()).is_some() {
        if let Some((_, side, path)) = list_contracts(fingerprint)
            .into_iter()
            .find(|(id, _, _)| *id == contract_id)
        {
            if let Ok(file) = File::open(path) {
                if let Ok(contract) = serde_yaml::from_reader(file) {
                    return Some((contract, side));
                }
            }
        }
    }
    None
}
