mod bitcoin;
mod client;
mod contract;
mod gui;
mod hot_signer;
mod logger;
mod mempool_space_api;
mod nostr;
pub mod signing_device;
mod wallet;
mod views;

use crate::bitcoin::BitcoinClient;
use crate::client::ClientFn;
use crate::gui::{Escrow, Flags};
use crate::nostr::{NostrArgs, NostrClient};
use iced::{Application, Settings, Size};
use miniscript::bitcoin::Network;

#[tokio::main]
async fn main() {
    #[cfg(target_arch = "wasm32")]
    {
        console_log::init().expect("Initialize logger");
        std::panic::set_hook(Box::new(console_error_panic_hook::hook));
    }

    #[cfg(not(target_arch = "wasm32"))]
    logger::set_logger(true);

    let (bitcoin_sender, gui_bitcoin_receiver) = async_channel::unbounded();
    let (gui_bitcoin_sender, bitcoin_receiver) = async_channel::unbounded();

    let (nostr_sender, gui_nostr_receiver) = async_channel::unbounded();
    let (gui_nostr_sender, nostr_receiver) = async_channel::unbounded();

    let flags = Flags {
        nostr_sender: gui_nostr_sender,
        nostr_receiver: gui_nostr_receiver,
        bitcoin_sender: gui_bitcoin_sender.clone(),
        bitcoin_receiver: gui_bitcoin_receiver,
        network: Network::Signet,
    };

    let bitcoin = BitcoinClient::new(bitcoin_sender, bitcoin_receiver, gui_bitcoin_sender);
    bitcoin.start();

    let args = NostrArgs {
        // relays: vec!["ws://127.0.0.1:8080"],
        relays: vec!["wss://relay.damus.io"],
    };

    let nostr = NostrClient::new(nostr_sender, nostr_receiver, args);
    nostr.start();

    let mut settings = Settings::with_flags(flags);
    settings.window.size = Size::new(950.0, 750.0);
    Escrow::run(settings).expect("")
}
