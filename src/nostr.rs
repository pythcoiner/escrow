use crate::client::ClientFn;
use crate::contract::ContractMessage;
use crate::gui::Message;
use crate::gui::Message::NostrClientMsg;
use crate::listener;
use nostr_sdk::async_utility::tokio;
use nostr_sdk::nips::nip04;
use nostr_sdk::{
    Client, Event, Filter, Keys, Kind, Options, PublicKey, RelayMessage, RelayPoolNotification,
    Tag, ToBech32,
};
use std::time::Duration;
use tokio::sync::broadcast;

listener!(NostrListener, NostrMessage, Message, NostrClientMsg);

#[derive(Debug, Clone)]
#[allow(unused)]
pub enum NostrMessage {
    // receive
    Connect(Keys),
    Peer(PublicKey),
    DmToPeer(String),

    // send
    AllReadyConnected,
    Connected,
    FailToConnect,
    DmFromPeer(String),
    DmToPeerSent(String),
    Contract(Box<ContractMessage>),
}

#[allow(unused)]
pub struct NostrClient {
    sender: Sender<NostrMessage>,
    receiver: Receiver<NostrMessage>,
    relays: Vec<&'static str>,
    keys: Option<Keys>,
    client: Option<Client>,
    nostr_receiver: Option<broadcast::Receiver<RelayPoolNotification>>,
    peer_key: Option<PublicKey>,
}

impl NostrClient {
    pub fn start(mut self) {
        tokio::spawn(async move {
            self.run().await;
        });
    }

    async fn subscribe_dm(&self, client: &Client) {
        if let Some(keys) = &self.keys {
            let dm = Filter::new()
                .pubkey(keys.public_key())
                .kind(Kind::EncryptedDirectMessage);

            client.subscribe(vec![dm], None).await;
            log::info!("Subscribed to DM");
        }
    }

    pub fn send_response(&mut self, msg: NostrMessage) {
        if self.sender.try_send(msg).is_err() {
            log::error!("Fail to send NostrMessage to GUI!")
        }
    }

    pub async fn handle_message_from_gui(&mut self, msg: NostrMessage) {
        // log::debug!("NostrClient.handle_message_from_gui({:?}", msg);
        #[allow(clippy::single_match)]
        match msg {
            NostrMessage::Connect(keys) => match self.client {
                None => {
                    log::info!("Try to connect to nostr");
                    if let Some(client) = self.connect_nostr(keys).await {
                        self.nostr_receiver = Some(client.notifications());
                        self.client = Some(client);
                        log::info!("Nostr Connected!");
                        self.send_response(NostrMessage::Connected);
                    }
                }
                Some(_) => self.send_response(NostrMessage::AllReadyConnected),
            },
            NostrMessage::Peer(pubkey) => {
                if let Some(client) = self.client.take() {
                    self.subscribe_dm(&client).await;
                    self.client = Some(client);
                }
                self.peer_key = Some(pubkey);
            }
            NostrMessage::DmToPeer(msg) => self.send_dm_to_peer(msg).await,
            NostrMessage::Contract(msg) => {
                // log::debug!("NostrMessage::Contract() => {:?}", msg);
                self.contract_from_gui(*msg).await
            }
            _ => {
                log::error!("unhandled message")
            }
        }
    }

    async fn contract_from_gui(&mut self, msg: ContractMessage) {
        // log::debug!("NostrClient.contract_from_gui({:?}", &msg);
        if let Ok(payload) = serde_json::to_string(&msg) {
            self.send_dm_to_peer(payload).await
        } else {
            panic!("Cannot serialize message: {:?}", msg);
        }
    }

    fn contract_to_gui(&mut self, msg: ContractMessage) {
        // log::debug!("NostrClient.contract_to_gui({:?})", msg);
        let msg = NostrMessage::Contract(Box::new(msg));
        self.send_response(msg);
    }

    pub async fn connect_nostr(&mut self, keys: Keys) -> Option<Client> {
        self.keys = Some(keys.clone());
        let opts = Options::new()
            .skip_disconnected_relays(true)
            .connection_timeout(Some(Duration::from_secs(10)))
            .send_timeout(Some(Duration::from_secs(5)));

        let client = Client::with_opts(&keys, opts);
        if client.add_relays(self.relays.clone()).await.is_ok() {
            client.connect().await;
            Some(client)
        } else {
            None
        }
    }

    pub fn handle_relay_notification(&mut self, notif: RelayPoolNotification) {
        match notif {
            RelayPoolNotification::Event { event, .. } => self.handle_relay_event(event),
            RelayPoolNotification::Message { message, .. } => self.handle_relay_message(message),
            RelayPoolNotification::RelayStatus { .. } => {}
            RelayPoolNotification::Stop => {}
            RelayPoolNotification::Shutdown => {}
        }
    }

    pub fn handle_relay_event(&mut self, event: Box<Event>) {
        // log::debug!("Received event");
        #[allow(clippy::single_match)]
        match event.kind {
            Kind::RelayList => self.handle_relay_list(*event),
            Kind::EncryptedDirectMessage => self.handle_dm(*event),
            _ => {}
        }
    }

    pub fn handle_relay_message(&mut self, _msg: RelayMessage) {
        // TODO: handle dm sent ACK + resend after timeout
        // log::info!("Received message: {:?}", msg);
        log::info!("NostrClient.handle_relay_message()");
    }

    pub fn handle_relay_list(&mut self, event: Event) {
        let urls = event
            .tags
            .clone()
            .into_iter()
            .filter_map(|tag| {
                if let Tag::RelayMetadata(url, _) = tag {
                    Some(url.to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<String>>();
        log::debug!("Received relay list: {:?}", urls)
    }

    pub fn handle_dm(&mut self, event: Event) {
        // log::debug!("NostrClient.handle_dm({:?})", event);
        if event.kind == Kind::EncryptedDirectMessage {
            if let (Some(keys), Some(peer)) = (&self.keys.as_ref(), &self.peer_key.as_ref()) {
                if *peer != event.author_ref() {
                    log::error!("NostrClient..handle_dm() => DM not from peer");
                    return;
                }
                match nip04::decrypt(
                    keys.secret_key().unwrap(),
                    event.author_ref(),
                    event.content(),
                ) {
                    Ok(r) => {
                        if let Ok(m) = serde_json::from_str::<ContractMessage>(&r) {
                            // try to deserialize ContractMessage
                            log::debug!("NostrClient.handle_dm() => Received ContractMessage");
                            self.contract_to_gui(m);
                        } else {
                            // else its a DM
                            log::debug!("NostrClient.handle_dm() => Received DM");
                            self.send_response(NostrMessage::DmFromPeer(r))
                        }
                    }
                    Err(e) => {
                        log::error!("Cannot decrypt DM: {}", e);
                    }
                }
            } else {
                panic!("Key or peer is missing!!!");
            }
        } else {
            panic!("Event of kind {:?} != EncryptedDirectMessage", event.kind);
        }
    }

    pub async fn send_dm_to_peer(&mut self, content: String) {
        // log::debug!("NostrClient.send_dm_to_peer({:?}", &content);
        if let (Some(client), Some(peer)) = (&self.client, &self.peer_key) {
            if client.send_direct_msg(*peer, &content, None).await.is_err() {
                log::error!("Cannot send message to {:?}", self.peer_key)
            } else {
                // if it's a ContractMessage we do not display as sent
                if serde_json::from_str::<ContractMessage>(&content).is_err() {
                    self.send_response(NostrMessage::DmToPeerSent(content))
                }
            }
        } else {
            log::error!(
                "Client or peer key missing {:?}, {:?}",
                self.client,
                self.peer_key
            );
        }
    }
}

#[derive(Debug)]
#[allow(unused)]
pub struct NostrArgs {
    pub relays: Vec<&'static str>,
}

impl ClientFn<NostrMessage, NostrArgs> for NostrClient {
    fn new(
        sender: Sender<NostrMessage>,
        receiver: Receiver<NostrMessage>,
        args: NostrArgs,
    ) -> Self {
        NostrClient {
            sender,
            receiver,
            relays: args.relays,
            keys: None,
            client: None,
            nostr_receiver: None,
            peer_key: None,
        }
    }

    async fn run(&mut self) {
        loop {
            // handle message from gui
            if let Ok(msg) = self.receiver.try_recv() {
                self.handle_message_from_gui(msg).await;
            }
            // handle nostr messages
            if let Some(receiver) = self.nostr_receiver.as_mut() {
                if let Ok(notification) = receiver.try_recv() {
                    self.handle_relay_notification(notification);
                }
            }
            tokio::time::sleep(Duration::from_nanos(1)).await;
        }
    }
}

pub fn generate_npriv() -> String {
    let keys = Keys::generate();
    keys.secret_key()
        .expect("cannot fail")
        .to_bech32()
        .expect("cannot fail")
}

pub fn key_from_npriv(npriv: &String) -> Option<Keys> {
    Keys::parse(npriv).ok()
}
