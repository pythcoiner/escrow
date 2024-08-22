use iced::{
    alignment::Horizontal,
    widget::{container, Button, Column, Row, Space, Text, TextInput},
    Element, Length,
};

use crate::gui::{Escrow, Message};

pub fn connect_view(escrow: &Escrow) -> Element<Message> {
    let content = container(
        Column::new()
            .push(
                Row::new()
                    .push(Space::with_width(Length::Fill))
                    .push(
                        TextInput::new("Npriv", escrow.npriv())
                            .on_input(Message::Npriv)
                            .width(600.0),
                    )
                    .push(Space::with_width(Length::Fill)),
            )
            .push(Text::new(if let Some(e) = escrow.npriv_error() {
                e
            } else {
                "".to_string()
            }))
            .push(Space::with_height(40.0))
            .push(
                Row::new()
                    .push(Space::with_width(Length::Fill))
                    .push(
                        Button::new(Text::new("Create").horizontal_alignment(Horizontal::Center))
                            .on_press(Message::CreateNpriv)
                            .width(130.0),
                    )
                    .push(Space::with_width(30.0))
                    .push(
                        Button::new(Text::new("Connect").horizontal_alignment(Horizontal::Center))
                            .on_press(Message::ConnectNpriv)
                            .width(130.0),
                    )
                    .push(Space::with_width(Length::Fill)),
            )
            .width(600),
    );

    content.into()
}

pub fn connect_peer_view(escrow: &Escrow) -> Element<Message> {
    let content = container(
        Column::new()
            .push(
                Row::new()
                    .push(Space::with_width(Length::Fill))
                    .push(
                        TextInput::new("", escrow.npub())
                            .on_input(Message::Npub)
                            .width(600.0),
                    )
                    .push(Space::with_width(Length::Fill)),
            )
            .push(Space::with_height(5))
            .push(
                Row::new()
                    .push(Space::with_width(Length::Fill))
                    .push(
                        TextInput::new("", escrow.peer_npub_str())
                            .on_input(Message::PeerNpub)
                            .width(600.0),
                    )
                    .push(Space::with_width(Length::Fill)),
            )
            .push(Space::with_height(40.0))
            .push(
                Row::new()
                    .push(Space::with_width(Length::Fill))
                    .push(
                        Button::new(Text::new("Receive").horizontal_alignment(Horizontal::Center))
                            .on_press(Message::ReceiveMode)
                            .width(130.0),
                    )
                    .push(Space::with_width(30.0))
                    .push(
                        Button::new(Text::new("Send").horizontal_alignment(Horizontal::Center))
                            .on_press(Message::SendMode)
                            .width(130.0),
                    )
                    .push(Space::with_width(Length::Fill)),
            )
            .width(600),
    );

    content.into()
}
