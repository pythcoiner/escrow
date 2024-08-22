use crate::views::theme;
use iced::{
    widget::{scrollable, Button, Column, Container, Row, Space, Text, TextInput},
    Length,
};

pub struct ChatEntry {
    pub user: User,
    pub text: String,
}

pub enum User {
    Me,
    Other(String),
    #[allow(unused)]
    Escrow(String),
}

use crate::gui::{Escrow, Message};

pub fn main_chat(escrow: &Escrow) -> Column<Message> {
    let mut chat = Column::new().padding(15);

    for entry in escrow.chat_history() {
        chat = chat.push(chat_line(entry));
        chat = chat.push(Space::with_height(3.0));
    }

    let chat_box = Container::new(scrollable(chat).height(580))
        .style(theme::chat_box)
        .padding(5);

    Column::new()
        .push(
            Row::new()
                .push(Space::with_width(Length::Fill))
                .push(Text::new("Chat").size(25.0))
                .push(Space::with_width(Length::Fill)),
        )
        .push(Space::with_height(20.0))
        .push(chat_box)
        .push(Space::with_height(5.0))
        .push(
            Row::new()
                .push(
                    TextInput::new("send message to peer...", escrow.chat_input())
                        .on_input(Message::ChatMsg)
                        .on_submit(Message::SendChat)
                        .width(Length::Fill),
                )
                .push(Space::with_width(10.0))
                .push(Button::new(Text::new("Send")).on_press(Message::SendChat)),
        )
}

fn chat_line(entry: &ChatEntry) -> Container<Message> {
    let me = match &entry.user {
        User::Me => Some(Space::with_width(Length::Fill)),
        _ => None,
    };
    let other = match &entry.user {
        User::Me => None,
        _ => Some(Space::with_width(Length::Fill)),
    };

    let chat_style = if me.is_some() {
        theme::chat_entry_me
    } else {
        theme::chat_entry_other
    };

    let row = Row::new()
        .push_maybe(me)
        .push(
            Container::new(Text::new(&entry.text))
                .padding(5.0)
                .style(chat_style),
        )
        .push_maybe(other);

    Container::new(row)
}

// fn message_box(text: &str) -> Column<Message> {
//     Column::new().push(
//         Row::new()
//             .push(Space::with_width(Length::Fill))
//             .push(
//                 container(Text::new(text))
//                     .width(400)
//                     .height(400)
//                     .style(theme::chat_box),
//             )
//             .push(Space::with_width(Length::Fill)),
//     )
// }
