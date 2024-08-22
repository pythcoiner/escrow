use iced::{
    widget::{container, row, Column, Row, Space},
    Alignment, Element, Length, Renderer, Theme,
};

use crate::gui::{Escrow, Message};

pub mod chat;
pub mod connect;
pub mod contract;
pub mod theme;

pub fn main_view(escrow: &Escrow) -> Element<Message> {
    let content = container(
        row!(
            contract::contract_column(escrow).width(400.0).height(900.0),
            Space::with_width(30.0),
            chat::main_chat(escrow).width(400.0).height(900.0),
        )
        .align_items(Alignment::Center),
    );

    content.into()
}

pub fn main_frame(element: Element<Message>) -> Column<Message> {
    let output: Column<Message, Theme, Renderer> = Column::new()
        .push(Space::with_height(Length::Fill))
        .push(
            Row::new()
                .push(Space::with_width(Length::Fill))
                .push(container(element))
                .push(Space::with_width(Length::Fill)),
        )
        .push(Space::with_height(Length::Fill))
        .padding(20.0);

    output
}
