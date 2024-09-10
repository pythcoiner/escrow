use std::str::FromStr;

use iced::{
    widget::{
        container, row, Button, Column, PickList, QRCode, Row, Space, Text, TextEditor, TextInput,
    },
    Length, Theme,
};
use miniscript::bitcoin::Address;

use crate::gui::{ContractState, Escrow, Message, Side, TimelockUnit};
use crate::views::theme;

pub fn contract_column(escrow: &Escrow) -> Column<Message> {
    let side = escrow.side();
    let step = escrow.contract_state();

    let contract_title = match (side, step) {
        (Side::Seller, ContractState::None) => "Prepare escrow contract!",
        (Side::Seller, ContractState::Offered) => "Waiting your peer accept contract...",
        (Side::Seller, ContractState::Accepted) => "Contract accepted!",
        (Side::Seller, ContractState::Funded) => "Contract funded! (unconfirmed)",
        (Side::Seller, ContractState::Locked) => "Funds locked in escrow",
        (Side::Seller, ContractState::Unlocked) => "Funds unlocked!",
        (Side::Buyer, ContractState::None) => "Waiting for seller to create contract...",
        (Side::Buyer, ContractState::Offered) => "Seller want to offer you this contract:",
        (Side::Buyer, ContractState::Accepted) => "Fund contract!",
        (Side::Buyer, ContractState::Funded) => "Contract funded (unconfirmed)...",
        (Side::Buyer, ContractState::Locked) => "Funds locked in escrow!",
        (Side::Buyer, ContractState::Unlocked) => "Payment finalized",
        (_, ContractState::InDispute) | (_, ContractState::DisputeOffered) => "Dispute Offer",
        (_, ContractState::DisputeAccepted) => "Dispute Accepted",
        _ => "",
    };

    let buttons = match (side, step) {
        (Side::Seller, ContractState::None) => btn_row(
            vec![(
                "Send contract!",
                if escrow.is_contract_valid() {
                    Some(Message::OfferContract)
                } else {
                    None
                },
            )],
            false,
        ),
        (Side::Seller, ContractState::Locked) => {
            btn_row(vec![("Dispute", Some(Message::Dispute))], false)
        }
        (Side::Seller, ContractState::Unlocked) => {
            let addr_valid = Address::from_str(escrow.withdraw_address()).is_ok();
            let withdraw_action = if addr_valid {
                Some(Message::Withdraw)
            } else {
                None
            };
            btn_row(vec![("Withdraw", withdraw_action)], false)
        }
        (Side::Buyer, ContractState::Offered) => btn_row(
            vec![
                ("Refuse", Some(Message::RefuseContract)),
                ("Accept and pay", Some(Message::AcceptContract)),
            ],
            false,
        ),
        (Side::Buyer, ContractState::Accepted) => {
            btn_row(vec![("PSBT Broadcast", Some(Message::TxBroadcasted))], true)
        }
        (Side::Buyer, ContractState::Funded) => {
            btn_row(vec![("Tx mined", Some(Message::TxMined))], true)
        }
        (Side::Buyer, ContractState::Locked) => {
            btn_row(vec![("Unlock", Some(Message::UnlockFunds))], false)
        }
        (Side::Seller, ContractState::InDispute) => {
            let message = if escrow.can_send_dispute_offer() {
                Some(Message::SendDisputeOffer)
            } else {
                None
            };
            btn_row(vec![("Send", message)], false)
        }
        (Side::Buyer, ContractState::DisputeOffered) => btn_row(
            vec![
                (
                    "Accept",
                    if escrow.can_accept_dispute() {
                        Some(Message::AcceptDisputeOffer)
                    } else {
                        None
                    },
                ),
                ("Refuse", Some(Message::RefuseDisputeOffer)),
            ],
            false,
        ),
        _ => {
            row!(Space::with_height(25))
        }
    };

    let content = match (side, step) {
        (Side::Seller, ContractState::Offered) | (Side::Buyer, ContractState::None) => None,
        (Side::Buyer, ContractState::Accepted) => Some(fund_contract(escrow)),
        (_, ContractState::DisputeAccepted)
        | (_, ContractState::DisputeOffered)
        | (_, ContractState::InDispute) => Some(dispute_offer(escrow)),
        _ => Some(contract(escrow)),
    };

    let display_withdraw =
        escrow.side() == Side::Seller && escrow.contract_state() == ContractState::Unlocked;
    let withdraw_input = if display_withdraw {
        Some(
            Row::new().push(
                TextInput::new("Enter an address to withdraw to", escrow.withdraw_address())
                    .on_input(Message::WithdrawAddress),
            ),
        )
    } else {
        None
    };

    Column::new()
        .push(Space::with_height(Length::Fill))
        .push(Space::with_height(50))
        .push(
            Row::new()
                .push(Space::with_width(Length::Fill))
                .push(Text::new(contract_title).size(30))
                .push(Space::with_width(Length::Fill)),
        )
        .push(Space::with_height(40.0))
        .push_maybe(content)
        .push(Space::with_height(30.0))
        .push_maybe(withdraw_input)
        .push_maybe(if display_withdraw {
            Some(Space::with_height(30))
        } else {
            None
        })
        .push(buttons)
        .push(Space::with_height(Length::Fill))
}

fn contract(escrow: &Escrow) -> Column<Message> {
    let units = [
        TimelockUnit::Day.to_string(),
        TimelockUnit::Hour.to_string(),
        TimelockUnit::Block.to_string(),
    ];

    let (amount_placeholder, deposit_placeholder, timelock_placeholder) =
        if escrow.side() == Side::Seller && escrow.contract_state() == ContractState::None {
            ("0.04 BTC", "0.01 BTC", "65535")
        } else {
            ("", "", "")
        };

    Column::new()
        .push(
            Row::new()
                .push(Text::new("Total amount to receive"))
                .push(Space::with_width(Length::Fill))
                .push(
                    TextInput::new(amount_placeholder, escrow.total_amount())
                        .on_input(Message::Amount)
                        .width(200.0),
                ),
        )
        .push(Space::with_height(30.0))
        .push(
            Row::new()
                .push(Text::new("Deposit"))
                .push(Space::with_width(Length::Fill))
                .push(
                    TextInput::new(deposit_placeholder, escrow.deposit_amount())
                        .on_input(Message::Deposit)
                        .width(200.0),
                ),
        )
        .push(Space::with_height(30.0))
        .push(
            Row::new()
                .push(Text::new("Timelock"))
                .push(Space::with_width(Length::Fill))
                .push(
                    TextInput::new(timelock_placeholder, escrow.timelock())
                        .on_input(Message::Timelock)
                        .width(110.0),
                )
                .push(Space::with_width(10.0))
                .push(
                    PickList::new(
                        units.clone(),
                        Some(escrow.timelock_unit().to_string()),
                        Message::TimelockUnit,
                    )
                    .width(80.0),
                ),
        )
        .push(Space::with_height(30.0))
        .push(
            TextEditor::new(escrow.contract_text())
                .on_action(Message::ContractDetail)
                .height(250),
        )
}

fn dispute_offer(escrow: &Escrow) -> Column<Message> {
    let (my_amount_label, other_amount_label) = match escrow.side() {
        Side::Buyer => ("Amount to receive back", "Amount to send"),
        Side::Seller => (
            "Amount to receive",
            // Message::DisputeAmount,
            "Amount to send back",
        ),
        _ => ("", ""),
    };
    let my_amount_message = match (escrow.side(), escrow.contract_state()) {
        (Side::Seller, ContractState::InDispute) => Message::DisputeAmount,
        _ => Message::Nop,
    };
    let address_message = match (escrow.side(), escrow.contract_state()) {
        (Side::Buyer, ContractState::DisputeOffered) | (Side::Seller, ContractState::InDispute) => {
            Message::DisputeAddress
        }
        (_, _) => Message::Nop,
    };
    Column::new()
        .push(
            Row::new()
                .push(Text::new(my_amount_label))
                .push(Space::with_width(Length::Fill))
                .push(
                    TextInput::new("", escrow.my_dispute_amount())
                        .on_input(my_amount_message)
                        .width(200.0),
                ),
        )
        .push(Space::with_height(30.0))
        .push(
            Row::new()
                .push(Text::new("Address"))
                .push(Space::with_width(Length::Fill))
                .push(
                    TextInput::new("", escrow.dispute_address())
                        .on_input(address_message)
                        .width(200.0),
                ),
        )
        .push(Space::with_height(30.0))
        .push(
            Row::new()
                .push(Text::new(other_amount_label))
                .push(Space::with_width(Length::Fill))
                .push(
                    TextInput::new("", escrow.peer_dispute_amount())
                        .on_input(Message::Nop)
                        .width(200.0),
                ),
        )
}

fn fund_contract(escrow: &Escrow) -> Column<Message> {
    Column::new()
        .push(
            Row::new()
                .push(Space::with_width(Length::Fill))
                .push(
                    container(qr_code(escrow))
                        .width(Length::Shrink)
                        .height(Length::Shrink)
                        .padding(25)
                        .style(theme::chat_box),
                )
                .push(Space::with_width(Length::Fill)),
        )
        .push(Space::with_height(10))
        .push(
            TextInput::new(
                "",
                escrow
                    .deposit_address()
                    .as_ref()
                    .expect("Should have an address at this step"),
            )
            .on_input(Message::Nop),
        )
}

pub fn btn_row(labels: Vec<(&str, Option<Message>)>, debug: bool) -> Row<Message> {
    let mut btns = labels
        .into_iter()
        .map(|(label, msg)| {
            let mut btn: Button<Message> = Button::new(label).on_press_maybe(msg);
            if debug {
                btn = btn.style(iced::theme::Button::Destructive);
            }
            btn
        })
        .collect::<Vec<_>>()
        .into_iter();

    let mut row = Row::new()
        .push(Space::with_width(Length::Fill))
        .push(btns.next().expect("At least one button"));

    for btn in btns {
        row = row.push(Space::with_width(30)).push(btn);
    }

    row.push(Space::with_width(Length::Fill))
}

fn qr_code(escrow: &Escrow) -> QRCode<Theme> {
    escrow
        .qr()
        .as_ref()
        .map(|data| QRCode::new(data).cell_size(8))
        .expect("Adress QR should not fail")
}
