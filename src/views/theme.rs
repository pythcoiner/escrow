use iced::{widget::container::Appearance, Border, Color, Theme};

pub fn chat_box(theme: &Theme) -> Appearance {
    let palette = theme.extended_palette();

    Appearance {
        background: Some(palette.background.weak.color.into()),
        border: Border::with_radius(10),
        ..Appearance::default()
    }
}

pub fn chat_entry_me(_: &Theme) -> Appearance {
    let red = Color::from_rgb8(250, 120, 120);
    let mut a = Appearance::default().with_background(red);
    a.border.radius = 4.into();
    a.text_color = Some(Color::BLACK);
    a
}

pub fn chat_entry_other(_: &Theme) -> Appearance {
    let blue = Color::from_rgb8(120, 235, 250);
    let mut a = Appearance::default().with_background(blue);
    a.border.radius = 4.into();
    a.text_color = Some(Color::BLACK);
    a
}
