//! SpaceX / xAI-inspired terminal aesthetic.
//! Black void · white signal · red for critical.

use comfy_table::{Attribute, Cell, Color as TableColor};
use owo_colors::OwoColorize;
use std::fmt::Display;

/// Section hairline — thin, quiet, expensive-looking.
pub fn rule() {
    println!(
        "  {}",
        "────────────────────────────────────────────────────────────"
            .bright_black()
    );
}

pub fn value_white(s: impl Display) -> String {
    format!("{}", s.to_string().white().bold())
}

pub fn value_ok(s: impl Display) -> String {
    format!("{}", s.to_string().green().bold())
}

pub fn section_title(title: &str) {
    println!();
    println!(
        "  {}  {}",
        "■".white().bold(),
        title.to_uppercase().white().bold()
    );
    rule();
}

pub fn kv(key: &str, val: impl Display) {
    println!(
        "  {:<10}  {}",
        key.to_uppercase().bright_black(),
        val
    );
}

/// Header cell for comfy-table — monochrome mission control.
pub fn th(text: &str) -> Cell {
    Cell::new(text)
        .add_attribute(Attribute::Bold)
        .fg(TableColor::White)
}

pub fn td_open() -> Cell {
    Cell::new("OPEN")
        .fg(TableColor::Green)
        .add_attribute(Attribute::Bold)
}

pub fn td_white(s: impl AsRef<str>) -> Cell {
    Cell::new(s.as_ref()).fg(TableColor::White)
}

pub fn td_dim(s: impl AsRef<str>) -> Cell {
    Cell::new(s.as_ref()).fg(TableColor::DarkGrey)
}

pub fn td_port(s: impl AsRef<str>) -> Cell {
    Cell::new(s.as_ref())
        .fg(TableColor::White)
        .add_attribute(Attribute::Bold)
}

pub fn td_svc(s: impl AsRef<str>) -> Cell {
    Cell::new(s.as_ref()).fg(TableColor::Grey)
}
