//! bin-inator: a small desktop tool that turns arbitrary files into `.bin`.
//!
//! The conversion engine lives in [`core`] and has no GUI dependencies.
//! The egui desktop app lives in [`gui`].

pub mod core;
pub mod gui;
