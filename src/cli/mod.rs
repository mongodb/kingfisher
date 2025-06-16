pub mod commands;
pub mod global;

// re‑export the top‑level parser and subcommand enum so main.rs can see them:
pub use global::{CommandLineArgs, GlobalArgs};
