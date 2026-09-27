//! Library support for the `ckb-idl` command-line interface.
//!
//! The initial public surface is limited to command parsing and the stable
//! error contract. Binding, manifest, and filesystem implementations are added
//! in their dedicated implementation phases.

pub mod bundle;
pub mod cli;
pub mod error;
pub mod hash;
pub mod idl;
pub mod manifest;
pub mod trailer;
