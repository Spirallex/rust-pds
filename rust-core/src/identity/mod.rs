pub mod plc;
pub mod service;
pub mod web;

pub use plc::{register_did_plc, PlcClient, PlcGenesisOpSigned};
pub use web::{did_web, did_web_document, DidDocument};
