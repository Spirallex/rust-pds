//! Server-side `plc` module: re-exports the device-portable PLC signing logic
//! from `stelyph-core` and adds the reqwest-based network client that submits
//! genesis operations to plc.directory. The network client is intentionally NOT
//! in the core crate so the iOS build stays reqwest-free.

pub use stelyph_core::identity::plc::*;

mod reqwest_client;
pub use reqwest_client::ReqwestPlcClient;
