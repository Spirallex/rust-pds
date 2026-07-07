// Identity primitives (did:plc genesis signing, did:web docs) live in
// `stelyph-core`. The server re-exports them so `crate::identity::web::*` and
// `crate::identity::plc::*` keep resolving, and adds the reqwest-based PLC
// network client (which is server-only and kept out of the device core).

pub use stelyph_core::identity::web;

pub mod plc;
pub mod web_resolver;

pub use plc::{register_did_plc, PlcClient, PlcGenesisOpSigned, ReqwestPlcClient};
pub use web::{did_web, did_web_document, DidDocument};
pub use web_resolver::{DidWebResolver, ReqwestDidWebResolver};
