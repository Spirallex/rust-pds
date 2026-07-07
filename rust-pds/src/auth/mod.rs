// JWT mint/verify + password hashing live in `stelyph-core` (device-portable).
// Re-exported so `crate::auth::jwt::*` keeps resolving. The axum request
// extractors are server-only and stay here.
pub use stelyph_core::auth::jwt;

pub mod extractor;
