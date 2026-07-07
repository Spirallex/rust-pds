//! AppView proxy: ES256K service-auth + GET read forwarding to api.bsky.app (XRPC-04).
pub mod client;
pub mod proxy;
pub mod service_auth;

pub use client::{AppViewClient, MockAppViewClient, ReqwestAppViewClient};
pub use proxy::routes;
pub use service_auth::mint_service_auth_jwt;
