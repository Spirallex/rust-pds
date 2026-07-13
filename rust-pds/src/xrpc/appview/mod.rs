//! Generalized XRPC service proxy: ES256K service-auth + `atproto-proxy`
//! header routing (AppView default) for GET and POST.
pub mod client;
pub mod proxy;
pub mod resolver;
pub mod service_auth;

pub use client::{AppViewClient, MockAppViewClient, ReqwestAppViewClient};
pub use resolver::{MockServiceDidResolver, ReqwestServiceDidResolver, ServiceDidResolver};
pub use service_auth::mint_service_auth_jwt;
