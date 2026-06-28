//! Common OAuth providers

mod discord;
mod github;
mod google;
mod oidc;

pub use discord::Discord;
pub use github::GitHub;
pub use google::Google;
pub use oidc::Oidc;
