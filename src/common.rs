//! Common OAuth providers

mod discord;
mod github;
mod gitlab;
mod google;
mod oidc;

pub use discord::Discord;
pub use github::GitHub;
pub use gitlab::GitLab;
pub use google::Google;
pub use oidc::Oidc;
