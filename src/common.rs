//! Common OAuth providers

mod discord;
mod facebook;
mod github;
mod gitlab;
mod google;
mod microsoft;
mod oidc;
mod twitch;

pub use discord::Discord;
pub use facebook::Facebook;
pub use github::GitHub;
pub use gitlab::GitLab;
pub use google::Google;
pub use microsoft::Microsoft;
pub use oidc::Oidc;
pub use twitch::Twitch;
