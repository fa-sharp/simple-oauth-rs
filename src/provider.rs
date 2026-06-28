use std::fmt::Debug;

use crate::types::UserInfo;

/// Trait for all OAuth providers
pub trait SimpleOAuthProvider: Debug + Send + Sync {
    /// The authorization endpoint of the provider
    fn authorize_url(&self) -> &str;
    /// The token endpoint of the provider
    fn token_url(&self) -> &str;
    /// The URL to fetch the user info from the provider
    fn user_info_url(&self) -> &str;
    /// Minimum scopes needed to get basic profile info (id, name, username).
    /// Email not included by default (user can specify that in custom scopes).
    fn default_scopes(&self) -> &'static [&'static str];
    /// Extract the user data from the provider's user response
    fn extract_user_info(&self, val: serde_json::Value) -> Result<UserInfo, serde_json::Error>;
    /// Additional headers to send when making requests to the provider
    fn addl_request_headers(&self) -> Vec<(String, String)> {
        vec![]
    }
}
