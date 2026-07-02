use std::{fmt::Debug, sync::Arc};

use crate::types::UserInfo;

/// Trait for all OAuth providers
pub trait SimpleOAuthProvider: Debug + Send + Sync {
    /// The authorization endpoint of the provider
    fn authorize_url(&self) -> &str;
    /// The token endpoint of the provider
    fn token_url(&self) -> &str;
    /// The URL to fetch the user info from the provider
    fn user_info_url(&self) -> &str;
    /// Minimum scopes needed to get basic profile info (id, name, username). Email is not included
    /// by default - the user can specify that by passing
    /// in custom scopes when calling `client.authorize_url()`
    fn default_scopes(&self) -> &'static [&'static str];
    /// Extract the user data from the provider's user response
    fn extract_user_info(&self, val: serde_json::Value) -> Result<UserInfo, serde_json::Error>;
    /// Additional headers to send when making requests to the provider
    fn additional_headers(&self) -> Vec<(String, String)> {
        vec![]
    }
}

impl<T> SimpleOAuthProvider for Box<T>
where
    T: SimpleOAuthProvider + ?Sized,
{
    fn authorize_url(&self) -> &str {
        (**self).authorize_url()
    }
    fn token_url(&self) -> &str {
        (**self).token_url()
    }
    fn user_info_url(&self) -> &str {
        (**self).user_info_url()
    }
    fn default_scopes(&self) -> &'static [&'static str] {
        (**self).default_scopes()
    }
    fn extract_user_info(&self, val: serde_json::Value) -> Result<UserInfo, serde_json::Error> {
        (**self).extract_user_info(val)
    }
    fn additional_headers(&self) -> Vec<(String, String)> {
        (**self).additional_headers()
    }
}

impl<T> SimpleOAuthProvider for Arc<T>
where
    T: SimpleOAuthProvider + ?Sized,
{
    fn authorize_url(&self) -> &str {
        (**self).authorize_url()
    }
    fn token_url(&self) -> &str {
        (**self).token_url()
    }
    fn user_info_url(&self) -> &str {
        (**self).user_info_url()
    }
    fn default_scopes(&self) -> &'static [&'static str] {
        (**self).default_scopes()
    }
    fn extract_user_info(&self, val: serde_json::Value) -> Result<UserInfo, serde_json::Error> {
        (**self).extract_user_info(val)
    }
    fn additional_headers(&self) -> Vec<(String, String)> {
        (**self).additional_headers()
    }
}
