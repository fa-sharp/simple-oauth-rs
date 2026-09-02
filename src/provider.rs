use std::{fmt::Debug, sync::Arc};

use crate::types::{OAuthCredentials, TokenAuthMethod, UserInfo};

/// Trait for all OAuth providers
pub trait SimpleOAuthProvider: Debug + Send + Sync {
    /// The authorization endpoint of the provider
    fn authorize_url(&self) -> &str;
    /// The token endpoint of the provider
    fn token_url(&self) -> &str;
    /// The token revocation endpoint of the provider
    fn revoke_url(&self) -> Option<&str> {
        None
    }
    /// Default scopes used when building the provider's authorization URL.
    fn default_scopes(&self) -> &'static [&'static str] {
        &[]
    }
    /// How the OAuth client should authenticate to the provider's token endpoint.
    fn token_auth_method(&self) -> TokenAuthMethod {
        TokenAuthMethod::BasicAuth
    }
}

/// Trait for OAuth providers that support fetching normalized user info.
pub trait UserInfoProvider: SimpleOAuthProvider {
    /// The URL to fetch the user info from the provider
    fn user_info_url(&self) -> &str;
    /// Extract the user data from the provider's user response
    fn extract_user_info(&self, val: serde_json::Value) -> Result<UserInfo, serde_json::Error>;
    /// Additional headers to send when making user info requests to the provider
    fn user_info_headers(&self, _credentials: &OAuthCredentials) -> Vec<(String, String)> {
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
    fn default_scopes(&self) -> &'static [&'static str] {
        (**self).default_scopes()
    }
    fn revoke_url(&self) -> Option<&str> {
        (**self).revoke_url()
    }
    fn token_auth_method(&self) -> TokenAuthMethod {
        (**self).token_auth_method()
    }
}

impl<T> UserInfoProvider for Box<T>
where
    T: UserInfoProvider + ?Sized,
{
    fn user_info_url(&self) -> &str {
        (**self).user_info_url()
    }
    fn extract_user_info(&self, val: serde_json::Value) -> Result<UserInfo, serde_json::Error> {
        (**self).extract_user_info(val)
    }
    fn user_info_headers(&self, credentials: &OAuthCredentials) -> Vec<(String, String)> {
        (**self).user_info_headers(credentials)
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
    fn default_scopes(&self) -> &'static [&'static str] {
        (**self).default_scopes()
    }
    fn revoke_url(&self) -> Option<&str> {
        (**self).revoke_url()
    }
    fn token_auth_method(&self) -> TokenAuthMethod {
        (**self).token_auth_method()
    }
}

impl<T> UserInfoProvider for Arc<T>
where
    T: UserInfoProvider + ?Sized,
{
    fn user_info_url(&self) -> &str {
        (**self).user_info_url()
    }
    fn extract_user_info(&self, val: serde_json::Value) -> Result<UserInfo, serde_json::Error> {
        (**self).extract_user_info(val)
    }
    fn user_info_headers(&self, credentials: &OAuthCredentials) -> Vec<(String, String)> {
        (**self).user_info_headers(credentials)
    }
}
