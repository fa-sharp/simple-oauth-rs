use std::fmt::Debug;

use serde::Deserialize;

const REDACTED: &str = "[redacted]";

/// OAuth2 authorization redirect URL, along with the state and PKCE verifier
#[derive(Clone)]
pub struct AuthorizeUrl {
    pub url: oauth2::url::Url,
    pub state: String,
    pub pkce_verifier: String,
}
impl Debug for AuthorizeUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizeUrl")
            .field("url", &REDACTED)
            .field("state", &self.state)
            .field("pkce_verifier", &REDACTED)
            .finish()
    }
}

/// User info returned by the OAuth provider
#[derive(Debug, Default, Clone)]
pub struct UserInfo {
    /// The ID of the user at the OAuth provider
    pub id: String,
    /// The user's display name
    pub name: Option<String>,
    /// The user's username
    pub username: Option<String>,
    /// The user's email. Will likely not be included unless you add the proper email scope for the provider.
    ///
    /// ⚠️ Do not rely on this for identifying the user. Use the `id` and the name of the provider.
    pub email: Option<String>,
    /// Whether the user's email is verified. Not all providers return this in the user info.
    pub email_verified: Option<bool>,
    /// The URL of the user's picture/avatar
    pub avatar_url: Option<String>,
    /// The groups the user is a part of. Only included for certain OIDC providers.
    pub groups: Option<Vec<String>>,
}

/// Standard OAuth2 token response
#[derive(Clone)]
pub struct StandardTokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<std::time::Duration>,
}
impl Debug for StandardTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandardTokenResponse")
            .field("access_token", &REDACTED)
            .field("refresh_token", &REDACTED)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// OAuth2 client ID and secret
#[derive(Clone)]
pub struct OAuthCredentials {
    pub client_id: String,
    pub client_secret: String,
}
impl OAuthCredentials {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }
}
impl Debug for OAuthCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &REDACTED)
            .finish()
    }
}

/// OIDC discovery document
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
}

/// Standard OIDC user info shape
#[derive(Debug, Deserialize)]
pub struct OidcUserInfo {
    pub sub: String,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub picture: Option<String>,
    pub groups: Option<Vec<String>>,
}
