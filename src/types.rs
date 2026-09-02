use std::fmt::Debug;

use serde::{Deserialize, Serialize};

/// Redacted field for debug outputs
const REDACTED: &str = "[redacted]";

/// Type of the internal oauth2 client
pub(crate) type OAuthClient = oauth2::Client<
    oauth2::basic::BasicErrorResponse,
    OAuthTokenResponse,
    oauth2::basic::BasicTokenIntrospectionResponse,
    oauth2::StandardRevocableToken,
    oauth2::basic::BasicRevocationErrorResponse,
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointMaybeSet,
    oauth2::EndpointSet,
>;

/// Type of the internal oauth2 token response
pub(crate) type OAuthTokenResponse =
    oauth2::StandardTokenResponse<OidcExtraTokenFields, oauth2::basic::BasicTokenType>;

/// Struct to extract the ID token if it exists
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct OidcExtraTokenFields {
    pub id_token: Option<String>,
}
impl oauth2::ExtraTokenFields for OidcExtraTokenFields {}

/// The token auth method (basic auth or request body)
pub type TokenAuthMethod = oauth2::AuthType;

/// The type of token to revoke (refresh or access)
pub enum RevokeTokenType {
    Refresh,
    Access,
}

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

/// Normalized user info returned by the OAuth provider
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
    /// Access token
    pub access_token: String,
    /// Refresh token
    pub refresh_token: Option<String>,
    /// ID token ⚠️ The ID token is not validated by this crate. You must manually validate the token.
    pub id_token: Option<String>,
    /// The valid duration of the access token
    pub expires_in: Option<std::time::Duration>,
}
impl Debug for StandardTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandardTokenResponse")
            .field("access_token", &REDACTED)
            .field("refresh_token", &REDACTED)
            .field("id_token", &REDACTED)
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
impl<S> From<(S, S)> for OAuthCredentials
where
    S: Into<String>,
{
    fn from((id, secret): (S, S)) -> Self {
        Self::new(id, secret)
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
    pub revocation_endpoint: Option<String>,
}

/// Standard OIDC user info shape
#[derive(Debug, Deserialize)]
pub(crate) struct OidcUserInfo {
    pub sub: String,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub picture: Option<String>,
    pub groups: Option<Vec<String>>,
}
