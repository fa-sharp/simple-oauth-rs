use bon::bon;
use oauth2::{
    CsrfToken, HttpClientError, RequestTokenError, TokenResponse,
    basic::{BasicClient, BasicErrorResponse},
};

pub mod common;
mod provider;
pub mod types;

pub use provider::SimpleOAuthProvider;
use subtle::ConstantTimeEq;

use crate::types::{AuthorizeUrl, OAuthCredentials, StandardTokenResponse, UserInfo};

#[derive(Debug, thiserror::Error)]
pub enum SimpleOAuthError {
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error("invalid url: {0}")]
    ParseUrl(#[from] oauth2::url::ParseError),
    #[error("returned state did not match initial state")]
    StateMismatch,
    #[error("token exchange error: {0}")]
    TokenExchange(#[from] RequestTokenError<HttpClientError<reqwest::Error>, BasicErrorResponse>),
    #[error("deserialization error: {0}")]
    Deserialization(#[from] serde_json::Error),
}

pub struct SimpleOAuthClient<'c> {
    http_client: reqwest::Client,
    oauth_client: oauth2_reqwest::ReqwestClient,
    provider: Box<dyn SimpleOAuthProvider>,
    credentials: OAuthCredentials<'c>,
}

#[bon]
impl<'c> SimpleOAuthClient<'c> {
    #[builder]
    pub fn new(
        provider: impl SimpleOAuthProvider + 'static,
        credentials: OAuthCredentials<'c>,
        http_client: Option<&reqwest::Client>,
    ) -> Result<Self, SimpleOAuthError> {
        let http_client = if let Some(client) = http_client {
            client.clone()
        } else {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?
        };

        Ok(Self {
            oauth_client: oauth2_reqwest::ReqwestClient::from(http_client.clone()),
            http_client,
            provider: Box::new(provider),
            credentials,
        })
    }

    /// Build the URL to navigate the user to for authorization. You will need to specify your server's
    /// redirect/callback URL.
    /// **Make sure to save the returned state and PKCE verifier in a secure location, typically
    /// in a server-side cache or session.**
    ///
    /// If scopes are not provided, will use default limited scopes to access basic user info (user ID and name only).
    /// If more info is needed, make sure to specify all needed scopes (e.g. if you need email, make sure to include the relevant scope).
    #[builder(on(String, into), finish_fn(name = "build"))]
    pub fn authorize_url(
        &self,
        redirect_url: String,
        scopes: Option<&[&str]>,
    ) -> Result<AuthorizeUrl, SimpleOAuthError> {
        let credentials = self.credentials.clone();
        let oauth_client =
            BasicClient::new(oauth2::ClientId::new(credentials.client_id.into_owned()))
                .set_client_secret(oauth2::ClientSecret::new(
                    credentials.client_secret.into_owned(),
                ))
                .set_auth_uri(oauth2::AuthUrl::new(self.provider.authorize_url().into())?)
                .set_redirect_uri(oauth2::RedirectUrl::new(redirect_url.into())?);
        let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();
        let (url, state) = oauth_client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(
                scopes
                    .unwrap_or(self.provider.default_scopes())
                    .into_iter()
                    .map(|s| oauth2::Scope::new((*s).to_owned())),
            )
            .set_pkce_challenge(pkce_challenge)
            .url();

        Ok(AuthorizeUrl {
            url,
            state: state.into_secret(),
            pkce_verifier: pkce_verifier.into_secret(),
        })
    }

    /// Exchange the returned code after authorization for an access/refresh token. Along with the
    /// returned code and state, you will need to specify your redirect/callback URL and the
    /// saved PKCE verifier and initial state (the state will be verified using a timing-resistant algorithm).
    #[builder(on(String, into), finish_fn(name = "build"))]
    pub async fn exchange_code(
        &self,
        code: String,
        state: &str,
        initial_state: &str,
        pkce_verifier: String,
        redirect_url: String,
    ) -> Result<StandardTokenResponse, SimpleOAuthError> {
        if state.as_bytes().ct_ne(initial_state.as_bytes()).into() {
            return Err(SimpleOAuthError::StateMismatch);
        }

        let credentials = self.credentials.clone();
        let oauth_client =
            BasicClient::new(oauth2::ClientId::new(credentials.client_id.into_owned()))
                .set_client_secret(oauth2::ClientSecret::new(
                    credentials.client_secret.into_owned(),
                ))
                .set_redirect_uri(oauth2::RedirectUrl::new(redirect_url.into())?)
                .set_token_uri(oauth2::TokenUrl::new(self.provider.token_url().into())?);
        let token = oauth_client
            .exchange_code(oauth2::AuthorizationCode::new(code))
            .set_pkce_verifier(oauth2::PkceCodeVerifier::new(pkce_verifier))
            .request_async(&self.oauth_client)
            .await?;

        Ok(StandardTokenResponse {
            access_token: token.access_token().secret().to_owned(),
            refresh_token: token.refresh_token().map(|s| s.secret().to_owned()),
            expires_in: token.expires_in(),
        })
    }

    /// Exchange the refresh token for a new access token
    #[builder(on(String, into), finish_fn(name = "build"))]
    pub async fn exchange_refresh_token(
        &self,
        refresh_token: String,
    ) -> Result<StandardTokenResponse, SimpleOAuthError> {
        let credentials = self.credentials.clone();
        let oauth_client =
            BasicClient::new(oauth2::ClientId::new(credentials.client_id.into_owned()))
                .set_client_secret(oauth2::ClientSecret::new(
                    credentials.client_secret.into_owned(),
                ))
                .set_token_uri(oauth2::TokenUrl::new(self.provider.token_url().into())?);
        let token = oauth_client
            .exchange_refresh_token(&oauth2::RefreshToken::new(refresh_token))
            .request_async(&self.oauth_client)
            .await?;

        Ok(StandardTokenResponse {
            access_token: token.access_token().secret().to_owned(),
            refresh_token: token.refresh_token().map(|s| s.secret().to_owned()),
            expires_in: token.expires_in(),
        })
    }

    /// Retrieve user info from the provider using the access token. This is a convenience
    /// method for when you only need basic info (e.g. id, name, email, avatar).
    pub async fn get_user_info(&self, access_token: &str) -> Result<UserInfo, SimpleOAuthError> {
        let mut user_info_request = self
            .http_client
            .get(self.provider.user_info_url())
            .bearer_auth(access_token);
        for (name, val) in self.provider.addl_request_headers() {
            user_info_request = user_info_request.header(name, val);
        }

        let user_info_val = user_info_request
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let user_info = self.provider.extract_user_info(user_info_val)?;

        Ok(user_info)
    }
}
