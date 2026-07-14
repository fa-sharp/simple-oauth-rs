#![doc = include_str!("../README.md")]

use std::borrow::Cow;

use bon::bon;
use oauth2::{
    CsrfToken, EndpointNotSet, EndpointSet, HttpClientError, RequestTokenError, TokenResponse,
    basic::{BasicClient, BasicErrorResponse},
};

pub mod common;
mod provider;
pub mod types;

pub use provider::SimpleOAuthProvider;

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

#[derive(Debug, Clone)]
pub struct SimpleOAuthClient<P> {
    http_client: reqwest::Client,
    oauth_http_client: oauth2_reqwest::ReqwestClient,
    oauth_client:
        BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>,
    provider: P,
}

#[bon]
impl<P> SimpleOAuthClient<P>
where
    P: SimpleOAuthProvider,
{
    #[builder(on(String, into))]
    #[builder(on(OAuthCredentials, into))]
    pub fn new(
        provider: P,
        credentials: OAuthCredentials,
        redirect_url: String,
        http_client: Option<&reqwest::Client>,
    ) -> Result<Self, SimpleOAuthError> {
        let http_client = if let Some(client) = http_client {
            client.to_owned()
        } else {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?
        };
        let oauth_client = BasicClient::new(oauth2::ClientId::new(credentials.client_id))
            .set_client_secret(oauth2::ClientSecret::new(credentials.client_secret))
            .set_redirect_uri(oauth2::RedirectUrl::new(redirect_url)?)
            .set_auth_uri(oauth2::AuthUrl::new(provider.authorize_url().into())?)
            .set_token_uri(oauth2::TokenUrl::new(provider.token_url().into())?);

        Ok(Self {
            oauth_http_client: oauth2_reqwest::ReqwestClient::from(http_client.clone()),
            http_client,
            oauth_client,
            provider,
        })
    }

    /// Build the URL to navigate the user to for authorization. **Make sure to save the returned state and
    /// PKCE verifier in a secure location, typically in a server-side cache or session.**
    ///
    /// If scopes are not provided, will use default limited scopes for the provider to access basic user info (user ID and name only).
    /// If more access is needed (e.g. email), make sure to specify all required scopes.
    ///
    /// You can optionally override the redirect URL, but make sure to pass in the exact same URL when calling
    /// `exchange_code()`.
    #[builder(on(String, into), finish_fn(name = "build"))]
    pub fn authorize_url(
        &self,
        redirect_url: Option<String>,
        scopes: Option<&[&str]>,
    ) -> Result<AuthorizeUrl, SimpleOAuthError> {
        let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();
        let mut auth_request = self
            .oauth_client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            .add_scopes(
                scopes
                    .unwrap_or(self.provider.default_scopes())
                    .iter()
                    .map(|s| oauth2::Scope::new((*s).to_owned())),
            );
        if let Some(redirect_url) = redirect_url {
            auth_request =
                auth_request.set_redirect_uri(Cow::Owned(oauth2::RedirectUrl::new(redirect_url)?));
        }
        let (url, state) = auth_request.url();

        Ok(AuthorizeUrl {
            url,
            state: state.into_secret(),
            pkce_verifier: pkce_verifier.into_secret(),
        })
    }

    /// Exchange the returned code after authorization for an access/refresh token. You will need to provide
    /// the returned code and the saved PKCE verifier. Make sure to first verify the returned state if applicable.
    ///
    /// If you set the redirect URL when calling `authorize_url()`, you must set the same URL here as well.
    #[builder(on(String, into), finish_fn(name = "build"))]
    pub async fn exchange_code(
        &self,
        code: String,
        pkce_verifier: String,
        redirect_url: Option<String>,
    ) -> Result<StandardTokenResponse, SimpleOAuthError> {
        let mut token_request = self
            .oauth_client
            .exchange_code(oauth2::AuthorizationCode::new(code))
            .set_pkce_verifier(oauth2::PkceCodeVerifier::new(pkce_verifier));
        if let Some(redirect_url) = redirect_url {
            token_request =
                token_request.set_redirect_uri(Cow::Owned(oauth2::RedirectUrl::new(redirect_url)?));
        }
        let token = token_request.request_async(&self.oauth_http_client).await?;

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
        let token = self
            .oauth_client
            .exchange_refresh_token(&oauth2::RefreshToken::new(refresh_token))
            .request_async(&self.oauth_http_client)
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
        for (name, val) in self.provider.additional_headers() {
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
