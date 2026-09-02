#![doc = include_str!("../README.md")]

use std::borrow::Cow;

use bon::bon;
use oauth2::{
    Client, CsrfToken, HttpClientError, RequestTokenError, RevocationErrorResponseType,
    StandardErrorResponse, TokenResponse, basic::BasicErrorResponse,
};

pub mod common;
mod provider;
pub mod types;

pub use provider::{SimpleOAuthProvider, UserInfoProvider};

use crate::types::{
    AuthorizeUrl, OAuthClient, OAuthCredentials, OAuthTokenResponse, RevokeTokenType,
    StandardTokenResponse, UserInfo,
};

#[derive(Debug, thiserror::Error)]
pub enum SimpleOAuthError {
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error("invalid url: {0}")]
    ParseUrl(#[from] oauth2::url::ParseError),
    #[error("token exchange error: {0}")]
    TokenExchange(#[from] RequestTokenError<HttpClientError<reqwest::Error>, BasicErrorResponse>),
    #[error("token revocation error: {0}")]
    TokenRevocation(
        #[from]
        RequestTokenError<
            HttpClientError<reqwest::Error>,
            StandardErrorResponse<RevocationErrorResponseType>,
        >,
    ),
    #[error("deserialization error: {0}")]
    Deserialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct SimpleOAuthClient<P> {
    http_client: reqwest::Client,
    oauth_http_client: oauth2_reqwest::ReqwestClient,
    oauth_client: OAuthClient,
    credentials: OAuthCredentials,
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
        let oauth_client = Client::new(oauth2::ClientId::new(credentials.client_id.clone()))
            .set_client_secret(oauth2::ClientSecret::new(credentials.client_secret.clone()))
            .set_redirect_uri(oauth2::RedirectUrl::new(redirect_url)?)
            .set_auth_uri(oauth2::AuthUrl::new(provider.authorize_url().into())?)
            .set_token_uri(oauth2::TokenUrl::new(provider.token_url().into())?)
            .set_auth_type(provider.token_auth_method())
            .set_revocation_url_option(
                provider
                    .revoke_url()
                    .map(|url| oauth2::RevocationUrl::new(url.into()))
                    .transpose()?,
            );

        Ok(Self {
            oauth_http_client: oauth2_reqwest::ReqwestClient::from(http_client.clone()),
            http_client,
            oauth_client,
            credentials,
            provider,
        })
    }

    /// Build the URL to navigate the user to for authorization. **Make sure to save the returned state and
    /// PKCE verifier in a secure location, typically in a server-side cache or session.**
    ///
    /// If scopes are not provided, this will use the provider's default scopes.
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
                    .unwrap_or_else(|| self.provider.default_scopes())
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

        Ok(standard_token_response(token))
    }

    /// Exchange the refresh token for a new access token. Can optionally specify scopes to request.
    #[builder(on(String, into), finish_fn(name = "build"))]
    pub async fn exchange_refresh_token(
        &self,
        #[builder(start_fn)] refresh_token: String,
        scopes: Option<&[&str]>,
    ) -> Result<StandardTokenResponse, SimpleOAuthError> {
        let refresh_token = oauth2::RefreshToken::new(refresh_token);
        let mut refresh_request = self.oauth_client.exchange_refresh_token(&refresh_token);
        if let Some(scopes) = scopes {
            refresh_request = refresh_request
                .add_scopes(scopes.iter().map(|s| oauth2::Scope::new((*s).to_owned())));
        }

        let token = refresh_request
            .request_async(&self.oauth_http_client)
            .await?;

        Ok(standard_token_response(token))
    }

    /// Revoke the given token from the provider. This is a no-op if the provider
    /// has no revocation URL.
    pub async fn revoke_token(
        &self,
        token: impl Into<String>,
        token_type: RevokeTokenType,
    ) -> Result<(), SimpleOAuthError> {
        if self.oauth_client.revocation_url().is_some() {
            let token = match token_type {
                RevokeTokenType::Access => oauth2::StandardRevocableToken::AccessToken(
                    oauth2::AccessToken::new(token.into()),
                ),
                RevokeTokenType::Refresh => oauth2::StandardRevocableToken::RefreshToken(
                    oauth2::RefreshToken::new(token.into()),
                ),
            };
            self.oauth_client
                .revoke_token(token)
                .expect("already checked for revocation URL")
                .request_async(&self.oauth_http_client)
                .await?;
        }

        Ok(())
    }
}

fn standard_token_response(token: OAuthTokenResponse) -> StandardTokenResponse {
    StandardTokenResponse {
        access_token: token.access_token().secret().to_owned(),
        refresh_token: token.refresh_token().map(|s| s.secret().to_owned()),
        expires_in: token.expires_in(),
        id_token: token.extra_fields().id_token.clone(),
    }
}

impl<P> SimpleOAuthClient<P>
where
    P: UserInfoProvider,
{
    /// Retrieve user info from the provider using the access token. This is a convenience
    /// method for providers that support normalized user info (e.g. id, name, email, avatar).
    pub async fn get_user_info(&self, access_token: &str) -> Result<UserInfo, SimpleOAuthError> {
        let mut user_info_request = self
            .http_client
            .get(self.provider.user_info_url())
            .bearer_auth(access_token);
        for (name, val) in self.provider.user_info_headers(&self.credentials) {
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
