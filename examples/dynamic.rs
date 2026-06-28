//! Example of using dynamic dispatch to abstract over multiple OAuth providers

use std::{collections::HashMap, sync::Arc};

use simple_oauth::{
    SimpleOAuthClient, SimpleOAuthProvider,
    common::{Discord, GitHub, Google},
    types::OAuthCredentials,
};

#[derive(Clone)]
struct AppState {
    http_client: reqwest::Client,
    providers: HashMap<&'static str, Arc<dyn SimpleOAuthProvider>>,
}

#[tokio::main]
pub async fn main() {
    let state = AppState {
        http_client: reqwest::Client::new(),
        providers: HashMap::from([
            ("github", Arc::new(GitHub) as Arc<dyn SimpleOAuthProvider>),
            ("google", Arc::new(Google) as Arc<dyn SimpleOAuthProvider>),
            ("discord", Arc::new(Discord) as Arc<dyn SimpleOAuthProvider>),
        ]),
    };

    // In an axum route this would usually come from `Path(provider_name)`.
    let provider_name = "github";
    let callback_url = "http://myserver/callback";

    let Some(provider) = state.providers.get(provider_name).cloned() else {
        eprintln!("unknown provider: {provider_name}");
        return;
    };

    let oauth_client = SimpleOAuthClient::builder()
        .provider(provider)
        .credentials(OAuthCredentials::new(
            "github-client-id",
            "github-client-secret",
        ))
        .http_client(&state.http_client)
        .build()
        .unwrap()
        .clone();

    let auth_url = oauth_client
        .authorize_url()
        .redirect_url(callback_url)
        .build()
        .unwrap();

    // Redirect the user to this URL from your route handler.
    let _redirect_to = auth_url.url;
}
