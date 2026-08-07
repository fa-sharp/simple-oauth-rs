//! Example of a custom OAuth provider (doesn't support user info)

use simple_oauth::{SimpleOAuthClient, SimpleOAuthProvider};

#[derive(Debug, Clone)]
struct CustomProvider;

impl SimpleOAuthProvider for CustomProvider {
    fn authorize_url(&self) -> &str {
        "https://provider.example/oauth/authorize"
    }
    fn token_url(&self) -> &str {
        "https://provider.example/oauth/token"
    }
    fn default_scopes(&self) -> &'static [&'static str] {
        &[]
    }
}

#[tokio::main]
pub async fn main() {
    let oauth_client = SimpleOAuthClient::builder()
        .provider(CustomProvider)
        .credentials(("client-id", "client-secret"))
        .redirect_url("http://myserver/auth/custom/callback")
        .build()
        .unwrap();

    let auth_url = oauth_client.authorize_url().build().unwrap();

    let _redirect_to = auth_url.url;
}
