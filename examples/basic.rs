use simple_oauth::{SimpleOAuthClient, types::OAuthCredentials};

#[tokio::main]
pub async fn main() {
    // Your server's callback URL
    let callback_url = "http://myserver/auth/github/callback";

    let oauth_client = SimpleOAuthClient::builder()
        .provider(simple_oauth::common::GitHub)
        .credentials(OAuthCredentials::new("client-id", "client-secret"))
        .redirect_url(callback_url)
        .http_client(&reqwest::Client::new()) // optionally pass in your own Reqwest client
        .build()
        .unwrap();

    // Build the authorization URL to redirect the user
    let auth_url = oauth_client
        .authorize_url()
        .scopes(&["read:user", "user:email"]) // if not provided, will use default limited scopes for basic user info
        .build()
        .unwrap();

    // Save the state and PKCE verifier in cache/session
    let initial_state = auth_url.state;
    let pkce_verifier = auth_url.pkce_verifier;

    // Redirect the user to the authorization URL `auth_url.url`, then in the callback route,
    // extract the `code` and `state` query parameters
    let code = "returned_code";
    let state = "returned_state";

    // Perform token exchange
    let token_response = oauth_client
        .exchange_code()
        .code(code) // use the returned `code` and `state` query parameters
        .state(state)
        .initial_state(&initial_state) // use the saved initial state and PKCE verifier
        .pkce_verifier(pkce_verifier)
        .build()
        .await
        .unwrap();

    // Get basic user info from provider
    let user_info = oauth_client
        .get_user_info(&token_response.access_token)
        .await
        .unwrap();
    let _id = user_info.id;
    let _name = user_info.name;
    let _email = user_info.email;

    // (if needed) refresh the token
    let _new_token_response = oauth_client
        .exchange_refresh_token()
        .refresh_token(token_response.refresh_token.unwrap())
        .build()
        .await
        .unwrap();
}
