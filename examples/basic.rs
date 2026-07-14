use simple_oauth::SimpleOAuthClient;

#[tokio::main]
pub async fn main() {
    // Your server's callback URL
    let callback_url = "http://myserver/auth/github/callback";

    let oauth_client = SimpleOAuthClient::builder()
        .provider(simple_oauth::common::GitHub)
        .credentials(("client-id", "client-secret"))
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

    // Save the state and PKCE verifier in a secure, server-side cache/session
    let initial_state = auth_url.state;
    let pkce_verifier = auth_url.pkce_verifier;

    // Redirect the user to the authorization URL `auth_url.url`, then in the callback route,
    // extract the `code` and `state` query parameters
    let _redirect_url = auth_url.url;
    let returned_code = "returned_code";
    let returned_state = "returned_state";

    // If the initial state was stored in session, verify the returned state against initial state
    if returned_state != initial_state {
        panic!("State doesn't match");
    }

    // Perform token exchange
    let token_response = oauth_client
        .exchange_code()
        .code(returned_code) // use the returned `code` query parameter
        .pkce_verifier(pkce_verifier)
        .build()
        .await
        .unwrap();

    // Get basic user info from provider (or perform your own API request with the token)
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
