# simple-oauth
Simple server-side OAuth2 login and authorization with the Authorization Code Flow, including common OAuth providers. Built on top of [`oauth2`](https://docs.rs/oauth2/5.0.0/oauth2/) and [`reqwest`](https://docs.rs/reqwest/0.13.4/reqwest/).

## Example

```rust
use simple_oauth::{SimpleOAuthClient, types::OAuthCredentials};

async fn example() {
    let oauth_client = SimpleOAuthClient::builder()
        .provider(simple_oauth::common::GitHub)
        .credentials(OAuthCredentials::new("client-id", "client-secret"))
        .redirect_url("https://myserver/auth/github/callback")
        .build()
        .unwrap();

    // Build the authorization URL to redirect the user
    let auth_url = oauth_client
        .authorize_url()
        .scopes(&["read:user", "user:email"])
        .build()
        .unwrap();

    // Save the state and PKCE verifier in cache/session
    let initial_state = auth_url.state;
    let pkce_verifier = auth_url.pkce_verifier;

    // In the callback route, extract the `code` and `state` query parameters
    let code = "returned_code";
    let state = "returned_state";

    // Perform token exchange
    let token = oauth_client
        .exchange_code()
        .code(code)
        .state(state)
        .initial_state(&initial_state)
        .pkce_verifier(pkce_verifier)
        .build()
        .await
        .unwrap();

    // Get basic user info
    let user = oauth_client.get_user_info(&token.access_token).await.unwrap();
    let _id = user.id;
    let _name = user.name;
}
```
