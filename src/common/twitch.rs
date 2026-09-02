use serde::{Deserialize, de::Error};

use crate::{
    SimpleOAuthProvider, UserInfoProvider,
    types::{OAuthCredentials, TokenAuthMethod, UserInfo},
};

#[derive(Debug, Clone)]
pub struct Twitch;

/// User info returned from Twitch Helix API
#[derive(Debug, Deserialize)]
struct TwitchUsers {
    data: Vec<TwitchUserInfo>,
}

#[derive(Debug, Deserialize)]
struct TwitchUserInfo {
    id: String,
    login: String,
    display_name: Option<String>,
    email: Option<String>,
    profile_image_url: Option<String>,
}

impl SimpleOAuthProvider for Twitch {
    fn authorize_url(&self) -> &str {
        "https://id.twitch.tv/oauth2/authorize"
    }

    fn token_url(&self) -> &str {
        "https://id.twitch.tv/oauth2/token"
    }

    fn revoke_url(&self) -> Option<&str> {
        Some("https://id.twitch.tv/oauth2/revoke")
    }

    fn token_auth_method(&self) -> TokenAuthMethod {
        TokenAuthMethod::RequestBody
    }
}

impl UserInfoProvider for Twitch {
    fn user_info_url(&self) -> &str {
        "https://api.twitch.tv/helix/users"
    }

    fn user_info_headers(&self, credentials: &OAuthCredentials) -> Vec<(String, String)> {
        vec![("Client-Id".into(), credentials.client_id.clone())]
    }

    fn extract_user_info(&self, val: serde_json::Value) -> Result<UserInfo, serde_json::Error> {
        let users: TwitchUsers = serde_json::from_value(val)?;
        let user_info = users
            .data
            .into_iter()
            .next()
            .ok_or_else(|| serde_json::Error::custom("missing Twitch user info"))?;

        Ok(UserInfo {
            id: user_info.id,
            name: user_info.display_name,
            username: Some(user_info.login),
            email: user_info.email,
            avatar_url: user_info.profile_image_url,
            ..Default::default()
        })
    }
}
