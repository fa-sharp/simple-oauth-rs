use crate::{
    SimpleOAuthProvider,
    types::{OidcUserInfo, UserInfo},
};

#[derive(Debug, Clone)]
pub struct Google;

impl SimpleOAuthProvider for Google {
    fn default_scopes(&self) -> &'static [&'static str] {
        &["openid", "profile"]
    }

    fn authorize_url(&self) -> &str {
        "https://accounts.google.com/o/oauth2/v2/auth"
    }

    fn token_url(&self) -> &str {
        "https://oauth2.googleapis.com/token"
    }

    fn user_info_url(&self) -> &str {
        "https://openidconnect.googleapis.com/v1/userinfo"
    }

    fn extract_user_info(&self, val: serde_json::Value) -> Result<UserInfo, serde_json::Error> {
        let user_info: OidcUserInfo = serde_json::from_value(val)?;

        Ok(UserInfo {
            id: user_info.sub,
            name: user_info.name,
            username: user_info.preferred_username,
            email: user_info.email,
            email_verified: user_info.email_verified,
            avatar_url: user_info.picture,
            ..Default::default()
        })
    }
}
