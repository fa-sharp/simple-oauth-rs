use crate::{
    SimpleOAuthProvider, UserInfoProvider,
    types::{OidcUserInfo, UserInfo},
};

#[derive(Debug, Clone)]
pub struct GitLab;

impl SimpleOAuthProvider for GitLab {
    fn authorize_url(&self) -> &str {
        "https://gitlab.com/oauth/authorize"
    }

    fn token_url(&self) -> &str {
        "https://gitlab.com/oauth/token"
    }

    fn revoke_url(&self) -> Option<&str> {
        Some("https://gitlab.com/oauth/revoke")
    }

    fn default_scopes(&self) -> &'static [&'static str] {
        &["openid", "profile"]
    }
}

impl UserInfoProvider for GitLab {
    fn user_info_url(&self) -> &str {
        "https://gitlab.com/oauth/userinfo"
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
            groups: user_info.groups,
        })
    }
}
