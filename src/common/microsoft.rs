use crate::{
    SimpleOAuthProvider, UserInfoProvider,
    types::{OidcUserInfo, TokenAuthMethod, UserInfo},
};

#[derive(Debug, Clone)]
pub struct Microsoft;

impl SimpleOAuthProvider for Microsoft {
    fn authorize_url(&self) -> &str {
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    }

    fn token_url(&self) -> &str {
        "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    }

    fn default_scopes(&self) -> &'static [&'static str] {
        &["openid", "profile"]
    }

    fn token_auth_method(&self) -> TokenAuthMethod {
        TokenAuthMethod::RequestBody
    }
}

impl UserInfoProvider for Microsoft {
    fn user_info_url(&self) -> &str {
        "https://graph.microsoft.com/oidc/userinfo"
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
