use serde::Deserialize;

use crate::{
    SimpleOAuthProvider, UserInfoProvider,
    types::{TokenAuthMethod, UserInfo},
};

#[derive(Debug, Clone)]
pub struct Facebook;

/// User info returned from Facebook Graph API
#[derive(Debug, Deserialize)]
struct FacebookUserInfo {
    id: String,
    name: Option<String>,
    email: Option<String>,
    picture: Option<FacebookPicture>,
}

#[derive(Debug, Deserialize)]
struct FacebookPicture {
    data: Option<FacebookPictureData>,
}

#[derive(Debug, Deserialize)]
struct FacebookPictureData {
    url: Option<String>,
}

impl SimpleOAuthProvider for Facebook {
    fn authorize_url(&self) -> &str {
        "https://www.facebook.com/dialog/oauth"
    }

    fn token_url(&self) -> &str {
        "https://graph.facebook.com/oauth/access_token"
    }

    fn default_scopes(&self) -> &'static [&'static str] {
        &["public_profile"]
    }

    fn token_auth_method(&self) -> TokenAuthMethod {
        TokenAuthMethod::RequestBody
    }
}

impl UserInfoProvider for Facebook {
    fn user_info_url(&self) -> &str {
        "https://graph.facebook.com/me?fields=id,name,email,picture"
    }

    fn extract_user_info(&self, val: serde_json::Value) -> Result<UserInfo, serde_json::Error> {
        let user_info: FacebookUserInfo = serde_json::from_value(val)?;
        let avatar_url = user_info
            .picture
            .and_then(|picture| picture.data)
            .and_then(|data| data.url);

        Ok(UserInfo {
            id: user_info.id,
            name: user_info.name,
            email: user_info.email,
            avatar_url,
            ..Default::default()
        })
    }
}
