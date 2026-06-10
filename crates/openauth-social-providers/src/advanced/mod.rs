//! Low-level provider modules, OAuth request types, and HTTP primitives.
//!
//! Application code should prefer [`crate::providers`] and [`SocialProviderConfig`].

macro_rules! provider {
    ($name:ident) => {
        pub mod $name {
            pub use crate::$name::*;
        }
    };
}

provider!(apple);
provider!(atlassian);
provider!(cognito);
provider!(discord);
provider!(dropbox);
provider!(facebook);
provider!(figma);
provider!(github);
provider!(gitlab);
provider!(google);
provider!(huggingface);
provider!(kakao);
provider!(kick);
provider!(line);
provider!(linear);
provider!(linkedin);
provider!(microsoft_entra_id);
provider!(naver);
provider!(notion);
provider!(paybin);
provider!(paypal);
provider!(polar);
provider!(railway);
provider!(reddit);
provider!(roblox);
provider!(salesforce);
provider!(slack);
provider!(spotify);
provider!(tiktok);
provider!(twitch);
provider!(twitter);
provider!(vercel);
provider!(vk);
provider!(wechat);
provider!(zoom);

pub mod http {
    pub use crate::http::*;
}
