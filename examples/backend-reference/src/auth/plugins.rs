//! Official plugin wiring: every production-ready plugin enabled with
//! development-friendly defaults and representative configuration.

use std::future;
use std::sync::Arc;

use http::Request;
use rustauth::oauth_provider::{oauth_provider, McpOptions, OAuthProviderOptions};
use rustauth::passkey::{passkey, PasskeyOptions};
use rustauth::plugin::AuthPlugin;
use rustauth::plugins::additional_fields::AdditionalField;
use rustauth::plugins::api_key::{
    ApiKeyConfiguration, ApiKeyExpirationOptions, ApiKeyOptions, ApiKeyRateLimitOptions,
    ApiKeyReference, StartingCharactersConfig,
};
use rustauth::plugins::additional_fields::additional_fields;
use rustauth::plugins::captcha::{captcha, CaptchaOptions};
use rustauth::plugins::custom_session::custom_session;
use rustauth::plugins::email_otp::{EmailOtpPayload, SendEmailOtp};
use rustauth::plugins::generic_oauth::{generic_oauth, GenericOAuthOptions};
use rustauth::plugins::last_login_method::last_login_method;
use rustauth::plugins::oauth_proxy::oauth_proxy;
use rustauth::plugins::one_time_token::{one_time_token, StoreToken};
use rustauth::plugins::organization::{
    DynamicAccessControlOptions, OrganizationOptions, TeamOptions,
};
use rustauth::plugins::prelude::*;
use rustauth::plugins::two_factor::{BackupCodeOptions, TotpOptions};
use rustauth::scim::{scim, ScimOptions};
use rustauth::sso::{sso, SsoOptions};
use rustauth::stripe::{stripe, OrganizationStripeOptions, StripeOptions, SubscriptionOptions};
use rustauth_core::db::DbFieldType;
use rustauth_core::outbound::OutboundSendFuture;
use time::Duration;

use crate::error::{AppError, AppResult};

/// Plugin identifiers enabled by this reference stack.
///
/// Keep in sync with `[plugins].enabled` in `rustauth.toml`.
/// `access` is a helper library (roles/statements), not an HTTP plugin — see
/// [`crate::auth::access`] and `/reference/access`.
pub const ENABLED_PLUGIN_IDS: &[&str] = &[
    "additional-fields",
    "admin",
    "anonymous",
    "api-key",
    "bearer",
    "captcha",
    "custom-session",
    "device-authorization",
    "email-otp",
    "generic-oauth",
    "have-i-been-pwned",
    "jwt",
    "last-login-method",
    "magic-link",
    "oauth-provider",
    "multi-session",
    "oauth-proxy",
    "one-tap",
    "one-time-token",
    "open-api",
    "organization",
    "passkey",
    "phone-number",
    "scim",
    "siwe",
    "sso",
    "stripe",
    "two-factor",
    "username",
];

struct ReferenceEmailOtpSender;

impl SendEmailOtp for ReferenceEmailOtpSender {
    fn send_email_otp(
        &self,
        _payload: EmailOtpPayload,
        _request: Option<&Request<Vec<u8>>>,
    ) -> OutboundSendFuture {
        Box::pin(async { Ok(()) })
    }
}

/// Build the full plugin list used by the reference application.
pub fn all_plugins() -> AppResult<Vec<AuthPlugin>> {
    Ok(vec![
        additional_fields(
            AdditionalFieldsOptions::new()
                .user_field(
                    "locale",
                    AdditionalField::new(DbFieldType::String).optional(),
                )
                .session_field(
                    "device_label",
                    AdditionalField::new(DbFieldType::String).optional(),
                ),
        ),
        admin(AdminOptions {
            default_role: "member".to_owned(),
            admin_roles: vec!["admin".to_owned()],
            impersonation_session_duration: Duration::seconds(30 * 60),
            ..AdminOptions::default()
        })?,
        anonymous(
            AnonymousOptions::default().email_domain_name("guest.rustauth.local"),
        ),
        api_key(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    reference: ApiKeyReference::User,
                    rate_limit: ApiKeyRateLimitOptions {
                        enabled: true,
                        time_window: Duration::days(1),
                        max_requests: 100,
                    },
                    key_expiration: ApiKeyExpirationOptions {
                        default_expires_in: Some(Duration::days(90)),
                        min_expires_in_days: 7,
                        max_expires_in_days: 365,
                        ..ApiKeyExpirationOptions::default()
                    },
                    starting_characters: StartingCharactersConfig {
                        should_store: true,
                        characters_length: 8,
                    },
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
        bearer(BearerOptions {
            require_signature: false,
            ..BearerOptions::default()
        }),
        custom_session(CustomSessionOptions::default(), |input, _context| {
            Box::pin(future::ready(Ok(input.session)))
        }),
        device_authorization(DeviceAuthorizationOptions {
            expires_in: Duration::minutes(15),
            interval: Duration::seconds(5),
            device_code_length: 32,
            user_code_length: 8,
            ..DeviceAuthorizationOptions::default()
        })?,
        email_otp(EmailOtpOptions {
            otp_length: 6,
            expires_in: Duration::minutes(5),
            allowed_attempts: 5,
            sender: Some(Arc::new(ReferenceEmailOtpSender)),
            ..EmailOtpOptions::default()
        })?,
        have_i_been_pwned(HaveIBeenPwnedOptions {
            enabled: false,
            ..HaveIBeenPwnedOptions::default()
        }),
        jwt(JwtOptions {
            disable_setting_jwt_header: false,
            ..JwtOptions::default()
        })?,
        last_login_method(LastLoginMethodOptions {
            max_age: Some(Duration::seconds(60 * 60 * 24 * 365)),
            ..LastLoginMethodOptions::default()
        }),
        magic_link_dev_log(),
        oauth_provider(OAuthProviderOptions {
            login_page: "/reference/login".to_owned(),
            consent_page: "/reference/consent".to_owned(),
            allow_dynamic_client_registration: true,
            mcp: Some(McpOptions::default()),
            ..OAuthProviderOptions::default()
        })
        .map_err(|error| AppError::Config(error.to_string()))?,
        multi_session(MultiSessionOptions {
            maximum_sessions: 10,
            ..MultiSessionOptions::default()
        }),
        oauth_proxy(
            OAuthProxyOptions::new()
                .max_age(Duration::seconds(120))
                .current_url("http://127.0.0.1:3000"),
        ),
        one_tap(OneTapOptions {
            disable_signup: false,
            ..OneTapOptions::default()
        }),
        one_time_token(OneTimeTokenOptions {
            expires_in: Duration::minutes(5),
            disable_client_request: false,
            store_token: StoreToken::Plain,
            ..OneTimeTokenOptions::default()
        }),
        open_api(OpenApiOptions {
            disable_default_reference: false,
            ..OpenApiOptions::default()
        }),
        organization(
            OrganizationOptions::builder()
                .allow_user_to_create_organization(true)
                .invitation_expires_in(Duration::days(7))
                .teams(TeamOptions {
                    enabled: true,
                    create_default_team: true,
                    maximum_teams: Some(20),
                    ..TeamOptions::default()
                })
                .dynamic_access_control(DynamicAccessControlOptions {
                    enabled: true,
                    maximum_roles_per_organization: Some(25),
                })
                .build(),
        ),
        phone_number(PhoneNumberOptions {
            otp_length: 6,
            expires_in: Duration::minutes(5),
            allowed_attempts: 3,
            require_verification: true,
            send_otp: Some(Arc::new(|_phone, _otp| Ok(()))),
            ..PhoneNumberOptions::default()
        })?,
        siwe_dev()?,
        two_factor(TwoFactorOptions {
            issuer: Some("RustAuth Reference".to_owned()),
            totp: TotpOptions {
                digits: 6,
                period: Duration::seconds(30),
                ..TotpOptions::default()
            },
            backup_codes: BackupCodeOptions {
                amount: 10,
                length: 10,
                ..BackupCodeOptions::default()
            },
            ..TwoFactorOptions::default()
        }),
        username(UsernameOptions {
            min_username_length: 3,
            max_username_length: 30,
            ..UsernameOptions::default()
        }),
        captcha(
            CaptchaOptions::cloudflare_turnstile("dev-captcha-secret")
                .endpoints(["/reference/captcha-protected"]),
        )?,
        passkey(PasskeyOptions::default()),
        generic_oauth(GenericOAuthOptions::default()),
        sso(SsoOptions::default()),
        scim(ScimOptions::default()),
        stripe(
            StripeOptions::dev()
                .subscription(SubscriptionOptions::enabled(Vec::new()))
                .organization(OrganizationStripeOptions::enabled()),
        )
        .map_err(|error| AppError::Config(error.to_string()))?,
        #[cfg(feature = "i18n")]
        i18n_plugin()?,
    ])
}

#[cfg(feature = "i18n")]
fn i18n_plugin() -> AppResult<AuthPlugin> {
    use rustauth::i18n::{i18n, I18nOptions, LocaleDetectionStrategy};

    i18n(
        I18nOptions::new()
            .locale("en", [("INVALID_EMAIL", "Invalid email")])
            .locale("es", [("INVALID_EMAIL", "Email inválido")])
            .default_locale("en")
            .detection([LocaleDetectionStrategy::Header]),
    )
    .map_err(|error| AppError::Config(error.to_string()))
}
