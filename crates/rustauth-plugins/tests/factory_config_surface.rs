//! Config surface tests: struct literal, builder, and `Options::new()` shortcuts.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use rustauth_core::error::RustAuthError;
use rustauth_core::plugin::AuthPlugin;
use rustauth_plugins::bearer::{bearer, BearerOptions, BearerOptionsBuilder};
use rustauth_plugins::captcha::{captcha, CaptchaOptions, CaptchaOptionsBuilder, CaptchaProvider};
use rustauth_plugins::custom_session::{
    custom_session, CustomSessionContext, CustomSessionInput, CustomSessionOptions,
};
use rustauth_plugins::email_otp::{
    email_otp, EmailOtpOptions, EmailOtpOptionsBuilder, EmailOtpPayload, SendEmailOtp,
};
use rustauth_plugins::jwt::{jwt, JwtOptions, JwtOptionsBuilder};
use rustauth_plugins::multi_session::{
    multi_session, MultiSessionOptions, MultiSessionOptionsBuilder,
};
use serde_json::json;

struct StubSender;

impl SendEmailOtp for StubSender {
    fn send_email_otp(
        &self,
        _payload: EmailOtpPayload,
        _request: Option<&http::Request<Vec<u8>>>,
    ) -> rustauth_core::outbound::OutboundSendFuture {
        Box::pin(async { Ok(()) })
    }
}

fn assert_plugin_id(plugin: &AuthPlugin, expected: &str) {
    assert_eq!(plugin.id, expected);
}

#[test]
fn bearer_from_struct_literal() {
    let plugin = bearer(BearerOptions {
        require_signature: true,
    });
    assert_plugin_id(&plugin, "bearer");
}

#[test]
fn bearer_from_builder() {
    let plugin = bearer(
        BearerOptionsBuilder::default()
            .require_signature(true)
            .build(),
    );
    assert_plugin_id(&plugin, "bearer");
}

#[test]
fn multi_session_from_struct_literal() {
    let plugin = multi_session(MultiSessionOptions {
        maximum_sessions: 3,
    });
    assert_plugin_id(&plugin, "multi-session");
}

#[test]
fn multi_session_from_builder() {
    let plugin = multi_session(
        MultiSessionOptionsBuilder::default()
            .maximum_sessions(3)
            .build(),
    );
    assert_plugin_id(&plugin, "multi-session");
}

#[test]
fn email_otp_from_struct_literal() {
    let plugin = email_otp(EmailOtpOptions {
        sender: Some(Arc::new(StubSender)),
        ..EmailOtpOptions::default()
    })
    .expect("valid email otp config");
    assert_plugin_id(&plugin, "email-otp");
}

#[test]
fn email_otp_from_new() {
    let plugin =
        email_otp(EmailOtpOptions::new(Arc::new(StubSender))).expect("valid email otp config");
    assert_plugin_id(&plugin, "email-otp");
}

#[test]
fn email_otp_from_builder() {
    let plugin = email_otp(
        EmailOtpOptionsBuilder::default()
            .sender(Arc::new(StubSender))
            .build()
            .expect("valid builder"),
    )
    .expect("valid email otp config");
    assert_plugin_id(&plugin, "email-otp");
}

#[test]
fn email_otp_missing_sender_fails_at_factory() {
    assert!(matches!(
        email_otp(EmailOtpOptions::default()),
        Err(RustAuthError::InvalidConfig(_))
    ));
}

#[test]
fn captcha_from_struct_literal() {
    let plugin =
        captcha(CaptchaOptions::cloudflare_turnstile("test-secret")).expect("valid captcha config");
    assert_plugin_id(&plugin, "captcha");
}

#[test]
fn captcha_from_builder() {
    let plugin = captcha(
        CaptchaOptionsBuilder::default()
            .provider(CaptchaProvider::CloudflareTurnstile)
            .secret_key("test-secret")
            .build()
            .expect("valid builder"),
    )
    .expect("valid captcha config");
    assert_plugin_id(&plugin, "captcha");
}

#[test]
fn jwt_from_struct_literal() {
    let plugin = jwt(JwtOptions {
        disable_setting_jwt_header: true,
        ..JwtOptions::default()
    })
    .expect("valid jwt config");
    assert_plugin_id(&plugin, "jwt");
}

#[test]
fn jwt_from_builder() {
    let plugin = jwt(JwtOptionsBuilder::default()
        .disable_setting_jwt_header(true)
        .build()
        .expect("valid builder"))
    .expect("valid jwt config");
    assert_plugin_id(&plugin, "jwt");
}

#[test]
fn custom_session_from_default_options_literal() {
    let plugin = custom_session(
        CustomSessionOptions::default(),
        |input: CustomSessionInput, _context: CustomSessionContext<'_>| {
            Box::pin(async move { Ok(input.session) })
        },
    );
    assert_plugin_id(&plugin, "custom-session");
}

#[test]
fn custom_session_handler_can_return_custom_shape() {
    let plugin = custom_session(CustomSessionOptions::default(), |_input, _context| {
        Box::pin(async { Ok(json!({ "ok": true })) })
    });
    assert_plugin_id(&plugin, "custom-session");
}
