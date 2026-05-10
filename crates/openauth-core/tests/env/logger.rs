use std::sync::{Arc, Mutex};

use openauth_core::env::logger::{create_logger, should_publish_log, LogLevel, LoggerOptions};

#[test]
fn should_publish_log_follows_level_ordering() {
    assert!(should_publish_log(LogLevel::Debug, LogLevel::Debug));
    assert!(should_publish_log(LogLevel::Debug, LogLevel::Error));
    assert!(!should_publish_log(LogLevel::Info, LogLevel::Debug));
    assert!(should_publish_log(LogLevel::Warn, LogLevel::Error));
    assert!(!should_publish_log(LogLevel::Error, LogLevel::Warn));
}

#[test]
fn logger_does_not_publish_below_configured_level() {
    let entries = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&entries);
    let logger = create_logger(LoggerOptions::new(LogLevel::Warn).with_handler(
        move |level, message, args| {
            captured
                .lock()
                .map(|mut entries| {
                    entries.push((
                        level,
                        message.to_owned(),
                        args.iter().map(|arg| (*arg).to_owned()).collect(),
                    ))
                })
                .ok();
        },
    ));

    logger.info("ignored", &[]);
    logger.warn("published", &["arg"]);

    assert_eq!(
        entries.lock().map(|entries| entries.clone()).ok(),
        Some(vec![(
            LogLevel::Warn,
            "published".to_owned(),
            vec!["arg".to_owned()]
        )])
    );
}

#[test]
fn logger_maps_success_to_info_for_custom_handler() {
    let entries = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&entries);
    let logger = create_logger(LoggerOptions::new(LogLevel::Debug).with_handler(
        move |level, message, _args| {
            captured
                .lock()
                .map(|mut entries| entries.push((level, message.to_owned())))
                .ok();
        },
    ));

    logger.success("created", &[]);

    assert_eq!(
        entries.lock().map(|entries| entries.clone()).ok(),
        Some(vec![(LogLevel::Info, "created".to_owned())])
    );
}

#[test]
fn disabled_logger_does_not_publish() {
    let entries = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&entries);
    let logger = create_logger(
        LoggerOptions::new(LogLevel::Debug)
            .disabled(true)
            .with_handler(move |level, message, _args| {
                captured
                    .lock()
                    .map(|mut entries| entries.push((level, message.to_owned())))
                    .ok();
            }),
    );

    logger.error("ignored", &[]);

    assert_eq!(entries.lock().map(|entries| entries.len()).ok(), Some(0));
}
