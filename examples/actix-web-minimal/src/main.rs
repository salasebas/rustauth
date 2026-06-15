use std::sync::Arc;

use actix_web::{App, HttpServer};
use rustauth_actix_web::{RustAuthActixWebExt, RustAuthActixWebOptions};
use rustauth_example_actix_web::DEFAULT_BASE_URL;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let auth = Arc::new(
        rustauth_example_actix_web::build_auth()
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?,
    );

    println!("RustAuth Actix Web example listening on {DEFAULT_BASE_URL}");

    HttpServer::new(move || {
        let scope = auth
            .mount_at_base_path(RustAuthActixWebOptions::default())
            .expect("valid RustAuth Actix mount");
        App::new().service(scope)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
