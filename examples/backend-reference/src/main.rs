use std::net::SocketAddr;

use rustauth_example_backend_reference::server::build_router;
use rustauth_example_backend_reference::{AppConfig, AuthStack};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let config = AppConfig::from_env()?;
    let addr: SocketAddr = config.socket_addr()?;
    let stack = AuthStack::from_config(config.clone()).await?;
    let endpoint_count = stack.auth.endpoint_registry().len();
    let app = build_router(stack)?;

    info!(%addr, endpoints = endpoint_count, "RustAuth backend reference listening");
    info!("Auth API: http://{addr}{}", config.auth_base_path);
    info!("Catalog: http://{addr}/reference/groups");
    info!("OpenAPI: http://{addr}/reference/openapi.json");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
