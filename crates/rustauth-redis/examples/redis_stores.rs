use rustauth_redis::RedisStores;

#[tokio::main]
async fn main() -> Result<(), rustauth_core::error::RustAuthError> {
    let stores = RedisStores::connect("redis://127.0.0.1:6379").await?;
    let _options = stores.apply_to_options(rustauth_core::options::RustAuthOptions::default());
    Ok(())
}
