//! Axum integration for OpenAuth.

mod error;
mod options;
mod request;
mod response;
mod router;

pub use error::OpenAuthAxumError;
pub use options::OpenAuthAxumOptions;
pub use router::{
    handle, handle_ref, handle_ref_with_options, handle_with_options, router, router_with_options,
    routes, routes_with_options, OpenAuthAxumExt,
};
