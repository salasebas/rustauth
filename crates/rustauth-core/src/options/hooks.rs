//! Global request hooks (parity with Better Auth `hooks` init option).

use std::fmt;
use std::sync::Arc;

use http::Method;

use crate::api::{ApiRequest, ApiResponse};
use crate::context::AuthContext;
use crate::error::RustAuthError;
use crate::plugin::{PluginAfterHook, PluginBeforeHook, PluginHookMatcher};

/// Global before/after hooks applied to every matched endpoint.
#[derive(Clone, Default)]
pub struct GlobalHooksOptions {
    pub before: Option<Arc<dyn GlobalBeforeHook>>,
    pub after: Option<Arc<dyn GlobalAfterHook>>,
}

impl GlobalHooksOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn before<H>(mut self, hook: H) -> Self
    where
        H: GlobalBeforeHook,
    {
        self.before = Some(Arc::new(hook));
        self
    }

    #[must_use]
    pub fn after<H>(mut self, hook: H) -> Self
    where
        H: GlobalAfterHook,
    {
        self.after = Some(Arc::new(hook));
        self
    }
}

impl fmt::Debug for GlobalHooksOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GlobalHooksOptions")
            .field(
                "before",
                &self.before.as_ref().map(|_| "<global-before-hook>"),
            )
            .field("after", &self.after.as_ref().map(|_| "<global-after-hook>"))
            .finish()
    }
}

/// Runs before any endpoint handler (after plugins' onRequest).
pub trait GlobalBeforeHook: Send + Sync + 'static {
    fn before(
        &self,
        context: &AuthContext,
        request: ApiRequest,
        method: &Method,
        path: &str,
    ) -> Result<GlobalHookAction, RustAuthError>;
}

impl<F> GlobalBeforeHook for F
where
    F: Fn(&AuthContext, ApiRequest, &Method, &str) -> Result<GlobalHookAction, RustAuthError>
        + Send
        + Sync
        + 'static,
{
    fn before(
        &self,
        context: &AuthContext,
        request: ApiRequest,
        method: &Method,
        path: &str,
    ) -> Result<GlobalHookAction, RustAuthError> {
        self(context, request, method, path)
    }
}

/// Runs after any endpoint handler (before plugins' onResponse).
pub trait GlobalAfterHook: Send + Sync + 'static {
    fn after(
        &self,
        context: &AuthContext,
        request: &ApiRequest,
        response: ApiResponse,
        method: &Method,
        path: &str,
    ) -> Result<ApiResponse, RustAuthError>;
}

impl<F> GlobalAfterHook for F
where
    F: Fn(
            &AuthContext,
            &ApiRequest,
            ApiResponse,
            &Method,
            &str,
        ) -> Result<ApiResponse, RustAuthError>
        + Send
        + Sync
        + 'static,
{
    fn after(
        &self,
        context: &AuthContext,
        request: &ApiRequest,
        response: ApiResponse,
        method: &Method,
        path: &str,
    ) -> Result<ApiResponse, RustAuthError> {
        self(context, request, response, method, path)
    }
}

/// Action returned by a global before hook.
pub enum GlobalHookAction {
    Continue(ApiRequest),
    Respond(ApiResponse),
}

pub(crate) fn plugin_before_hooks(options: &GlobalHooksOptions) -> Vec<PluginBeforeHook> {
    let Some(hook) = options.before.clone() else {
        return Vec::new();
    };
    vec![PluginBeforeHook {
        matcher: PluginHookMatcher {
            path: "/*".to_owned(),
            method: None,
            operation_id: None,
        },
        handler: Arc::new(move |context, request| {
            let method = request.method().clone();
            let path = request
                .uri()
                .path()
                .trim_start_matches(context.base_path.trim_end_matches('/'))
                .to_owned();
            match hook.before(context, request, &method, &path)? {
                GlobalHookAction::Continue(request) => {
                    Ok(crate::plugin::PluginBeforeHookAction::Continue(request))
                }
                GlobalHookAction::Respond(response) => {
                    Ok(crate::plugin::PluginBeforeHookAction::Respond(response))
                }
            }
        }),
    }]
}

pub(crate) fn plugin_after_hooks(options: &GlobalHooksOptions) -> Vec<PluginAfterHook> {
    let Some(hook) = options.after.clone() else {
        return Vec::new();
    };
    vec![PluginAfterHook {
        matcher: PluginHookMatcher {
            path: "/*".to_owned(),
            method: None,
            operation_id: None,
        },
        handler: Arc::new(move |context, request, response| {
            let method = request.method().clone();
            let path = request
                .uri()
                .path()
                .trim_start_matches(context.base_path.trim_end_matches('/'))
                .to_owned();
            let response = hook.after(context, request, response, &method, &path)?;
            Ok(crate::plugin::PluginAfterHookAction::Continue(response))
        }),
    }]
}

#[cfg(test)]
mod tests {
    use http::Method;

    use crate::api::{ApiRequest, ApiResponse};
    use crate::context::AuthContext;

    use super::*;

    struct TestBeforeHook;
    struct TestAfterHook;

    impl GlobalBeforeHook for TestBeforeHook {
        fn before(
            &self,
            _context: &AuthContext,
            request: ApiRequest,
            _method: &Method,
            _path: &str,
        ) -> Result<GlobalHookAction, RustAuthError> {
            Ok(GlobalHookAction::Continue(request))
        }
    }

    impl GlobalAfterHook for TestAfterHook {
        fn after(
            &self,
            _context: &AuthContext,
            _request: &ApiRequest,
            response: ApiResponse,
            _method: &Method,
            _path: &str,
        ) -> Result<ApiResponse, RustAuthError> {
            Ok(response)
        }
    }

    #[test]
    fn global_hooks_options_supports_fluent_registration() {
        let options = GlobalHooksOptions::new()
            .before(TestBeforeHook)
            .after(TestAfterHook);

        assert!(options.before.is_some());
        assert!(options.after.is_some());
    }
}
