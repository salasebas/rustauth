use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use openauth_core::error::OpenAuthError;
use time::Duration;

pub type DeviceCodeGeneratorFuture = Pin<Box<dyn Future<Output = String> + Send>>;
pub type AsyncDeviceCodeGenerator = Arc<dyn Fn() -> DeviceCodeGeneratorFuture + Send + Sync>;
pub type ClientValidationFuture = Pin<Box<dyn Future<Output = Result<bool, OpenAuthError>> + Send>>;
pub type ClientValidator = Arc<dyn Fn(String) -> ClientValidationFuture + Send + Sync>;
pub type DeviceAuthRequestFuture = Pin<Box<dyn Future<Output = Result<(), OpenAuthError>> + Send>>;
pub type DeviceAuthRequestHook =
    Arc<dyn Fn(String, Option<String>) -> DeviceAuthRequestFuture + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceAuthorizationOptionsError {
    EmptyDeviceCodeLength,
    EmptyUserCodeLength,
    NonPositiveExpiresIn,
    NonPositiveInterval,
}

impl std::fmt::Display for DeviceAuthorizationOptionsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::EmptyDeviceCodeLength => "device code length must be greater than zero",
            Self::EmptyUserCodeLength => "user code length must be greater than zero",
            Self::NonPositiveExpiresIn => "expires_in must be positive",
            Self::NonPositiveInterval => "interval must be positive",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DeviceAuthorizationOptionsError {}

#[derive(Clone)]
pub struct DeviceAuthorizationOptions {
    pub expires_in: Duration,
    pub interval: Duration,
    pub device_code_length: usize,
    pub user_code_length: usize,
    pub generate_device_code: Option<AsyncDeviceCodeGenerator>,
    pub generate_user_code: Option<AsyncDeviceCodeGenerator>,
    pub validate_client: Option<ClientValidator>,
    pub on_device_auth_request: Option<DeviceAuthRequestHook>,
    pub verification_uri: String,
    pub schema: DeviceAuthorizationSchemaOptions,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceAuthorizationSchemaOptions {
    pub table_name: Option<String>,
    pub fields: DeviceAuthorizationSchemaFields,
}

impl DeviceAuthorizationSchemaOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn table_name(mut self, table_name: impl Into<String>) -> Self {
        self.table_name = Some(table_name.into());
        self
    }

    #[must_use]
    pub fn field_name(
        mut self,
        logical_name: impl Into<String>,
        physical_name: impl Into<String>,
    ) -> Self {
        self.fields.set(logical_name.into(), physical_name.into());
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceAuthorizationSchemaFields {
    pub id: Option<String>,
    pub device_code: Option<String>,
    pub user_code: Option<String>,
    pub user_id: Option<String>,
    pub expires_at: Option<String>,
    pub status: Option<String>,
    pub last_polled_at: Option<String>,
    pub polling_interval: Option<String>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl DeviceAuthorizationSchemaFields {
    fn set(&mut self, logical_name: String, physical_name: String) {
        match logical_name.as_str() {
            "id" => self.id = Some(physical_name),
            "deviceCode" => self.device_code = Some(physical_name),
            "userCode" => self.user_code = Some(physical_name),
            "userId" => self.user_id = Some(physical_name),
            "expiresAt" => self.expires_at = Some(physical_name),
            "status" => self.status = Some(physical_name),
            "lastPolledAt" => self.last_polled_at = Some(physical_name),
            "pollingInterval" => self.polling_interval = Some(physical_name),
            "clientId" => self.client_id = Some(physical_name),
            "scope" => self.scope = Some(physical_name),
            "createdAt" => self.created_at = Some(physical_name),
            "updatedAt" => self.updated_at = Some(physical_name),
            _ => {}
        }
    }
}

impl Default for DeviceAuthorizationOptions {
    fn default() -> Self {
        Self {
            expires_in: Duration::minutes(30),
            interval: Duration::seconds(5),
            device_code_length: 40,
            user_code_length: 8,
            generate_device_code: None,
            generate_user_code: None,
            validate_client: None,
            on_device_auth_request: None,
            verification_uri: "/device".to_owned(),
            schema: DeviceAuthorizationSchemaOptions::default(),
        }
    }
}

impl DeviceAuthorizationOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<(), DeviceAuthorizationOptionsError> {
        if self.device_code_length == 0 {
            return Err(DeviceAuthorizationOptionsError::EmptyDeviceCodeLength);
        }
        if self.user_code_length == 0 {
            return Err(DeviceAuthorizationOptionsError::EmptyUserCodeLength);
        }
        if self.expires_in <= Duration::ZERO {
            return Err(DeviceAuthorizationOptionsError::NonPositiveExpiresIn);
        }
        if self.interval <= Duration::ZERO {
            return Err(DeviceAuthorizationOptionsError::NonPositiveInterval);
        }
        Ok(())
    }

    #[must_use]
    pub fn expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = expires_in;
        self
    }

    #[must_use]
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    #[must_use]
    pub fn device_code_length(mut self, length: usize) -> Self {
        self.device_code_length = length;
        self
    }

    #[must_use]
    pub fn user_code_length(mut self, length: usize) -> Self {
        self.user_code_length = length;
        self
    }

    #[must_use]
    pub fn generate_device_code<F>(mut self, generator: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        self.generate_device_code =
            Some(Arc::new(move || Box::pin(std::future::ready(generator()))));
        self
    }

    #[must_use]
    pub fn generate_user_code<F>(mut self, generator: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        self.generate_user_code = Some(Arc::new(move || Box::pin(std::future::ready(generator()))));
        self
    }

    #[must_use]
    pub fn generate_device_code_async<F, Fut>(mut self, generator: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = String> + Send + 'static,
    {
        self.generate_device_code = Some(Arc::new(move || Box::pin(generator())));
        self
    }

    #[must_use]
    pub fn generate_user_code_async<F, Fut>(mut self, generator: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = String> + Send + 'static,
    {
        self.generate_user_code = Some(Arc::new(move || Box::pin(generator())));
        self
    }

    #[must_use]
    pub fn validate_client<F, Fut>(mut self, validator: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, OpenAuthError>> + Send + 'static,
    {
        self.validate_client = Some(Arc::new(move |client_id| Box::pin(validator(client_id))));
        self
    }

    #[must_use]
    pub fn on_device_auth_request<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(String, Option<String>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.on_device_auth_request = Some(Arc::new(move |client_id, scope| {
            Box::pin(hook(client_id, scope))
        }));
        self
    }

    #[must_use]
    pub fn verification_uri(mut self, uri: impl Into<String>) -> Self {
        self.verification_uri = uri.into();
        self
    }

    #[must_use]
    pub fn schema(mut self, schema: DeviceAuthorizationSchemaOptions) -> Self {
        self.schema = schema;
        self
    }
}
