#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiSessionOptions {
    pub maximum_sessions: usize,
}

impl Default for MultiSessionOptions {
    fn default() -> Self {
        Self {
            maximum_sessions: 5,
        }
    }
}

impl MultiSessionOptions {
    #[must_use]
    pub fn builder() -> MultiSessionOptionsBuilder {
        MultiSessionOptionsBuilder::default()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MultiSessionOptionsBuilder {
    maximum_sessions: Option<usize>,
}

impl MultiSessionOptionsBuilder {
    #[must_use]
    pub fn maximum_sessions(mut self, maximum_sessions: usize) -> Self {
        self.maximum_sessions = Some(maximum_sessions);
        self
    }

    #[must_use]
    pub fn build(self) -> MultiSessionOptions {
        let defaults = MultiSessionOptions::default();
        MultiSessionOptions {
            maximum_sessions: self.maximum_sessions.unwrap_or(defaults.maximum_sessions),
        }
    }
}
