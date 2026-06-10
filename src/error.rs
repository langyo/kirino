#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum KirinoError {
    #[error("store error: {0}")]
    Store(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("session expired")]
    SessionExpired,

    #[error("session not found")]
    SessionNotFound,

    #[error("constraint violation: {0}")]
    ConstraintViolation(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl From<anyhow::Error> for KirinoError {
    fn from(e: anyhow::Error) -> Self {
        KirinoError::Internal(e.to_string())
    }
}

pub type KirinoResult<T> = Result<T, KirinoError>;
