/// Errors that can occur in the iroh-atproto library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The remote AT Protocol service returned an error.
    #[error("AT Protocol identity error: {0}")]
    Identity(#[from] atrium_identity::Error),

    /// JSON serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// An iroh networking error occurred.
    #[error("iroh error: {0}")]
    Iroh(Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The remote peer returned a resolution error.
    #[error("remote resolution error: {0}")]
    Remote(String),
}

pub type Result<T> = std::result::Result<T, Error>;
