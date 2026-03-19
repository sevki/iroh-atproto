/// Errors that can occur when resolving an iroh node via AT Protocol.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to resolve the AT Protocol identity (handle or DID).
    #[error("AT Protocol identity error: {0}")]
    Identity(#[from] atrium_identity::Error),

    /// The DID document does not contain an `IrohNode` service entry.
    #[error("no `IrohNode` service found in DID document for `{0}`")]
    NoIrohService(String),

    /// The `IrohNode` service endpoint is malformed or cannot be parsed.
    #[error("invalid IrohNode service endpoint `{endpoint}`: {reason}")]
    InvalidServiceEndpoint { endpoint: String, reason: String },

    /// Failed to parse the iroh node ID from the service endpoint.
    #[error("invalid iroh node ID `{value}`: {source}")]
    InvalidNodeId {
        value: String,
        #[source]
        source: iroh::KeyParsingError,
    },
}

pub type Result<T> = std::result::Result<T, Error>;
