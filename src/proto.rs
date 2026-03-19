/// ALPN identifier for the AT Protocol resolver over iroh.
///
/// Both the server and client must agree on this ALPN when establishing a connection.
pub const ALPN: &[u8] = b"/atproto/resolve/1";

/// A resolution request sent by the client.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResolveRequest {
    /// Resolve an AT Protocol handle (e.g. `alice.bsky.social`) to a DID and PDS endpoint.
    Handle {
        /// The handle to resolve.
        handle: String,
    },
    /// Resolve a DID (e.g. `did:plc:xyz`) to a PDS endpoint.
    Did {
        /// The DID to resolve.
        did: String,
    },
}

/// A resolution response returned by the server.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ResolveResponse {
    /// Successful resolution result.
    Ok {
        /// The resolved DID.
        did: String,
        /// The PDS endpoint URL for the DID.
        pds: String,
    },
    /// An error occurred during resolution.
    Error {
        /// A human-readable error message.
        message: String,
    },
}
