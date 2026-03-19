use iroh::{Endpoint, EndpointAddr};

use crate::error::{Error, Result};
use crate::proto::{ALPN, ResolveRequest, ResolveResponse};

/// A client for resolving AT Protocol identities over iroh.
///
/// Connects to a remote iroh node running [`crate::AtprotoProtocol`] and sends
/// resolution requests over the [`ALPN`] protocol.
///
/// # Example
///
/// ```no_run
/// use iroh::{Endpoint, EndpointAddr, endpoint::presets};
/// use iroh_atproto::AtprotoClient;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let endpoint = Endpoint::bind(presets::N0).await?;
/// let server_addr: EndpointAddr = todo!();
/// let client = AtprotoClient::new(endpoint);
/// let result = client.resolve_handle(&server_addr, "alice.bsky.social").await?;
/// println!("DID: {}, PDS: {}", result.did, result.pds);
/// # Ok(())
/// # }
/// ```
pub struct AtprotoClient {
    endpoint: Endpoint,
}

/// The resolved AT Protocol identity returned by [`AtprotoClient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIdentity {
    /// The DID for the resolved identity.
    pub did: String,
    /// The PDS endpoint URL for the DID.
    pub pds: String,
}

impl AtprotoClient {
    /// Creates a new [`AtprotoClient`] using the given iroh [`Endpoint`].
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Resolves an AT Protocol handle to a DID and PDS endpoint.
    ///
    /// Connects to the iroh node at `server_addr` and requests resolution of
    /// the given handle (e.g. `alice.bsky.social`).
    pub async fn resolve_handle(
        &self,
        server_addr: &EndpointAddr,
        handle: &str,
    ) -> Result<ResolvedIdentity> {
        let request = ResolveRequest::Handle {
            handle: handle.to_string(),
        };
        self.send_request(server_addr, &request).await
    }

    /// Resolves an AT Protocol DID to a PDS endpoint.
    ///
    /// Connects to the iroh node at `server_addr` and requests resolution of
    /// the given DID (e.g. `did:plc:xyz123`).
    pub async fn resolve_did(
        &self,
        server_addr: &EndpointAddr,
        did: &str,
    ) -> Result<ResolvedIdentity> {
        let request = ResolveRequest::Did {
            did: did.to_string(),
        };
        self.send_request(server_addr, &request).await
    }

    async fn send_request(
        &self,
        server_addr: &EndpointAddr,
        request: &ResolveRequest,
    ) -> Result<ResolvedIdentity> {
        let conn = self
            .endpoint
            .connect(server_addr.clone(), ALPN)
            .await
            .map_err(|e| Error::Iroh(Box::new(e)))?;

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Iroh(Box::new(e)))?;

        // Send the request.
        let encoded = serde_json::to_vec(request)?;
        send.write_all(&encoded)
            .await
            .map_err(|e| Error::Iroh(Box::new(e)))?;
        send.finish()
            .map_err(|e| Error::Iroh(Box::new(e)))?;

        // Read the response (limit to 64 KiB).
        let response_bytes = recv
            .read_to_end(65536)
            .await
            .map_err(|e| Error::Iroh(Box::new(e)))?;

        let response: ResolveResponse = serde_json::from_slice(&response_bytes)?;

        match response {
            ResolveResponse::Ok { did, pds } => Ok(ResolvedIdentity { did, pds }),
            ResolveResponse::Error { message } => Err(Error::Remote(message)),
        }
    }
}
