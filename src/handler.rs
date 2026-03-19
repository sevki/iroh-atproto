use std::sync::Arc;

use atrium_common::resolver::Resolver;
use atrium_identity::{
    did::{CommonDidResolver, CommonDidResolverConfig, DEFAULT_PLC_DIRECTORY_URL},
    handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig},
    identity_resolver::{IdentityResolver, IdentityResolverConfig},
};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};

use crate::dns::HickoryDnsTxtResolver;
use crate::error::Result;
use crate::http::ReqwestHttpClient;
use crate::proto::{ResolveRequest, ResolveResponse};

type AtprotoIdentityResolver = IdentityResolver<
    CommonDidResolver<ReqwestHttpClient>,
    AtprotoHandleResolver<HickoryDnsTxtResolver, ReqwestHttpClient>,
>;

/// Configuration for [`AtprotoProtocol`].
#[derive(Clone, Debug)]
pub struct AtprotoProtocolConfig {
    /// URL of the PLC directory to use for `did:plc` resolution.
    ///
    /// Defaults to `https://plc.directory/`.
    pub plc_directory_url: String,
}

impl Default for AtprotoProtocolConfig {
    fn default() -> Self {
        Self {
            plc_directory_url: DEFAULT_PLC_DIRECTORY_URL.to_string(),
        }
    }
}

/// An iroh protocol handler that resolves AT Protocol identities.
///
/// Register this with an [`iroh::protocol::Router`] to serve AT Protocol handle and DID
/// resolution requests from other iroh peers over the [`crate::ALPN`] protocol.
///
/// # Example
///
/// ```no_run
/// use iroh::{Endpoint, endpoint::presets};
/// use iroh::protocol::Router;
/// use iroh_atproto::{AtprotoProtocol, ALPN};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let endpoint = Endpoint::bind(presets::N0).await?;
/// let protocol = AtprotoProtocol::new(Default::default())?;
/// let router = Router::builder(endpoint)
///     .accept(ALPN, protocol)
///     .spawn();
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AtprotoProtocol {
    resolver: Arc<AtprotoIdentityResolver>,
}

impl std::fmt::Debug for AtprotoProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtprotoProtocol").finish_non_exhaustive()
    }
}

impl AtprotoProtocol {
    /// Creates a new [`AtprotoProtocol`] handler with the given configuration.
    pub fn new(config: AtprotoProtocolConfig) -> std::result::Result<Self, hickory_resolver::ResolveError> {
        let http_client = Arc::new(ReqwestHttpClient::new());
        let dns_txt_resolver = HickoryDnsTxtResolver::new()?;

        let did_resolver = CommonDidResolver::new(CommonDidResolverConfig {
            plc_directory_url: config.plc_directory_url,
            http_client: http_client.clone(),
        });
        let handle_resolver = AtprotoHandleResolver::new(AtprotoHandleResolverConfig {
            dns_txt_resolver,
            http_client,
        });

        let resolver = IdentityResolver::new(IdentityResolverConfig {
            did_resolver,
            handle_resolver,
        });

        Ok(Self {
            resolver: Arc::new(resolver),
        })
    }
}

impl ProtocolHandler for AtprotoProtocol {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;

        // Read the full request (limit to 64 KiB).
        let raw = recv
            .read_to_end(65536)
            .await
            .map_err(AcceptError::from_err)?;

        let response = match handle_request(&*self.resolver, &raw).await {
            Ok(resp) => resp,
            Err(e) => ResolveResponse::Error {
                message: e.to_string(),
            },
        };

        let encoded = serde_json::to_vec(&response).unwrap_or_else(|e| {
            format!("{{\"status\":\"error\",\"message\":\"{e}\"}}").into_bytes()
        });

        send.write_all(&encoded)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;

        connection.closed().await;
        Ok(())
    }
}

async fn handle_request(
    resolver: &AtprotoIdentityResolver,
    raw: &[u8],
) -> Result<ResolveResponse> {
    let request: ResolveRequest = serde_json::from_slice(raw)?;
    let input = match &request {
        ResolveRequest::Handle { handle } => handle.clone(),
        ResolveRequest::Did { did } => did.clone(),
    };
    let identity = resolver.resolve(&input).await?;
    Ok(ResolveResponse::Ok {
        did: identity.did,
        pds: identity.pds,
    })
}
