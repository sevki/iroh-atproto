use std::sync::Arc;

use atrium_api::did_doc::DidDocument;
use atrium_api::types::string::AtIdentifier;
use atrium_common::resolver::Resolver;
use atrium_identity::{
    did::{CommonDidResolver, CommonDidResolverConfig, DEFAULT_PLC_DIRECTORY_URL},
    handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig},
};
use iroh::EndpointAddr;

use crate::dns::HickoryDnsTxtResolver;
use crate::error::{Error, Result};
use crate::http::ReqwestHttpClient;
use crate::service::{IROH_SERVICE_TYPE, SERVICE_ID, parse_service_endpoint};

/// Configuration for [`AtprotoIrohResolver`].
#[derive(Clone, Debug)]
pub struct AtprotoIrohResolverConfig {
    /// URL of the PLC directory to use for `did:plc` resolution.
    ///
    /// Defaults to `https://plc.directory/`.
    pub plc_directory_url: String,
}

impl Default for AtprotoIrohResolverConfig {
    fn default() -> Self {
        Self {
            plc_directory_url: DEFAULT_PLC_DIRECTORY_URL.to_string(),
        }
    }
}

/// Resolves an AT Protocol handle or DID to an iroh [`EndpointAddr`].
///
/// Given an AT Protocol identity (handle like `alice.bsky.social` or a DID like
/// `did:plc:xyz`), this resolver:
///
/// 1. Fetches the DID document via AT Protocol (DNS TXT + PLC directory / `did:web`).
/// 2. Looks for a service entry with `"type": "IrohNode"` and `"id": "#iroh"`.
/// 3. Parses the `serviceEndpoint` as `iroh://<node-id>` (optionally with
///    `?relay=<relay-url>`) to produce an [`EndpointAddr`].
///
/// # Adding an iroh node to a DID document
///
/// In your PLC operation or `did:web` document, add a service:
///
/// ```json
/// {
///   "id": "#iroh",
///   "type": "IrohNode",
///   "serviceEndpoint": "iroh://<node-id>"
/// }
/// ```
///
/// where `<node-id>` is the hex-encoded iroh public key, and an optional
/// `?relay=<url>` query parameter can be included to advertise a relay URL.
///
/// # Example
///
/// ```no_run
/// use iroh_atproto::{AtprotoIrohResolver, AtprotoIrohResolverConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let resolver = AtprotoIrohResolver::new(Default::default())?;
/// let addr = resolver.resolve("alice.bsky.social").await?;
/// println!("iroh node id: {}", addr.id);
/// # Ok(())
/// # }
/// ```
pub struct AtprotoIrohResolver {
    did_resolver: Arc<CommonDidResolver<ReqwestHttpClient>>,
    handle_resolver: Arc<AtprotoHandleResolver<HickoryDnsTxtResolver, ReqwestHttpClient>>,
}

impl AtprotoIrohResolver {
    /// Creates a new [`AtprotoIrohResolver`] with the given configuration.
    pub fn new(
        config: AtprotoIrohResolverConfig,
    ) -> std::result::Result<Self, hickory_resolver::ResolveError> {
        let http_client = Arc::new(ReqwestHttpClient::new());
        let dns_txt_resolver = HickoryDnsTxtResolver::new()?;

        let did_resolver = Arc::new(CommonDidResolver::new(CommonDidResolverConfig {
            plc_directory_url: config.plc_directory_url,
            http_client: http_client.clone(),
        }));

        let handle_resolver = Arc::new(AtprotoHandleResolver::new(AtprotoHandleResolverConfig {
            dns_txt_resolver,
            http_client,
        }));

        Ok(Self {
            did_resolver,
            handle_resolver,
        })
    }

    /// Resolves an AT Protocol handle or DID to an iroh [`EndpointAddr`].
    ///
    /// The DID document must contain a service entry with `"type": "IrohNode"` and
    /// `"id": "#iroh"`. The `serviceEndpoint` must follow the format
    /// `iroh://<node-id>` (with optional `?relay=<relay-url>`).
    pub async fn resolve(&self, at_identifier: &str) -> Result<EndpointAddr> {
        // 1. Determine the DID string from the input.
        let did_str = match at_identifier
            .parse::<AtIdentifier>()
            .map_err(|e| atrium_identity::Error::AtIdentifier(e.to_string()))?
        {
            AtIdentifier::Did(did) => did.as_str().to_string(),
            AtIdentifier::Handle(handle) => {
                let did = self.handle_resolver.resolve(&handle).await?;
                did.as_str().to_string()
            }
        };

        // 2. Fetch the DID document.
        let did = did_str
            .parse()
            .map_err(|e| atrium_identity::Error::Did(format!("invalid DID `{did_str}`: {e}")))?;
        let doc = self.did_resolver.resolve(&did).await?;

        // 3. Extract the IrohNode service endpoint.
        extract_iroh_addr(&doc, at_identifier)
    }
}

/// Extracts an iroh [`EndpointAddr`] from the `IrohNode` service entry in a DID document.
pub(crate) fn extract_iroh_addr(doc: &DidDocument, identity: &str) -> Result<EndpointAddr> {
    let services = doc.service.as_deref().unwrap_or_default();

    // Accept either `#iroh` or `<did>#iroh` as the service id.
    let full_id = format!("{}#{}", doc.id, SERVICE_ID.trim_start_matches('#'));
    let service = services.iter().find(|svc| {
        (svc.id == SERVICE_ID || svc.id == full_id) && svc.r#type == IROH_SERVICE_TYPE
    });

    let Some(service) = service else {
        return Err(Error::NoIrohService(identity.to_string()));
    };

    parse_service_endpoint(&service.service_endpoint)
}
