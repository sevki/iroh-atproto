//! [`AtProtoResolver`] — iroh [`AddressLookup`] backed by AT Protocol DID documents.
//!
//! [`AddressLookup`]: iroh::address_lookup::AddressLookup

use std::sync::Arc;

use atrium_api::did_doc::DidDocument;
use atrium_api::types::string::AtIdentifier;
use atrium_common::resolver::Resolver;
use atrium_identity::{
    did::{CommonDidResolver, CommonDidResolverConfig, DEFAULT_PLC_DIRECTORY_URL},
    handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig},
};
use iroh::{
    EndpointId,
    address_lookup::{AddressLookup, EndpointData, EndpointInfo, Error, Item},
};
use n0_future::boxed::BoxStream;

use crate::dns::HickoryDnsTxtResolver;
use crate::http::ReqwestHttpClient;
use crate::service::{IROH_SERVICE_TYPE, SERVICE_ID, parse_service_endpoint};

const PROVENANCE: &str = "atproto";

/// Configuration for [`AtProtoResolver`].
#[derive(Clone, Debug)]
pub struct AtProtoResolverConfig {
    /// The AT Protocol handle or DID whose DID document this resolver manages.
    ///
    /// - For **resolve**: the DID document belonging to this identity is fetched
    ///   and its `IrohNode` service entry is returned when the stored
    ///   [`EndpointId`] matches the requested one.
    /// - For **publish**: updating a live PLC operation requires a rotation key
    ///   or PLC access token, which is out of scope here; `publish` is a no-op.
    pub at_identifier: String,

    /// URL of the PLC directory to use for `did:plc` resolution.
    ///
    /// Defaults to `https://plc.directory/`.
    pub plc_directory_url: String,
}

impl AtProtoResolverConfig {
    /// Creates a new config for the given AT Protocol handle or DID.
    pub fn new(at_identifier: impl Into<String>) -> Self {
        Self {
            at_identifier: at_identifier.into(),
            plc_directory_url: DEFAULT_PLC_DIRECTORY_URL.to_string(),
        }
    }
}

/// An iroh [`AddressLookup`] that resolves iroh node addresses via AT Protocol DID documents.
///
/// ## How it works
///
/// An iroh endpoint publishes its addressing information into an AT Protocol DID
/// document under a custom `IrohNode` service entry (see [`crate::service`]).
/// Other peers that know the AT Protocol handle or DID of the endpoint can then
/// resolve its iroh [`EndpointAddr`] without needing an out-of-band address exchange.
///
/// ### Registering with an iroh endpoint
///
/// ```no_run
/// use iroh::{Endpoint, endpoint::presets};
/// use iroh_atproto::{AtProtoResolver, AtProtoResolverConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let resolver = AtProtoResolver::new(AtProtoResolverConfig::new("alice.bsky.social"))?;
/// let ep = Endpoint::builder(presets::N0)
///     .address_lookup(resolver)
///     .bind()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// ### DID document service entry format
///
/// Add this service to the AT Protocol DID document that peers should look up:
///
/// ```json
/// {
///   "id": "#iroh",
///   "type": "IrohNode",
///   "serviceEndpoint": "iroh://<node-id-hex>"
/// }
/// ```
///
/// with an optional relay URL:
///
/// ```json
/// { "serviceEndpoint": "iroh://<node-id-hex>?relay=https%3A%2F%2Frelay.example.com" }
/// ```
///
/// [`AddressLookup`]: iroh::address_lookup::AddressLookup
/// [`EndpointAddr`]: iroh::EndpointAddr
pub struct AtProtoResolver {
    at_identifier: String,
    did_resolver: Arc<CommonDidResolver<ReqwestHttpClient>>,
    handle_resolver: Arc<AtprotoHandleResolver<HickoryDnsTxtResolver, ReqwestHttpClient>>,
}

impl std::fmt::Debug for AtProtoResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtProtoResolver")
            .field("at_identifier", &self.at_identifier)
            .finish_non_exhaustive()
    }
}

impl AtProtoResolver {
    /// Creates a new [`AtProtoResolver`] with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns a [`hickory_resolver::ResolveError`] if the DNS resolver cannot be
    /// initialised from the system configuration.
    pub fn new(
        config: AtProtoResolverConfig,
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
            at_identifier: config.at_identifier,
            did_resolver,
            handle_resolver,
        })
    }
}

impl AddressLookup for AtProtoResolver {
    /// Publishes the local endpoint's addressing information to AT Protocol.
    ///
    /// **Note**: Updating a live AT Protocol DID document (PLC operation) requires
    /// the account's rotation key or a PLC client credential, which is not held by
    /// this resolver.  This method is intentionally a no-op — DID document updates
    /// must be performed out-of-band (e.g. via the Bluesky app or a PLC client).
    fn publish(&self, _data: &EndpointData) {
        // Updating a live AT Protocol DID document requires the account's rotation
        // key or PLC client credentials, which are not available to this resolver.
        // DID document updates must be performed out-of-band.
    }

    /// Resolves an iroh [`EndpointId`] to its addressing information via AT Protocol.
    ///
    /// Fetches the DID document for the configured AT Protocol identity and returns
    /// the [`EndpointAddr`] stored in the `IrohNode` service entry, **provided** the
    /// stored node ID matches `endpoint_id`.
    ///
    /// [`EndpointAddr`]: iroh::EndpointAddr
    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        let at_identifier = self.at_identifier.clone();
        let did_resolver = self.did_resolver.clone();
        let handle_resolver = self.handle_resolver.clone();

        let fut = async move {
            // 1. Resolve the AT Protocol handle or DID to a canonical DID string.
            let did_str = resolve_to_did(&handle_resolver, &at_identifier)
                .await
                .map_err(|e| Error::from_err_box(PROVENANCE, Box::new(e)))?;

            // 2. Fetch the DID document.
            let did = did_str.parse().map_err(|e| {
                Error::from_err_box(
                    PROVENANCE,
                    Box::<dyn std::error::Error + Send + Sync>::from(
                        format!("invalid DID `{did_str}`: {e}"),
                    ),
                )
            })?;
            let doc: DidDocument = did_resolver
                .resolve(&did)
                .await
                .map_err(|e| Error::from_err_box(PROVENANCE, Box::new(e)))?;

            // 3. Extract the IrohNode service entry.
            let endpoint_addr = extract_iroh_addr(&doc, &at_identifier)
                .map_err(|e| Error::from_err_box(PROVENANCE, Box::new(e)))?;

            // 4. Return the address only when the stored EndpointId matches.
            // If the DID document belongs to a different iroh node, this resolver
            // has no results for the requested endpoint_id.
            if endpoint_addr.id != endpoint_id {
                return Err(n0_error::e!(Error::NoResults));
            }

            Ok(Item::new(EndpointInfo::from(endpoint_addr), PROVENANCE, None))
        };

        Some(Box::pin(n0_future::stream::once_future(fut)))
    }
}

/// Resolves the AT Protocol handle or DID to a DID string.
async fn resolve_to_did(
    handle_resolver: &AtprotoHandleResolver<HickoryDnsTxtResolver, ReqwestHttpClient>,
    at_identifier: &str,
) -> std::result::Result<String, atrium_identity::Error> {
    match at_identifier
        .parse::<AtIdentifier>()
        .map_err(|e| atrium_identity::Error::AtIdentifier(e.to_string()))?
    {
        AtIdentifier::Did(did) => Ok(did.as_str().to_string()),
        AtIdentifier::Handle(handle) => {
            let did = handle_resolver.resolve(&handle).await?;
            Ok(did.as_str().to_string())
        }
    }
}

/// Extracts an iroh [`EndpointAddr`] from the `IrohNode` service entry in a DID document.
///
/// [`EndpointAddr`]: iroh::EndpointAddr
pub(crate) fn extract_iroh_addr(
    doc: &DidDocument,
    identity: &str,
) -> crate::error::Result<iroh::EndpointAddr> {
    let services = doc.service.as_deref().unwrap_or_default();
    let full_id = format!("{}#{}", doc.id, SERVICE_ID.trim_start_matches('#'));
    let service = services.iter().find(|svc| {
        (svc.id == SERVICE_ID || svc.id == full_id) && svc.r#type == IROH_SERVICE_TYPE
    });

    let Some(service) = service else {
        return Err(crate::error::Error::NoIrohService(identity.to_string()));
    };

    parse_service_endpoint(&service.service_endpoint)
}
