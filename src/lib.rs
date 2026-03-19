//! # iroh-atproto
//!
//! Resolve [iroh] nodes via [AT Protocol] DID documents.
//!
//! This crate implements [`iroh::address_lookup::AddressLookup`] using AT Protocol
//! DID documents as the address storage backend.  Iroh endpoints can publish their
//! addressing information to a DID document and other peers can resolve it using
//! only the peer's AT Protocol handle (e.g. `alice.bsky.social`) or DID.
//!
//! ## DID document format
//!
//! Add a service entry to your AT Protocol DID document:
//!
//! ```json
//! {
//!   "id": "#iroh",
//!   "type": "IrohNode",
//!   "serviceEndpoint": "iroh://<node-id-hex>"
//! }
//! ```
//!
//! An optional relay URL can be appended as a query parameter:
//!
//! ```json
//! { "serviceEndpoint": "iroh://<node-id-hex>?relay=https%3A%2F%2Frelay.example.com" }
//! ```
//!
//! ## Example
//!
//! ```no_run
//! use iroh::{Endpoint, endpoint::presets};
//! use iroh_atproto::{AtProtoResolver, AtProtoResolverConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let resolver = AtProtoResolver::new(AtProtoResolverConfig::new("alice.bsky.social"))?;
//! let ep = Endpoint::builder(presets::N0)
//!     .address_lookup(resolver)
//!     .bind()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! [iroh]: https://iroh.computer
//! [AT Protocol]: https://atproto.com

mod dns;
pub mod error;
mod http;
mod resolver;
pub mod service;

pub use error::{Error, Result};
pub use resolver::{AtProtoResolver, AtProtoResolverConfig};
pub use service::{IROH_SERVICE_TYPE, SERVICE_ID, format_service_endpoint, parse_service_endpoint};

// Re-export the shared helper used by lib tests.
#[cfg(test)]
pub(crate) use resolver::extract_iroh_addr;

#[cfg(test)]
mod tests {
    use atrium_api::did_doc::{DidDocument, Service};
    use iroh::{EndpointAddr, RelayUrl, SecretKey};

    use super::*;

    fn dummy_node_id() -> iroh::EndpointId {
        SecretKey::from([1u8; 32]).public()
    }

    fn make_doc_with_service(did: &str, service_endpoint: &str) -> DidDocument {
        DidDocument {
            context: None,
            id: did.to_string(),
            also_known_as: None,
            verification_method: None,
            service: Some(vec![Service {
                id: SERVICE_ID.to_string(),
                r#type: IROH_SERVICE_TYPE.to_string(),
                service_endpoint: service_endpoint.to_string(),
            }]),
        }
    }

    /// Constants have expected values.
    #[test]
    fn service_constants() {
        assert_eq!(SERVICE_ID, "#iroh");
        assert_eq!(IROH_SERVICE_TYPE, "IrohNode");
    }

    /// `extract_iroh_addr` returns the correct EndpointAddr for a well-formed DID document.
    #[test]
    fn extract_from_did_doc() {
        let node_id = dummy_node_id();
        let endpoint = format!("iroh://{node_id}");
        let doc = make_doc_with_service("did:plc:test123", &endpoint);
        let addr = extract_iroh_addr(&doc, "alice.example.com").unwrap();
        assert_eq!(addr.id, node_id);
    }

    /// `extract_iroh_addr` returns `NoIrohService` when no service entry exists.
    #[test]
    fn extract_missing_service() {
        let doc = DidDocument {
            context: None,
            id: "did:plc:test123".to_string(),
            also_known_as: None,
            verification_method: None,
            service: None,
        };
        let err = extract_iroh_addr(&doc, "alice.example.com").unwrap_err();
        assert!(matches!(err, Error::NoIrohService(_)));
    }

    /// A service with the wrong type is ignored.
    #[test]
    fn extract_wrong_service_type() {
        let doc = DidDocument {
            context: None,
            id: "did:plc:test123".to_string(),
            also_known_as: None,
            verification_method: None,
            service: Some(vec![Service {
                id: SERVICE_ID.to_string(),
                r#type: "AtprotoPersonalDataServer".to_string(),
                service_endpoint: "https://bsky.social".to_string(),
            }]),
        };
        let err = extract_iroh_addr(&doc, "alice.example.com").unwrap_err();
        assert!(matches!(err, Error::NoIrohService(_)));
    }

    /// `extract_iroh_addr` also accepts the full `<did>#iroh` service id.
    #[test]
    fn extract_full_service_id() {
        let node_id = dummy_node_id();
        let endpoint = format!("iroh://{node_id}");
        let did = "did:plc:test123";
        let doc = DidDocument {
            context: None,
            id: did.to_string(),
            also_known_as: None,
            verification_method: None,
            service: Some(vec![Service {
                id: format!("{did}#iroh"),
                r#type: IROH_SERVICE_TYPE.to_string(),
                service_endpoint: endpoint.clone(),
            }]),
        };
        let addr = extract_iroh_addr(&doc, "alice.example.com").unwrap();
        assert_eq!(addr.id, node_id);
    }

    /// format/parse roundtrip with a relay URL.
    #[test]
    fn format_parse_roundtrip_with_relay() {
        let node_id = dummy_node_id();
        let relay: RelayUrl = "https://relay.example.com".parse().unwrap();
        let addr = EndpointAddr::new(node_id).with_relay_url(relay.clone());
        let endpoint = format_service_endpoint(&addr);
        let parsed = parse_service_endpoint(&endpoint).unwrap();
        assert_eq!(parsed.id, node_id);
        let relays: Vec<_> = parsed.relay_urls().collect();
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0], &relay);
    }
}
