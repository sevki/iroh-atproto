//! # iroh-atproto
//!
//! Resolve [iroh] nodes via [AT Protocol] DID documents.
//!
//! Given an AT Protocol handle (e.g. `alice.bsky.social`) or DID (e.g.
//! `did:plc:xyz`), this crate fetches the DID document through the standard AT
//! Protocol resolution pipeline and extracts the iroh node information from a
//! well-known service entry.
//!
//! ## DID document format
//!
//! Add a service entry to your PLC operation or `did:web` document:
//!
//! ```json
//! {
//!   "id": "#iroh",
//!   "type": "IrohNode",
//!   "serviceEndpoint": "iroh://<node-id>"
//! }
//! ```
//!
//! `<node-id>` is the lowercase hex-encoded iroh public key (64 hex characters).
//! An optional relay URL can be appended as `?relay=<percent-encoded-relay-url>`:
//!
//! ```json
//! {
//!   "serviceEndpoint": "iroh://a3b1c2...?relay=https%3A%2F%2Frelay.example.com"
//! }
//! ```
//!
//! ## Example
//!
//! ```no_run
//! use iroh_atproto::{AtprotoIrohResolver, AtprotoIrohResolverConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let resolver = AtprotoIrohResolver::new(Default::default())?;
//! let addr = resolver.resolve("alice.bsky.social").await?;
//! println!("node id: {}", addr.id);
//! # Ok(())
//! # }
//! ```
//!
//! [iroh]: https://iroh.computer
//! [AT Protocol]: https://atproto.com

mod dns;
mod error;
mod http;
mod resolver;
pub mod service;

pub use error::{Error, Result};
pub use resolver::{AtprotoIrohResolver, AtprotoIrohResolverConfig};
pub use service::{IROH_SERVICE_TYPE, SERVICE_ID, format_service_endpoint, parse_service_endpoint};

#[cfg(test)]
mod tests {
    use atrium_api::did_doc::{DidDocument, Service};
    use iroh::{EndpointAddr, RelayUrl};

    use super::*;

    fn make_doc_with_service(service_endpoint: &str) -> DidDocument {
        DidDocument {
            context: None,
            id: "did:plc:test123".to_string(),
            also_known_as: None,
            verification_method: None,
            service: Some(vec![Service {
                id: SERVICE_ID.to_string(),
                r#type: IROH_SERVICE_TYPE.to_string(),
                service_endpoint: service_endpoint.to_string(),
            }]),
        }
    }

    fn dummy_node_id() -> iroh::EndpointId {
        iroh::SecretKey::from([1u8; 32]).public()
    }

    /// Verifies the service type and id constants.
    #[test]
    fn service_constants() {
        assert_eq!(SERVICE_ID, "#iroh");
        assert_eq!(IROH_SERVICE_TYPE, "IrohNode");
    }

    /// Verifies that extract_iroh_addr works for a DID document that has an IrohNode service.
    #[test]
    fn extract_from_did_doc() {
        let node_id = dummy_node_id();
        let endpoint = format!("iroh://{node_id}");
        let doc = make_doc_with_service(&endpoint);
        let addr = resolver::extract_iroh_addr(&doc, "alice.example.com").unwrap();
        assert_eq!(addr.id, node_id);
    }

    /// Verifies that extract_iroh_addr returns NoIrohService for a doc with no IrohNode service.
    #[test]
    fn extract_missing_service() {
        let doc = DidDocument {
            context: None,
            id: "did:plc:test123".to_string(),
            also_known_as: None,
            verification_method: None,
            service: None,
        };
        let err = resolver::extract_iroh_addr(&doc, "alice.example.com").unwrap_err();
        assert!(matches!(err, Error::NoIrohService(_)));
    }

    /// Verifies that a service with the wrong type is ignored.
    #[test]
    fn extract_wrong_service_type() {
        let doc = DidDocument {
            context: None,
            id: "did:plc:test123".to_string(),
            also_known_as: None,
            verification_method: None,
            service: Some(vec![atrium_api::did_doc::Service {
                id: SERVICE_ID.to_string(),
                r#type: "AtprotoPersonalDataServer".to_string(),
                service_endpoint: "https://bsky.social".to_string(),
            }]),
        };
        let err = resolver::extract_iroh_addr(&doc, "alice.example.com").unwrap_err();
        assert!(matches!(err, Error::NoIrohService(_)));
    }

    /// Verifies the format/parse roundtrip with a relay URL.
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
