//! # iroh-atproto
//!
//! An [iroh] P2P resolver for [AT Protocol] identities.
//!
//! This crate provides:
//!
//! - [`AtprotoProtocol`] — an iroh [`ProtocolHandler`] that resolves AT Protocol handles
//!   and DIDs on behalf of peers that connect over the [`ALPN`] protocol.
//! - [`AtprotoClient`] — a client that connects to an [`AtprotoProtocol`] node over iroh
//!   and requests handle or DID resolution.
//!
//! ## Protocol
//!
//! The custom ALPN identifier is [`ALPN`] (`/atproto/resolve/1`).  A client opens a
//! bi-directional QUIC stream, writes a JSON [`ResolveRequest`], and receives a JSON
//! [`ResolveResponse`] back.
//!
//! ## Quick-start
//!
//! ### Server
//!
//! ```no_run
//! use iroh::{Endpoint, endpoint::presets};
//! use iroh::protocol::Router;
//! use iroh_atproto::{AtprotoProtocol, ALPN};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let endpoint = Endpoint::bind(presets::N0).await?;
//!     let protocol = AtprotoProtocol::new(Default::default())?;
//!     let router = Router::builder(endpoint)
//!         .accept(ALPN, protocol)
//!         .spawn();
//!     tokio::signal::ctrl_c().await?;
//!     router.shutdown().await?;
//!     Ok(())
//! }
//! ```
//!
//! ### Client
//!
//! ```no_run
//! use iroh::{Endpoint, EndpointAddr, endpoint::presets};
//! use iroh_atproto::AtprotoClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let endpoint = Endpoint::bind(presets::N0).await?;
//!     let server_addr: EndpointAddr = todo!("obtain from server");
//!     let client = AtprotoClient::new(endpoint);
//!     let identity = client.resolve_handle(&server_addr, "alice.bsky.social").await?;
//!     println!("DID:  {}", identity.did);
//!     println!("PDS:  {}", identity.pds);
//!     Ok(())
//! }
//! ```
//!
//! [iroh]: https://iroh.computer
//! [AT Protocol]: https://atproto.com
//! [`ProtocolHandler`]: iroh::protocol::ProtocolHandler

mod client;
mod dns;
mod error;
mod handler;
mod http;
mod proto;

pub use client::{AtprotoClient, ResolvedIdentity};
pub use error::{Error, Result};
pub use handler::{AtprotoProtocol, AtprotoProtocolConfig};
pub use proto::{ALPN, ResolveRequest, ResolveResponse};

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::Endpoint;
    use iroh::protocol::Router;

    /// Verifies that the ALPN constant has the expected value.
    #[test]
    fn alpn_value() {
        assert_eq!(ALPN, b"/atproto/resolve/1");
    }

    /// Verifies that [`ResolveRequest`] serializes and deserializes correctly.
    #[test]
    fn request_roundtrip() {
        let req = ResolveRequest::Handle {
            handle: "alice.bsky.social".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: ResolveRequest = serde_json::from_str(&json).unwrap();
        match decoded {
            ResolveRequest::Handle { handle } => assert_eq!(handle, "alice.bsky.social"),
            other => panic!("unexpected variant: {other:?}"),
        }

        let req = ResolveRequest::Did {
            did: "did:plc:abc123".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: ResolveRequest = serde_json::from_str(&json).unwrap();
        match decoded {
            ResolveRequest::Did { did } => assert_eq!(did, "did:plc:abc123"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// Verifies that [`ResolveResponse`] serializes and deserializes correctly.
    #[test]
    fn response_roundtrip() {
        let resp = ResolveResponse::Ok {
            did: "did:plc:xyz".to_string(),
            pds: "https://bsky.social".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: ResolveResponse = serde_json::from_str(&json).unwrap();
        match decoded {
            ResolveResponse::Ok { did, pds } => {
                assert_eq!(did, "did:plc:xyz");
                assert_eq!(pds, "https://bsky.social");
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        let resp = ResolveResponse::Error {
            message: "not found".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: ResolveResponse = serde_json::from_str(&json).unwrap();
        match decoded {
            ResolveResponse::Error { message } => assert_eq!(message, "not found"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// Integration test: spins up a local iroh server and client, sends a
    /// resolution request that will fail (because the test handle does not
    /// exist), and verifies that the error is propagated correctly.
    #[tokio::test]
    async fn local_request_error_propagation() {
        // Build the server endpoint and protocol handler.
        let server_ep = Endpoint::empty_builder().bind().await.unwrap();
        let protocol = AtprotoProtocol::new(Default::default()).unwrap();
        let router = Router::builder(server_ep).accept(ALPN, protocol).spawn();
        let server_addr = router.endpoint().addr();

        // Build the client endpoint.
        let client_ep = Endpoint::empty_builder().bind().await.unwrap();
        let client = AtprotoClient::new(client_ep);

        // Resolve a handle that doesn't exist — we expect an error to come back
        // rather than a panic or a hang.
        let result = client
            .resolve_handle(&server_addr, "nonexistent.invalid")
            .await;
        assert!(
            result.is_err(),
            "expected an error for an unknown handle, got: {result:?}"
        );

        router.shutdown().await.unwrap();
    }
}
