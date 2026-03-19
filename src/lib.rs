//! Iroh resolver primitives for AT Protocol records.

use atrium_api::{
    client::AtpServiceClient,
    com::atproto::repo::get_record,
    types::{string::AtIdentifier, string::Nsid, string::RecordKey, Object},
};
use atrium_xrpc_client::reqwest::ReqwestClient;
use iroh::PublicKey;
use n0_future::boxed::BoxStream;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, ResolverError>;

/// A parsed `at://` URI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtUri {
    /// Repo DID or handle.
    pub repo: String,
    /// Record collection NSID.
    pub collection: String,
    /// Record key.
    pub rkey: String,
}

impl AtUri {
    /// Parse an `at://did-or-handle/collection/rkey` URI.
    pub fn parse(uri: &str) -> Result<Self> {
        let without_scheme = uri
            .strip_prefix("at://")
            .ok_or_else(|| ResolverError::UnsupportedScheme(uri.to_string()))?;

        let mut parts = without_scheme.split('/');
        let repo = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or(ResolverError::MissingUriPart("repo"))?
            .to_string();
        let collection = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or(ResolverError::MissingUriPart("collection"))?
            .to_string();
        let rkey = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or(ResolverError::MissingUriPart("rkey"))?
            .to_string();

        if parts.next().is_some() {
            return Err(ResolverError::InvalidUriShape(uri.to_string()));
        }

        Ok(Self {
            repo,
            collection,
            rkey,
        })
    }
}

/// Record material resolved from AT protocol and tagged for iroh distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedRecord {
    /// Original at-uri.
    pub at_uri: String,
    /// Optional CID returned by ATP.
    pub cid: Option<String>,
    /// JSON value of the record body.
    pub value: serde_json::Value,
    /// Iroh node ID that resolved this record.
    pub resolved_by: PublicKey,
}

/// Resolver backed by atrium service client.
pub struct AtriumIrohResolver {
    client: AtpServiceClient<ReqwestClient>,
    node_id: PublicKey,
}

impl AtriumIrohResolver {
    /// Build a resolver pointed to an AT protocol PDS endpoint.
    pub fn new(pds_endpoint: &str, node_id: PublicKey) -> Self {
        Self {
            client: AtpServiceClient::new(ReqwestClient::new(pds_endpoint)),
            node_id,
        }
    }

    /// Resolve an `at://` URI using `com.atproto.repo.getRecord`.
    pub async fn resolve(&self, at_uri: &str) -> Result<ResolvedRecord> {
        let parts = AtUri::parse(at_uri)?;

        let params: Object<get_record::ParametersData> = get_record::ParametersData {
            cid: None,
            collection: Nsid::new(parts.collection)
                .map_err(|e| ResolverError::InvalidAtprotoType(e.to_string()))?,
            repo: parts
                .repo
                .parse::<AtIdentifier>()
                .map_err(|e| ResolverError::InvalidAtprotoType(e.to_string()))?,
            rkey: RecordKey::new(parts.rkey)
                .map_err(|e| ResolverError::InvalidAtprotoType(e.to_string()))?,
        }
        .into();

        let response = self
            .client
            .service
            .com
            .atproto
            .repo
            .get_record(params)
            .await
            .map_err(ResolverError::Atproto)?;

        let data = response.data;
        let value = serde_json::to_value(data.value).map_err(ResolverError::Serde)?;

        Ok(ResolvedRecord {
            at_uri: data.uri,
            cid: data.cid.map(|cid| cid.as_ref().to_string()),
            value,
            resolved_by: self.node_id,
        })
    }
}

#[derive(Debug, Default)]
pub struct AtProtoResolver {}

impl iroh::address_lookup::AddressLookup for AtProtoResolver {
    fn publish(&self, _data: &iroh::endpoint_info::EndpointData) {}

    fn resolve(
        &self,
        _endpoint_id: iroh::EndpointId,
    ) -> Option<
        BoxStream<std::result::Result<iroh::address_lookup::Item, iroh::address_lookup::Error>>,
    > {
        None
    }
}

/// Errors returned by resolver operations.
#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("invalid URI: {0}")]
    InvalidUri(String),
    #[error("unsupported URI scheme: {0}")]
    UnsupportedScheme(String),
    #[error("missing URI part: {0}")]
    MissingUriPart(&'static str),
    #[error("invalid at-uri shape: {0}")]
    InvalidUriShape(String),
    #[error("invalid AT protocol type: {0}")]
    InvalidAtprotoType(String),
    #[error("atproto request failed: {0}")]
    Atproto(atrium_xrpc::error::Error<get_record::Error>),
    #[error("serialization failed: {0}")]
    Serde(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_at_uri() {
        let parsed = AtUri::parse("at://did:plc:123/app.bsky.feed.post/abc123").unwrap();
        assert_eq!(parsed.repo, "did:plc:123");
        assert_eq!(parsed.collection, "app.bsky.feed.post");
        assert_eq!(parsed.rkey, "abc123");
    }

    #[test]
    fn parse_invalid_shape() {
        let err = AtUri::parse("at://did:plc:123/app.bsky.feed.post/abc/extra").unwrap_err();
        assert!(matches!(err, ResolverError::InvalidUriShape(_)));
    }
}
