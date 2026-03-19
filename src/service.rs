//! AT Protocol DID document service entry types and parsing for iroh nodes.
//!
//! ## Format
//!
//! An iroh node is advertised in a DID document as:
//!
//! ```json
//! {
//!   "id": "#iroh",
//!   "type": "IrohNode",
//!   "serviceEndpoint": "iroh://<node-id>"
//! }
//! ```
//!
//! - `<node-id>` is the lowercase hex-encoded iroh public key (64 hex characters).
//! - An optional relay URL can be appended as `?relay=<relay-url-percent-encoded>`.
//!
//! Example with relay:
//! ```text
//! iroh://a3b1c2d4e5f6...?relay=https%3A%2F%2Frelay.example.com
//! ```

use iroh::{EndpointAddr, EndpointId, RelayUrl};

use crate::error::{Error, Result};

/// The DID document service `id` for an iroh node entry.
pub const SERVICE_ID: &str = "#iroh";

/// The DID document service `type` for an iroh node entry.
pub const IROH_SERVICE_TYPE: &str = "IrohNode";

/// Prefix for the `serviceEndpoint` URI.
const SCHEME: &str = "iroh://";

/// Parses an iroh `serviceEndpoint` string into an [`EndpointAddr`].
///
/// Accepts `iroh://<node-id>` with an optional `?relay=<relay-url>` query parameter.
pub fn parse_service_endpoint(endpoint: &str) -> Result<EndpointAddr> {
    let rest = endpoint
        .strip_prefix(SCHEME)
        .ok_or_else(|| Error::InvalidServiceEndpoint {
            endpoint: endpoint.to_string(),
            reason: format!("must start with `{SCHEME}`"),
        })?;

    // Split optional query string.
    let (node_id_str, query) = match rest.split_once('?') {
        Some((id, q)) => (id, Some(q)),
        None => (rest, None),
    };

    // Parse the node id.
    let node_id: EndpointId = node_id_str.parse().map_err(|e| Error::InvalidNodeId {
        value: node_id_str.to_string(),
        source: e,
    })?;

    let mut addr = EndpointAddr::new(node_id);

    // Parse optional relay URL from `?relay=<url>`.
    if let Some(query) = query {
        for pair in query.split('&') {
            if let Some(raw_url) = pair.strip_prefix("relay=") {
                let decoded = percent_decode(raw_url);
                let relay_url: RelayUrl =
                    decoded.parse().map_err(|_| Error::InvalidServiceEndpoint {
                        endpoint: endpoint.to_string(),
                        reason: format!("invalid relay URL `{decoded}`"),
                    })?;
                addr = addr.with_relay_url(relay_url);
            }
        }
    }

    Ok(addr)
}

/// Formats an [`EndpointAddr`] as an iroh `serviceEndpoint` string.
///
/// Produces `iroh://<node-id>` with an optional `?relay=<relay-url>` query parameter
/// for each relay URL in the address.
pub fn format_service_endpoint(addr: &EndpointAddr) -> String {
    let node_id = addr.id.to_string();
    let mut endpoint = format!("{SCHEME}{node_id}");

    let relay_urls: Vec<String> = addr
        .relay_urls()
        .map(|url| format!("relay={}", percent_encode(url.as_str())))
        .collect();

    if !relay_urls.is_empty() {
        endpoint.push('?');
        endpoint.push_str(&relay_urls.join("&"));
    }

    endpoint
}

/// Minimal percent-encoding for relay URLs: encodes all bytes that are not
/// unreserved characters per RFC 3986 (A-Z a-z 0-9 - _ . ~).
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => {
                out.push('%');
                out.push_str(&format!("{other:02X}"));
            }
        }
    }
    out
}

/// Minimal percent-decoding: replaces `%XX` sequences with the decoded byte.
/// The result is interpreted as UTF-8; any invalid sequences are replaced with
/// the Unicode replacement character.
fn percent_decode(input: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(decoded) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                16,
            ) {
                out.push(decoded);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    fn dummy_node_id() -> EndpointId {
        // Generate a valid ed25519 public key from a fixed secret key.
        SecretKey::from([1u8; 32]).public()
    }

    #[test]
    fn parse_endpoint_no_relay() {
        let node_id = dummy_node_id();
        let endpoint = format!("iroh://{}", node_id);
        let addr = parse_service_endpoint(&endpoint).unwrap();
        assert_eq!(addr.id, node_id);
        assert!(addr.relay_urls().next().is_none());
    }

    #[test]
    fn parse_endpoint_with_relay() {
        let node_id = dummy_node_id();
        let relay = "https://relay.example.com";
        let relay_url: RelayUrl = relay.parse().unwrap();
        let endpoint = format!("iroh://{}?relay={}", node_id, percent_encode(relay));
        let addr = parse_service_endpoint(&endpoint).unwrap();
        assert_eq!(addr.id, node_id);
        let relay_urls: Vec<_> = addr.relay_urls().collect();
        assert_eq!(relay_urls.len(), 1);
        // RelayUrl normalizes the URL (e.g. adds a trailing slash), so compare
        // against the parsed form rather than the raw input string.
        assert_eq!(relay_urls[0], &relay_url);
    }

    #[test]
    fn format_roundtrip_no_relay() {
        let node_id = dummy_node_id();
        let addr = EndpointAddr::new(node_id);
        let endpoint = format_service_endpoint(&addr);
        let parsed = parse_service_endpoint(&endpoint).unwrap();
        assert_eq!(parsed.id, addr.id);
        assert!(parsed.relay_urls().next().is_none());
    }

    #[test]
    fn format_roundtrip_with_relay() {
        let node_id = dummy_node_id();
        let relay_url: RelayUrl = "https://relay.example.com".parse().unwrap();
        let addr = EndpointAddr::new(node_id).with_relay_url(relay_url.clone());
        let endpoint = format_service_endpoint(&addr);
        let parsed = parse_service_endpoint(&endpoint).unwrap();
        assert_eq!(parsed.id, addr.id);
        let relay_urls: Vec<_> = parsed.relay_urls().collect();
        assert_eq!(relay_urls.len(), 1);
        assert_eq!(relay_urls[0], &relay_url);
    }

    #[test]
    fn parse_invalid_scheme() {
        assert!(parse_service_endpoint("https://example.com").is_err());
        assert!(parse_service_endpoint("did:plc:abc").is_err());
    }

    #[test]
    fn parse_invalid_node_id() {
        assert!(parse_service_endpoint("iroh://not-a-key").is_err());
    }
}
