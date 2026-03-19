use atrium_xrpc::HttpClient;
use atrium_xrpc::http::{Request, Response};

/// An HTTP client backed by [`reqwest`].
///
/// This implements [`HttpClient`] from `atrium_xrpc` so that the AT Protocol
/// identity resolvers can make HTTP requests to PLC directory and well-known endpoints.
#[derive(Clone, Debug)]
pub struct ReqwestHttpClient {
    inner: reqwest::Client,
}

impl ReqwestHttpClient {
    /// Creates a new [`ReqwestHttpClient`] with default settings.
    pub fn new() -> Self {
        Self {
            inner: reqwest::Client::new(),
        }
    }
}

impl HttpClient for ReqwestHttpClient {
    async fn send_http(
        &self,
        request: Request<Vec<u8>>,
    ) -> std::result::Result<
        Response<Vec<u8>>,
        Box<dyn std::error::Error + Send + Sync + 'static>,
    > {
        let (parts, body) = request.into_parts();
        let url: reqwest::Url = parts.uri.to_string().parse()?;
        let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())?;

        let mut req = self.inner.request(method, url);
        for (name, value) in &parts.headers {
            req = req.header(name.as_str(), value.as_bytes());
        }
        req = req.body(body);

        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();

        let mut builder = Response::builder().status(status);
        for (name, value) in &headers {
            builder = builder.header(name.as_str(), value.as_bytes());
        }

        let bytes = resp.bytes().await?;
        Ok(builder.body(bytes.to_vec())?)
    }
}
