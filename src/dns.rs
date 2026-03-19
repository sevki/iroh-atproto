use atrium_identity::handle::DnsTxtResolver;
use hickory_resolver::TokioResolver;

/// A DNS TXT resolver backed by [`hickory_resolver`].
///
/// This is used by [`atrium_identity`] to resolve AT Protocol handles via DNS TXT records.
/// The AT Protocol requires a `_atproto.<handle>` TXT record containing `did=<did>`.
#[derive(Clone, Debug)]
pub struct HickoryDnsTxtResolver {
    resolver: TokioResolver,
}

impl HickoryDnsTxtResolver {
    /// Creates a new [`HickoryDnsTxtResolver`] using the system DNS configuration.
    pub fn new() -> std::result::Result<Self, hickory_resolver::ResolveError> {
        let resolver = TokioResolver::builder_tokio()?.build();
        Ok(Self { resolver })
    }
}

impl DnsTxtResolver for HickoryDnsTxtResolver {
    async fn resolve(
        &self,
        query: &str,
    ) -> std::result::Result<Vec<String>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let lookup = self.resolver.txt_lookup(query).await?;
        let records = lookup
            .iter()
            .flat_map(|txt| txt.txt_data())
            .filter_map(|data| std::str::from_utf8(data).ok())
            .map(String::from)
            .collect();
        Ok(records)
    }
}
