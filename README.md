# iroh-atproto

Iroh resolver library over AT Protocol using [atrium](https://github.com/atrium-rs/atrium).

## What this provides

- `AtUri` parser for `at://repo/collection/rkey`.
- `AtriumIrohResolver` that calls `com.atproto.repo.getRecord` via atrium.
- `ResolvedRecord` envelope that includes the iroh resolver node ID (`iroh::PublicKey`).

## Quick start

```rust,no_run
use iroh::PublicKey;
use iroh_atproto::AtriumIrohResolver;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let node_id: PublicKey = todo!("load this from your iroh node");
    let resolver = AtriumIrohResolver::new("https://public.api.bsky.app", node_id);

    let record = resolver
        .resolve("at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3l6g7z2vopk2r")
        .await?;

    println!("resolved: {}", record.at_uri);
    Ok(())
}
```
