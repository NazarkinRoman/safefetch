# safefetch

`safefetch` is a small blocking HTTP client for server-side fetch paths that
need SSRF protection by default.

It validates URL schemes, resolves and pins connection addresses, rejects
loopback/private/link-local targets, re-checks redirects, limits response size,
and allows callers to opt into a narrow set of request headers. HTTPS requests
can also use an explicit ECH config list.

## Example

```rust
use safefetch::{safe_fetch, SafeFetchMethod, SafeFetchRequest};

let response = safe_fetch(&SafeFetchRequest {
  url: "https://example.com/".to_owned(),
  method: Some(SafeFetchMethod::Get),
  headers: None,
  body: None,
  timeout_ms: Some(10_000),
  max_redirects: Some(3),
  max_bytes: Some(1024 * 1024),
  allowed_headers: None,
  allowed_hosts: None,
  allow_http: Some(false),
  allow_private_target_origin: None,
  ech_config_list: None,
})?;

assert!(response.status < 400);
# Ok::<(), anyhow::Error>(())
```

## ECH

ECH is disabled unless `SafeFetchRequest::ech_config_list` is provided. For
Cloudflare-hosted targets, `safefetch::ech::cloudflare_https_ech_config_list`
can resolve the HTTPS record and extract the ECH config list.

## License

Licensed under AGPL-3.0-only.
