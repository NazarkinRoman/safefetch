use std::{collections::HashMap, io::Read, net::SocketAddr, time::Duration};

use anyhow::{Context, Result as AnyResult, bail};
use reqwest::{
  Method,
  blocking::{Client, Response},
  header::{HeaderMap, HeaderName, HeaderValue},
};
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use url::Url;

use crate::{SafeFetchMethod, SafeFetchResponse};

pub(crate) fn build_headers(
  headers: Option<&HashMap<String, String>>,
  allowed_headers: Option<&[String]>,
) -> AnyResult<HeaderMap> {
  let mut out = HeaderMap::new();
  let Some(headers) = headers else {
    return Ok(out);
  };
  let allowed_headers = allowed_headers
    .unwrap_or_default()
    .iter()
    .map(|name| name.to_ascii_lowercase())
    .collect::<Vec<_>>();
  for (name, value) in headers {
    let lower = name.to_ascii_lowercase();
    if !(lower.starts_with("sec-")
      || lower.starts_with("accept")
      || lower == "user-agent"
      || allowed_headers.iter().any(|allowed| allowed == &lower))
    {
      continue;
    }
    out.insert(
      HeaderName::from_bytes(name.as_bytes()).context("invalid header name")?,
      HeaderValue::from_str(value).context("invalid header value")?,
    );
  }
  Ok(out)
}

pub(crate) fn build_pinned_client(
  url: &Url,
  addrs: &[SocketAddr],
  timeout: Duration,
  ech_config_list: Option<&[u8]>,
) -> AnyResult<Client> {
  let host = url.host_str().context("blocked_hostname")?;
  Client::builder()
    .timeout(timeout)
    .no_proxy()
    .redirect(reqwest::redirect::Policy::none())
    .tls_backend_preconfigured(webpki_tls_config(ech_config_list)?)
    .resolve_to_addrs(host, addrs)
    .build()
    .context("failed to build http client")
}

fn webpki_tls_config(ech_config_list: Option<&[u8]>) -> AnyResult<rustls::ClientConfig> {
  let root_store = rustls::RootCertStore {
    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
  };
  let provider = rustls::crypto::aws_lc_rs::default_provider();
  let builder = rustls::ClientConfig::builder_with_provider(provider.clone().into());

  let builder = if let Some(ech_config_list) = ech_config_list {
    let ech_config = rustls::client::EchConfig::new(
      rustls::pki_types::EchConfigListBytes::from(ech_config_list),
      ALL_SUPPORTED_SUITES,
    )
    .context("invalid ech config")?;
    builder
      .with_ech(rustls::client::EchMode::Enable(ech_config))
      .context("failed to build ech tls config")?
  } else {
    builder
      .with_safe_default_protocol_versions()
      .context("failed to build tls protocol config")?
  };

  Ok(builder.with_root_certificates(root_store).with_no_client_auth())
}

pub(crate) fn send_request(
  client: &Client,
  method: SafeFetchMethod,
  url: Url,
  headers: HeaderMap,
  body: Option<Vec<u8>>,
) -> AnyResult<Response> {
  let method = match method {
    SafeFetchMethod::Get => Method::GET,
    SafeFetchMethod::Head => Method::HEAD,
    SafeFetchMethod::Post => Method::POST,
    SafeFetchMethod::Put => Method::PUT,
    SafeFetchMethod::Propfind => Method::from_bytes(b"PROPFIND").context("invalid method")?,
    SafeFetchMethod::Report => Method::from_bytes(b"REPORT").context("invalid method")?,
  };
  let request = client.request(method, url).headers(headers);
  let request = if let Some(body) = body {
    request.body(body)
  } else {
    request
  };
  request.send().context("failed to fetch url")
}

pub(crate) fn response_to_output(
  mut response: Response,
  url: Url,
  max_bytes: usize,
  method: SafeFetchMethod,
) -> AnyResult<SafeFetchResponse> {
  let status = response.status().as_u16();
  let headers = response_headers(response.headers());
  if matches!(method, SafeFetchMethod::Head) {
    return Ok(SafeFetchResponse {
      status,
      final_url: url.to_string(),
      headers,
      body: Vec::new(),
    });
  }
  let mut body = Vec::new();
  if let Some(len) = response.content_length()
    && len > max_bytes as u64
  {
    bail!("response_too_large");
  }
  response
    .by_ref()
    .take(u64::try_from(max_bytes).unwrap_or(u64::MAX) + 1)
    .read_to_end(&mut body)
    .context("failed to read response")?;
  if body.len() > max_bytes {
    bail!("response_too_large");
  }
  Ok(SafeFetchResponse {
    status,
    final_url: url.to_string(),
    headers,
    body,
  })
}

fn response_headers(headers: &HeaderMap) -> HashMap<String, String> {
  headers
    .iter()
    .filter_map(|(name, value)| {
      value
        .to_str()
        .ok()
        .map(|value| (name.as_str().to_string(), value.to_string()))
    })
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn builds_https_client_with_embedded_roots() {
    let url = Url::parse("https://example.com/").unwrap();
    let addrs = ["93.184.216.34:443".parse().unwrap()];
    build_pinned_client(&url, &addrs, Duration::from_secs(1), None).unwrap();
  }
}
