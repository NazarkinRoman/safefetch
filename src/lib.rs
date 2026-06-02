mod client;
pub mod ech;
mod media;
mod policy;

use std::{collections::HashMap, time::Duration};

use anyhow::{Context, Result as AnyResult, bail};
use client::{build_headers, build_pinned_client, response_to_output, send_request};
pub use media::inspect_image;
use media::{infer_mime_type_from_extension, normalize_mime_type};
use policy::{assert_url_policy, parse_safe_url, private_target_origin_allowlist, resolve_safe_socket_addrs};
use reqwest::header::LOCATION;
use url::Url;

const DEFAULT_TIMEOUT_MS: u32 = 10_000;
const DEFAULT_MAX_REDIRECTS: u32 = 3;
const DEFAULT_MAX_BYTES: u32 = 10 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub enum SafeFetchMethod {
  Get,
  Head,
  Post,
  Put,
  Propfind,
  Report,
}

#[derive(Clone, Debug)]
pub struct SafeFetchRequest {
  pub url: String,
  pub method: Option<SafeFetchMethod>,
  pub headers: Option<HashMap<String, String>>,
  pub body: Option<Vec<u8>>,
  pub timeout_ms: Option<u32>,
  pub max_redirects: Option<u32>,
  pub max_bytes: Option<u32>,
  pub allowed_headers: Option<Vec<String>>,
  pub allowed_hosts: Option<Vec<String>>,
  pub allow_http: Option<bool>,
  pub allow_private_target_origin: Option<bool>,
  pub ech_config_list: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct SafeFetchResponse {
  pub status: u16,
  pub final_url: String,
  pub headers: HashMap<String, String>,
  pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ImageInspectionOptions {
  pub max_width: Option<u32>,
  pub max_height: Option<u32>,
  pub max_pixels: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct ImageInspection {
  pub mime_type: String,
  pub width: u32,
  pub height: u32,
}

#[derive(Clone, Debug)]
pub struct RemoteAttachmentFetchRequest {
  pub url: String,
  pub timeout_ms: Option<u32>,
  pub max_bytes: u32,
  pub allow_private_target_origin: Option<bool>,
  pub expected_content_type_prefix: Option<String>,
  pub max_image_width: Option<u32>,
  pub max_image_height: Option<u32>,
  pub max_image_pixels: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct RemoteAttachmentFetchResponse {
  pub final_url: String,
  pub mime_type: String,
  pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RemoteMimeTypeRequest {
  pub url: String,
  pub timeout_ms: Option<u32>,
}

pub fn safe_fetch(request: &SafeFetchRequest) -> AnyResult<SafeFetchResponse> {
  let timeout = Duration::from_millis(u64::from(request.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)));
  let max_redirects = request.max_redirects.unwrap_or(DEFAULT_MAX_REDIRECTS);
  let max_bytes = usize::try_from(request.max_bytes.unwrap_or(DEFAULT_MAX_BYTES)).context("invalid maxBytes")?;
  let method = request.method.unwrap_or(SafeFetchMethod::Get);
  let mut current = parse_safe_url(&request.url)?;
  let allow_private_origins =
    private_target_origin_allowlist(&request.url, request.allow_private_target_origin.unwrap_or(false))?;
  assert_url_policy(
    &current,
    request.allowed_hosts.as_deref(),
    request.allow_http.unwrap_or(true),
  )?;
  let headers = build_headers(request.headers.as_ref(), request.allowed_headers.as_deref())?;

  for redirect_count in 0..=max_redirects {
    let addrs = resolve_safe_socket_addrs(&current, allow_private_origins.as_deref())?;
    let client = build_pinned_client(&current, &addrs, timeout, request.ech_config_list.as_deref())?;
    let response = send_request(&client, method, current.clone(), headers.clone(), request.body.clone())?;

    if response.status().is_redirection() {
      if redirect_count >= max_redirects {
        bail!("too_many_redirects");
      }
      let Some(location) = response.headers().get(LOCATION) else {
        return response_to_output(response, current, max_bytes, method);
      };
      let location = location.to_str().context("invalid redirect location")?;
      current = parse_safe_url(current.join(location).context("invalid redirect location")?.as_str())?;
      assert_url_policy(
        &current,
        request.allowed_hosts.as_deref(),
        request.allow_http.unwrap_or(true),
      )?;
      continue;
    }

    return response_to_output(response, current, max_bytes, method);
  }

  bail!("too_many_redirects")
}

pub fn fetch_remote_attachment(request: &RemoteAttachmentFetchRequest) -> AnyResult<RemoteAttachmentFetchResponse> {
  let response = safe_fetch(&SafeFetchRequest {
    url: request.url.clone(),
    method: Some(SafeFetchMethod::Get),
    headers: None,
    body: None,
    timeout_ms: request.timeout_ms,
    max_redirects: Some(DEFAULT_MAX_REDIRECTS),
    max_bytes: Some(request.max_bytes),
    allowed_headers: None,
    allowed_hosts: None,
    allow_http: None,
    allow_private_target_origin: request.allow_private_target_origin,
    ech_config_list: None,
  })?;
  if !(200..300).contains(&response.status) {
    bail!("fetch_failed_status: {}", response.status);
  }
  let mime_type = normalize_mime_type(response.headers.get("content-type"));
  if let Some(expected) = request.expected_content_type_prefix.as_deref() {
    if !mime_type.starts_with(expected) {
      bail!("content_type_mismatch");
    }
    if expected.starts_with("image/") {
      inspect_image(
        &response.body,
        ImageInspectionOptions {
          max_width: request.max_image_width,
          max_height: request.max_image_height,
          max_pixels: request.max_image_pixels,
        },
      )?;
    }
  }

  Ok(RemoteAttachmentFetchResponse {
    final_url: response.final_url,
    mime_type,
    body: response.body,
  })
}

pub fn infer_remote_mime_type(request: &RemoteMimeTypeRequest) -> String {
  let Ok(url) = Url::parse(&request.url) else {
    return "application/octet-stream".to_string();
  };
  if let Some(mime_type) = infer_mime_type_from_extension(&url) {
    return mime_type.to_string();
  }
  let Ok(response) = safe_fetch(&SafeFetchRequest {
    url: request.url.clone(),
    method: Some(SafeFetchMethod::Head),
    headers: None,
    body: None,
    timeout_ms: request.timeout_ms,
    max_redirects: Some(DEFAULT_MAX_REDIRECTS),
    max_bytes: Some(0),
    allowed_headers: None,
    allowed_hosts: None,
    allow_http: None,
    allow_private_target_origin: None,
    ech_config_list: None,
  }) else {
    return "application/octet-stream".to_string();
  };
  normalize_mime_type(response.headers.get("content-type"))
}

pub fn assert_safe_url(raw_url: &str) -> AnyResult<()> {
  let url = parse_safe_url(raw_url)?;
  resolve_safe_socket_addrs(&url, None)?;
  Ok(())
}
