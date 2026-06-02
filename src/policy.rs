use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use anyhow::{Context, Result as AnyResult, bail};
use url::Url;

pub(crate) fn private_target_origin_allowlist(
  raw_url: &str,
  allow_private_target_origin: bool,
) -> AnyResult<Option<Vec<String>>> {
  if !allow_private_target_origin {
    return Ok(None);
  }
  Ok(Some(vec![parse_safe_url(raw_url)?.origin().ascii_serialization()]))
}

pub(crate) fn parse_safe_url(raw: &str) -> AnyResult<Url> {
  let url = Url::parse(raw).context("invalid_url")?;
  match url.scheme() {
    "http" | "https" => {}
    _ => bail!("disallowed_protocol"),
  }
  if !url.username().is_empty() || url.password().is_some() {
    bail!("url_has_credentials");
  }
  if url.host_str().is_none() {
    bail!("blocked_hostname");
  }
  Ok(url)
}

pub(crate) fn assert_url_policy(url: &Url, allowed_hosts: Option<&[String]>, allow_http: bool) -> AnyResult<()> {
  if !allow_http && url.scheme() == "http" {
    bail!("disallowed_protocol");
  }

  let Some(allowed_hosts) = allowed_hosts else {
    return Ok(());
  };
  if allowed_hosts.is_empty() {
    return Ok(());
  }

  let host = url.host_str().context("blocked_hostname")?.to_ascii_lowercase();
  let allowed = allowed_hosts.iter().any(|entry| {
    let normalized = entry.to_ascii_lowercase();
    if normalized.is_empty() {
      return false;
    }
    if let Some(suffix) = normalized.strip_prefix("*.") {
      return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    host == normalized || host.ends_with(&format!(".{normalized}"))
  });
  if !allowed {
    bail!("host_not_allowed");
  }
  Ok(())
}

pub(crate) fn resolve_safe_socket_addrs(
  url: &Url,
  allow_private_origins: Option<&[String]>,
) -> AnyResult<Vec<SocketAddr>> {
  let host = url.host_str().context("blocked_hostname")?;
  let port = url.port_or_known_default().context("blocked_hostname")?;
  let origin = url.origin().ascii_serialization();
  let allow_private = allow_private_origins
    .map(|origins| origins.iter().any(|allowed| allowed == &origin))
    .unwrap_or(false);
  let addrs: Vec<SocketAddr> = (host, port)
    .to_socket_addrs()
    .context("unresolvable_hostname")?
    .collect();
  if addrs.is_empty() {
    bail!("unresolvable_hostname");
  }
  for addr in &addrs {
    if is_blocked_ip(addr.ip()) && !allow_private {
      bail!("blocked_ip");
    }
  }
  Ok(addrs)
}

pub(crate) fn is_blocked_ip(ip: IpAddr) -> bool {
  match ip {
    IpAddr::V4(ip) => {
      ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 224
        || ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1])
        || ip.octets()[0] == 169 && ip.octets()[1] == 254
        || ip.octets()[0] == 198 && (18..=19).contains(&ip.octets()[1])
        || ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0
    }
    IpAddr::V6(ip) => {
      if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_ip(IpAddr::V4(v4));
      }
      if let Some(v4) = extract_6to4_ipv4(ip).or_else(|| extract_teredo_client_ipv4(ip)) {
        return is_blocked_ip(IpAddr::V4(v4));
      }
      (ip.segments()[0] & 0xe000 != 0x2000)
        || ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (ip.segments()[0] & 0xfe00 == 0xfc00)
        || (ip.segments()[0] & 0xffc0 == 0xfe80)
        || (ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8)
    }
  }
}

fn extract_6to4_ipv4(ip: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
  let segments = ip.segments();
  if segments[0] != 0x2002 {
    return None;
  }
  Some(std::net::Ipv4Addr::new(
    (segments[1] >> 8) as u8,
    segments[1] as u8,
    (segments[2] >> 8) as u8,
    segments[2] as u8,
  ))
}

fn extract_teredo_client_ipv4(ip: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
  let segments = ip.segments();
  if segments[0] != 0x2001 || segments[1] != 0 {
    return None;
  }
  Some(std::net::Ipv4Addr::new(
    (!(segments[6] >> 8)) as u8,
    (!segments[6]) as u8,
    (!(segments[7] >> 8)) as u8,
    (!segments[7]) as u8,
  ))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn blocks_private_ips() {
    assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
    assert!(is_blocked_ip("10.0.0.1".parse().unwrap()));
    assert!(is_blocked_ip("169.254.169.254".parse().unwrap()));
    assert!(is_blocked_ip("::1".parse().unwrap()));
    assert!(is_blocked_ip("::ffff:127.0.0.1".parse().unwrap()));
    assert!(is_blocked_ip("2002:7f00:0001::1".parse().unwrap()));
    assert!(is_blocked_ip("2002:c0a8:0001::1".parse().unwrap()));
    assert!(is_blocked_ip(
      "2001:0000:4136:e378:8000:63bf:807f:fffe".parse().unwrap()
    ));
    assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
    assert!(!is_blocked_ip("2002:0808:0808::1".parse().unwrap()));
  }
}
