use std::time::Duration;

use anyhow::{Context, Result as AnyResult};
use hickory_resolver::{
  TokioResolver,
  config::{CLOUDFLARE, ResolverConfig},
  net::runtime::TokioRuntimeProvider,
  proto::rr::{
    RData, RecordType,
    rdata::svcb::{SvcParamKey, SvcParamValue},
  },
};

pub fn cloudflare_https_ech_config_list(host: &str, timeout: Duration) -> AnyResult<Vec<u8>> {
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .context("failed to build ech dns runtime")?;

  runtime.block_on(async {
    let mut builder =
      TokioResolver::builder_with_config(ResolverConfig::https(&CLOUDFLARE), TokioRuntimeProvider::default());
    builder.options_mut().timeout = timeout;
    let resolver = builder.build().context("failed to build ech resolver")?;
    let result = resolver
      .lookup(host, RecordType::HTTPS)
      .await
      .context("failed to query ech config")?;

    result
      .answers()
      .iter()
      .find_map(|record| match &record.data {
        RData::HTTPS(svcb) => svcb.svc_params.iter().find_map(|param| match param {
          (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(ech)) => Some(ech.clone().0),
          _ => None,
        }),
        _ => None,
      })
      .ok_or_else(|| anyhow::anyhow!("ech_config_not_found"))
  })
}
