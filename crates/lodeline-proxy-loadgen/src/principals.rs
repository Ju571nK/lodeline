//! Principals and routes for a load run, set up the way the proxy authenticates
//! clients (control-plane.md 5.1-5.2): each principal has one 256-bit bearer
//! token, and the proxy config carries only its SHA-256 verifier. The config
//! comes from the control plane (`PUT /v1/proxies/{id}/config`); the tokens stay
//! on the load host in owner-only files.
//!
//! The proxy limits calls per principal (8) and per route (16), so a run at
//! concurrency C needs at least C/8 principals spread over at least C/16 routes.

use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::server::PROTOCOL;

pub struct Layout<'a> {
    pub proxy_id: &'a str,
    /// The proxy listener, `host:port`.
    pub listen: &'a str,
    pub upstream_url: &'a str,
    pub credential_ref: &'a str,
    pub principals: usize,
    pub routes: usize,
}

/// One proxied lane: a route URL and a principal's token file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LaneSpec {
    pub principal_id: String,
    pub url: String,
    pub token_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Targets {
    pub proxied: Vec<LaneSpec>,
}

fn token() -> anyhow::Result<String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|e| anyhow::anyhow!("OS random source: {e}"))?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

fn write_owner_only(path: &Path, data: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?;
        f.write_all(data.as_bytes())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data).with_context(|| format!("write {}", path.display()))
    }
}

/// The `config` object of the proxy config PUT for `layout`, given each
/// principal's verifier. Principal `i` uses route `i % routes` only.
pub fn config(layout: &Layout, verifiers: &[String]) -> Value {
    let routes: Vec<Value> = (0..layout.routes)
        .map(|j| {
            json!({"route_id": format!("load-r{j}"), "upstream_id": format!("load-up{j}"),
                   "upstream_url": layout.upstream_url, "upstream_protocol": PROTOCOL,
                   "credential_ref": layout.credential_ref})
        })
        .collect();
    let principals: Vec<Value> = verifiers
        .iter()
        .enumerate()
        .map(|(i, v)| {
            json!({"principal_id": format!("load-p{i}"), "actor_kind": "non_human",
                   "verifiers": [{"key_id": format!("load-p{i}-k1"), "verifier": v}],
                   "routes": [format!("load-r{}", i % layout.routes)]})
        })
        .collect();
    json!({"schema_version": 1, "proxy_id": layout.proxy_id, "allowed_origins": [],
           "routes": routes, "principals": principals})
}

/// Write `tokens/load-p{i}.token`, `config.json` (the `config` object) and
/// `targets.json` into `out`, which must not exist yet.
pub fn generate(layout: &Layout, out: &Path) -> anyhow::Result<Targets> {
    anyhow::ensure!(
        layout.principals > 0 && layout.routes > 0,
        "need at least one principal and one route"
    );
    anyhow::ensure!(
        layout.routes <= layout.principals,
        "every route needs a principal"
    );
    std::fs::create_dir(out)
        .with_context(|| format!("create {} (it must not exist)", out.display()))?;
    std::fs::create_dir(out.join("tokens"))?;
    let mut verifiers = Vec::new();
    let mut proxied = Vec::new();
    for i in 0..layout.principals {
        let t = token()?;
        verifiers.push(lodeline_proxy_api::verifier_for(&t));
        let file = format!("tokens/load-p{i}.token");
        write_owner_only(&out.join(&file), &format!("{t}\n"))?;
        proxied.push(LaneSpec {
            principal_id: format!("load-p{i}"),
            url: format!("http://{}/mcp/load-r{}", layout.listen, i % layout.routes),
            token_file: file,
        });
    }
    let targets = Targets { proxied };
    std::fs::write(
        out.join("config.json"),
        serde_json::to_vec_pretty(&config(layout, &verifiers))?,
    )?;
    std::fs::write(
        out.join("targets.json"),
        serde_json::to_vec_pretty(&targets)?,
    )?;
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> Layout<'static> {
        Layout {
            proxy_id: "px-load",
            listen: "127.0.0.1:8480",
            upstream_url: "http://127.0.0.1:18090/mcp",
            credential_ref: "load-upstream",
            principals: 4,
            routes: 2,
        }
    }

    #[test]
    fn principals_spread_over_routes_and_only_verifiers_leave() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("out");
        let t = generate(&layout(), &dir).unwrap();
        let cfg: Value =
            serde_json::from_slice(&std::fs::read(dir.join("config.json")).unwrap()).unwrap();
        assert_eq!(cfg["routes"].as_array().unwrap().len(), 2);
        let ps = cfg["principals"].as_array().unwrap();
        assert_eq!(ps.len(), 4);
        for (i, (p, lane)) in ps.iter().zip(&t.proxied).enumerate() {
            let tok = std::fs::read_to_string(dir.join(&lane.token_file)).unwrap();
            let tok = tok.trim();
            assert_eq!(tok.len(), 64);
            assert_eq!(
                p["verifiers"][0]["verifier"],
                lodeline_proxy_api::verifier_for(tok)
            );
            assert_eq!(p["routes"][0], format!("load-r{}", i % 2));
            assert!(lane.url.ends_with(&format!("/mcp/load-r{}", i % 2)));
            assert!(!cfg.to_string().contains(tok), "a token reached the config");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(dir.join(&lane.token_file))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600);
            }
        }
        assert!(generate(&layout(), &dir).is_err(), "never overwrites");
    }
}
