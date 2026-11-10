//! Diagnostic: start the client mesh stack, wait, and print the peer/tree map.
//! Local-only helper; not part of the product CLI.
use bibavpn::yb_mesh::{bootstrap_peers, MeshNode};
use serde_json::json;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let peers = std::env::var("BIBA_YB_MESH_PEERS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|peers| !peers.is_empty())
        .unwrap_or_else(bootstrap_peers);
    let limit = std::env::var("BIBA_MESH_MAP_LIMIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200);
    let wait = std::env::var("BIBA_MESH_MAP_WAIT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30);

    eprintln!("mesh map: starting with {} candidates, wait {}s", peers.len(), wait);
    let node = MeshNode::start(peers, vec![]).await?;
    tokio::time::sleep(Duration::from_secs(wait)).await;
    let topology = node.topology().await;

    let peers: Vec<_> = topology
        .peers
        .iter()
        .map(|peer| {
            json!({
                "uri": peer.uri,
                "up": peer.up,
                "latency_ms": peer.latency_ms,
                "cost": peer.cost,
                "rx_rate": peer.rx_rate,
                "tx_rate": peer.tx_rate,
                "uptime_secs": peer.uptime_secs,
                "last_error": peer.last_error,
            })
        })
        .collect();
    let tree_total = topology.tree.len();
    let paths_total = topology.paths.len();
    let tree: Vec<_> = topology
        .tree
        .iter()
        .take(limit)
        .map(|(key, parent, sequence)| {
            json!({"key": key, "parent": parent, "sequence": sequence})
        })
        .collect();
    let paths: Vec<_> = topology
        .paths
        .iter()
        .take(limit)
        .map(|(key, path, sequence)| {
            json!({"key": key, "path": path, "sequence": sequence})
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "peers": peers,
            "tree_total": tree_total,
            "tree": tree,
            "coordinates": topology.coordinates,
            "paths_total": paths_total,
            "paths": paths,
        }))?
    );
    node.shutdown().await;
    Ok(())
}
