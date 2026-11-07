use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Run a control command against the admin socket.
pub async fn run_ctl(
    endpoint: &str,
    json_output: bool,
    command: &str,
    arguments: serde_json::Map<String, serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = serde_json::json!({
        "request": command,
        "arguments": arguments,
        "keepalive": false,
    });

    let addr = endpoint.strip_prefix("tcp://").unwrap_or(endpoint);

    let stream = TcpStream::connect(addr).await.map_err(|e| {
        format!("Failed to connect to admin socket at {}: {}", endpoint, e)
    })?;

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Send request
    let req_json = serde_json::to_string(&request)?;
    writer.write_all(req_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    // Read response
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    if line.trim().is_empty() {
        eprintln!("Empty response from admin socket");
        std::process::exit(1);
    }

    let resp: serde_json::Value = serde_json::from_str(line.trim())?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    // Check status
    let status = resp
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    if status != "success" {
        let error = resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        eprintln!("Error: {}", error);
        std::process::exit(1);
    }

    let response = &resp["response"];

    // Pretty-print based on command
    match command.to_lowercase().as_str() {
        "list" => {
            if let Some(list) = response.get("list").and_then(|v| v.as_array()) {
                println!("Available commands:");
                for cmd in list {
                    if let Some(s) = cmd.as_str() {
                        println!("  {}", s);
                    }
                }
            }
        }

        "getself" => {
            print_kv(response, &[
                ("Build name", "build_name"),
                ("Build version", "build_version"),
                ("Public key", "key"),
                ("IPv6 address", "address"),
                ("IPv6 subnet", "subnet"),
                ("Coordinates", "coordinates"),
                ("Routing entries", "routing_entries"),
            ]);
        }

        "getpeers" => {
            if let Some(peers) = response.get("peers").and_then(|v| v.as_array()) {
                if peers.is_empty() {
                    println!("No peers connected.");
                } else {
                    let header = vec![
                        "URI", "State", "Dir", "IP Address", "Latency", "Cost",
                        "Uptime", "RX", "TX", "RX Rate", "TX Rate", "Pr", "Last Error",
                    ];
                    let rows: Vec<Vec<String>> = peers.iter().map(|peer| {
                        let uri = json_str(peer, "uri");
                        let up = peer.get("up").and_then(|v| v.as_bool()).unwrap_or(false);
                        let state = if up { "Up" } else { "Down" }.into();
                        let inbound = peer.get("inbound").and_then(|v| v.as_bool()).unwrap_or(false);
                        let dir: String = if inbound { "In" } else { "Out" }.into();
                        let address = json_str(peer, "address");
                        let latency = peer.get("latency")
                            .and_then(|v| v.as_f64())
                            .map(|ms| if ms > 0.0 { format!("{:.1}ms", ms) } else { "-".into() })
                            .unwrap_or_else(|| "-".into());
                        let cost = peer.get("cost")
                            .and_then(|v| v.as_u64())
                            .map(|c| if c > 0 { c.to_string() } else { "-".into() })
                            .unwrap_or_else(|| "-".into());
                        let uptime = peer.get("uptime")
                            .and_then(|v| v.as_f64())
                            .map(format_uptime)
                            .unwrap_or_else(|| "-".into());
                        let rx_bytes = peer.get("bytes_recvd")
                            .and_then(|v| v.as_u64())
                            .map(format_bytes)
                            .unwrap_or_else(|| "-".into());
                        let tx_bytes = peer.get("bytes_sent")
                            .and_then(|v| v.as_u64())
                            .map(format_bytes)
                            .unwrap_or_else(|| "-".into());
                        let rx_rate = peer.get("rx_rate")
                            .and_then(|v| v.as_u64())
                            .map(|r| if r > 0 { format!("{}/s", format_bytes(r)) } else { "-".into() })
                            .unwrap_or_else(|| "-".into());
                        let tx_rate = peer.get("tx_rate")
                            .and_then(|v| v.as_u64())
                            .map(|r| if r > 0 { format!("{}/s", format_bytes(r)) } else { "-".into() })
                            .unwrap_or_else(|| "-".into());
                        let priority = peer.get("priority")
                            .and_then(|v| v.as_u64())
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".into());
                        let last_error = json_str(peer, "last_error");
                        let last_error = if last_error.is_empty() { "-".into() } else { last_error };
                        vec![uri, state, dir, address, latency, cost, uptime,
                             rx_bytes, tx_bytes, rx_rate, tx_rate, priority, last_error]
                    }).collect();
                    // URI is the flexible column: it gets truncated to fit the terminal
                    print_table_flex(&header, &rows, 0);
                }
            }
        }

        "gettree" => {
            if let Some(tree) = response.get("tree").and_then(|v| v.as_array()) {
                if tree.is_empty() {
                    println!("No tree entries.");
                } else {
                    let header = vec!["Public Key", "IP Address", "Parent", "Sequence"];
                    let rows: Vec<Vec<String>> = tree.iter().map(|entry| {
                        vec![
                            json_str(entry, "key"),
                            json_str(entry, "address"),
                            json_str(entry, "parent"),
                            json_u64(entry, "sequence"),
                        ]
                    }).collect();
                    print_table(&header, &rows);
                }
            }
        }

        "getpaths" => {
            if let Some(paths) = response.get("paths").and_then(|v| v.as_array()) {
                if paths.is_empty() {
                    println!("No cached paths.");
                } else {
                    let header = vec!["Public Key", "IP Address", "Path", "Sequence"];
                    let rows: Vec<Vec<String>> = paths.iter().map(|entry| {
                        let path = entry.get("path")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_u64())
                                    .map(|n| n.to_string())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            })
                            .unwrap_or_else(|| "-".into());
                        vec![
                            json_str(entry, "key"),
                            json_str(entry, "address"),
                            path,
                            json_u64(entry, "sequence"),
                        ]
                    }).collect();
                    print_table(&header, &rows);
                }
            }
        }

        "getsessions" => {
            if let Some(sessions) = response.get("sessions").and_then(|v| v.as_array()) {
                if sessions.is_empty() {
                    println!("No active sessions.");
                } else {
                    let header = vec!["Public Key", "IP Address", "Uptime", "RX", "TX"];
                    print_table(&header, &session_rows(sessions));
                }
            }
        }

        "gettun" => {
            print_kv(response, &[
                ("TUN enabled", "enabled"),
                ("Interface name", "name"),
                ("Interface MTU", "mtu"),
            ]);
        }

        "getdebug" => {
            print_kv(response, &[
                ("Tree nodes known",      "tree_node_count"),
                ("Routing peers",         "routing_peer_count"),
                ("Tree root key",         "tree_root"),
                ("Our coordinates",       "our_coords"),
                ("Path cache total",      "path_cache_count"),
                ("Broken paths",          "broken_path_count"),
                ("Pending lookups",       "pending_lookup_count"),
                ("Pending sig requests",  "pending_sig_requests"),
                ("RX queue bytes",        "delivery_queue_bytes"),
            ]);

            if let Some(down) = response.get("peers_down").and_then(|v| v.as_array()) {
                if !down.is_empty() {
                    println!("\n  Down peers:");
                    for p in down {
                        let uri = json_str(p, "uri");
                        let err = json_str(p, "last_error");
                        println!("    {} ({})", uri, err);
                    }
                }
            }

            if let Some(lats) = response.get("peer_latencies").and_then(|v| v.as_array()) {
                if !lats.is_empty() {
                    println!("\n  Peer latencies:");
                    let header = vec!["Key", "IP Address", "Latency"];
                    let rows: Vec<Vec<String>> = lats.iter().map(|p| {
                        let ms = p.get("latency_ms").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let lat = if ms > 0.0 { format!("{:.1} ms", ms) } else { "n/a".into() };
                        vec![json_str(p, "key"), json_str(p, "address"), lat]
                    }).collect();
                    print_table(&header, &rows);
                }
            }

            if let Some(sessions) = response.get("sessions").and_then(|v| v.as_array()) {
                if !sessions.is_empty() {
                    println!("\n  Active sessions:");
                    let header = vec!["Key", "IP Address", "Uptime", "RX", "TX"];
                    print_table(&header, &session_rows(sessions));
                } else {
                    println!("\n  No active sessions.");
                }
            }
        }

        _ => {
            println!("{}", serde_json::to_string_pretty(response)?);
        }
    }

    Ok(())
}

fn session_rows(sessions: &[serde_json::Value]) -> Vec<Vec<String>> {
    sessions.iter().map(|s| {
        let uptime = s.get("uptime").and_then(|v| v.as_f64())
            .map(format_uptime).unwrap_or_else(|| "-".into());
        let rx = s.get("bytes_recvd").and_then(|v| v.as_u64())
            .map(format_bytes).unwrap_or_else(|| "-".into());
        let tx = s.get("bytes_sent").and_then(|v| v.as_u64())
            .map(format_bytes).unwrap_or_else(|| "-".into());
        vec![json_str(s, "key"), json_str(s, "address"), uptime, rx, tx]
    }).collect()
}

/// Smallest width the flexible column may be shrunk to.
const MIN_FLEX_WIDTH: usize = 20;

/// Print rows as space-aligned columns with no borders or padding.
fn print_table(header: &[&str], rows: &[Vec<String>]) {
    print_table_inner(header, rows, None);
}

/// Like [`print_table`], but if the table is wider than the terminal, column
/// `flex_col` is narrowed (its cells truncated with an ellipsis) until the
/// table fits, down to [`MIN_FLEX_WIDTH`].
fn print_table_flex(header: &[&str], rows: &[Vec<String>], flex_col: usize) {
    print_table_inner(header, rows, Some(flex_col));
}

fn print_table_inner(header: &[&str], rows: &[Vec<String>], flex_col: Option<usize>) {
    for line in format_table(header, rows, flex_col, terminal_width()) {
        println!("{}", line);
    }
}

fn format_table(
    header: &[&str],
    rows: &[Vec<String>],
    flex_col: Option<usize>,
    term_width: Option<usize>,
) -> Vec<String> {
    let cols = header.len();
    // Compute max width per column
    let mut widths = vec![0usize; cols];
    for (i, h) in header.iter().enumerate() {
        widths[i] = h.chars().count();
    }
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < cols {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }
    }
    // Narrow the flexible column if the table overflows the terminal
    let flex_col = flex_col.filter(|&i| i < cols);
    if let (Some(flex), Some(term)) = (flex_col, term_width) {
        let total: usize = widths.iter().sum::<usize>() + 2 * cols.saturating_sub(1);
        if total > term {
            let shrunk = widths[flex].saturating_sub(total - term).max(MIN_FLEX_WIDTH);
            widths[flex] = shrunk.min(widths[flex]);
        }
    }

    let render = |cells: &mut dyn Iterator<Item = &str>| -> String {
        let mut line = String::new();
        for (i, cell) in cells.enumerate() {
            if i > 0 {
                line.push_str("  ");
            }
            let cell = fit_cell(cell, widths[i], flex_col == Some(i));
            if i < cols - 1 {
                line.push_str(&format!("{:<width$}", cell, width = widths[i]));
            } else {
                line.push_str(&cell); // last column: no trailing spaces
            }
        }
        line
    };

    let mut out = vec![render(&mut header.iter().copied())];
    for row in rows {
        out.push(render(&mut row.iter().map(|s| s.as_str())));
    }
    out
}

/// Cut `s` down to `width` characters, marking the cut with an ellipsis.
/// Returns it unchanged when `truncate` is false or it already fits.
fn fit_cell(s: &str, width: usize, truncate: bool) -> String {
    if !truncate || width == 0 || s.chars().count() <= width {
        return s.to_string();
    }
    let mut out: String = s.chars().take(width - 1).collect();
    out.push('…');
    out
}

/// Terminal width in columns, or `None` when stdout isn't a terminal
/// (redirected to a file or a pipe — leave the output untruncated there).
fn terminal_width() -> Option<usize> {
    terminal_size::terminal_size().map(|(terminal_size::Width(w), _)| w as usize)
}

fn json_str(obj: &serde_json::Value, key: &str) -> String {
    obj.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string()
}

fn json_u64(obj: &serde_json::Value, key: &str) -> String {
    obj.get(key)
        .and_then(|v| v.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "-".into())
}

fn print_kv(obj: &serde_json::Value, fields: &[(&str, &str)]) {
    let max_label = fields.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    for (label, key) in fields {
        if let Some(val) = obj.get(key) {
            let val_str = match val {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => "n/a".to_string(),
                other => other.to_string(),
            };
            println!("  {:width$}  {}", format!("{}:", label), val_str, width = max_label + 1);
        }
    }
}

/// Format bytes as human-readable string (KB, MB, GB, etc.)
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (Vec<&'static str>, Vec<Vec<String>>) {
        let header = vec!["URI", "State", "Latency"];
        let rows = vec![
            vec!["tls://[201:23b0:9e11:2a7c:4d5f::1]:7743".into(), "Up".into(), "21.0ms".into()],
            vec!["tcp://192.168.44.125:7743".into(), "Up".into(), "1.1ms".into()],
        ];
        (header, rows)
    }

    /// Every line of a fitted table has the same width, and it's within the terminal.
    fn assert_fits(lines: &[String], term: usize) {
        for line in lines {
            assert!(line.chars().count() <= term, "line over {} cols: {:?}", term, line);
        }
    }

    #[test]
    fn table_untruncated_when_it_fits() {
        let (header, rows) = sample();
        let lines = format_table(&header, &rows, Some(0), Some(200));
        assert!(lines[1].starts_with("tls://[201:23b0:9e11:2a7c:4d5f::1]:7743"));
        assert!(!lines.iter().any(|l| l.contains('…')));
    }

    #[test]
    fn table_untruncated_when_not_a_terminal() {
        let (header, rows) = sample();
        let lines = format_table(&header, &rows, Some(0), None);
        assert!(lines[1].starts_with("tls://[201:23b0:9e11:2a7c:4d5f::1]:7743"));
    }

    #[test]
    fn flex_column_shrinks_to_terminal_width() {
        let (header, rows) = sample();
        let term = 45;
        let lines = format_table(&header, &rows, Some(0), Some(term));
        assert_fits(&lines, term);
        // Widest line uses the full terminal width, i.e. we shrank by exactly the overflow
        assert_eq!(lines.iter().map(|l| l.chars().count()).max().unwrap(), term);
        assert!(lines[1].starts_with("tls://[201:23b0"));
        assert!(lines[1].contains('…'));
        // The short URI still fits, so it keeps its tail
        assert!(lines[2].starts_with("tcp://192.168.44.125:7743"));
    }

    #[test]
    fn flex_column_never_shrinks_below_minimum() {
        let (header, rows) = sample();
        let lines = format_table(&header, &rows, Some(0), Some(10));
        let uri: String = lines[1].chars().take(MIN_FLEX_WIDTH).collect();
        assert_eq!(uri.chars().count(), MIN_FLEX_WIDTH);
        assert!(uri.ends_with('…'));
    }

    #[test]
    fn other_columns_are_never_truncated() {
        let (header, rows) = sample();
        let lines = format_table(&header, &rows, Some(0), Some(30));
        for line in &lines[1..] {
            assert!(line.ends_with("ms"), "latency column was cut: {:?}", line);
        }
    }

    #[test]
    fn plain_table_ignores_terminal_width() {
        let (header, rows) = sample();
        let lines = format_table(&header, &rows, None, Some(20));
        assert!(lines[1].starts_with("tls://[201:23b0:9e11:2a7c:4d5f::1]:7743"));
    }
}

/// Format uptime in seconds as human-readable string (e.g., "1h23m45s")
fn format_uptime(seconds: f64) -> String {
    let total_secs = seconds as u64;
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    if hours > 0 {
        format!("{}h{}m{}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m{}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}
