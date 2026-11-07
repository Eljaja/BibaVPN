use std::path::Path;
use std::sync::Arc;

use getopts::Options;
use tracing_subscriber::EnvFilter;

use yggdrasil::admin::AdminSocket;
use yggdrasil::core::Core;
use yggdrasil::ipv6rwc::ReadWriteCloser;

#[cfg(feature = "dhat-profiling")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use yggstack::config;
use yggstack::forward::tcp::{spawn_local_tcp, spawn_remote_tcp};
use yggstack::forward::udp::{spawn_local_udp, spawn_remote_udp};
use yggstack::http_proxy::HttpProxyServer;
use yggstack::mapping::{TcpMapping, UdpMapping};
use yggstack::netstack::YggNetstack;
use yggstack::resolver::NameResolver;
use yggstack::socks::Socks5Server;

use yggstack::BUILD_NUM;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "dhat-profiling")]
    let _profiler = dhat::Profiler::builder().file_name("/data/data/com.termux/files/home/dhat-heap.json").build();

    let args: Vec<String> = std::env::args().collect();

    let mut opts = Options::new();
    opts.optflag("", "genconf", "print a new config to stdout");
    opts.optflag("", "useconf", "read TOML config from stdin");
    opts.optopt("", "useconffile", "read TOML config from specified file", "FILE");
    opts.optflag(
        "",
        "normaliseconf",
        "use in combination with -useconf/-useconffile, outputs normalised config",
    );
    opts.optflag("", "json", "with -genconf/-normaliseconf, output as JSON (unsupported, ignored)");
    opts.optflag("", "autoconf", "automatic mode (dynamic IP, peer with IPv6 neighbors)");
    opts.optflag("", "version", "prints the version of this build");
    opts.optflag("", "address", "outputs your IPv6 address");
    opts.optflag("", "subnet", "outputs your IPv6 subnet");
    opts.optflag("", "publickey", "outputs your public key");
    opts.optflag("", "exportkey", "outputs your private key in PEM format");
    opts.optopt("", "loglevel", "loglevel to enable (default: info)", "LEVEL");
    opts.optopt("", "logto", "log destination: stdout or file path (default: stdout)", "PATH");
    opts.optopt(
        "",
        "socks",
        "address for SOCKS5 proxy, e.g. :1080",
        "ADDR",
    );
    opts.optopt(
        "",
        "http",
        "address for HTTP proxy, e.g. :8080",
        "ADDR",
    );
    opts.optopt(
        "",
        "nameserver",
        "Yggdrasil IPv6 address to use as DNS for SOCKS/HTTP; comma-separated servers are tried in order with failover",
        "ADDR",
    );
    opts.optmulti(
        "",
        "local-tcp",
        "TCP port to forward to Yggdrasil, e.g. 8080:[addr]:80",
        "SPEC",
    );
    opts.optmulti(
        "",
        "local-udp",
        "UDP port to forward to Yggdrasil, e.g. 553:[addr]:53",
        "SPEC",
    );
    opts.optmulti(
        "",
        "remote-tcp",
        "TCP port to expose from Yggdrasil, e.g. 22 or 2022:22",
        "SPEC",
    );
    opts.optmulti(
        "",
        "remote-udp",
        "UDP port to expose from Yggdrasil, e.g. 53 or 5353:53",
        "SPEC",
    );
    opts.optflag("h", "help", "print this help");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: {}", e);
            print!("{}", opts.usage("Usage: yggstack [OPTIONS]"));
            std::process::exit(1);
        }
    };

    if matches.opt_present("help") {
        print!("{}", opts.usage("Usage: yggstack [OPTIONS]"));
        return Ok(());
    }

    if matches.opt_present("version") {
        println!(
            "yggstack {}",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }

    // ── Logging ──────────────────────────────────────────────────────────────

    let loglevel = matches
        .opt_str("loglevel")
        .unwrap_or_else(|| "info".to_string());

    init_logging(&loglevel, matches.opt_str("logto").as_deref());

    // ── -genconf ─────────────────────────────────────────────────────────────

    if matches.opt_present("genconf") {
        print!("{}", config::generate_text());
        return Ok(());
    }

    // ── Load config ───────────────────────────────────────────────────────────

    let cfg = if matches.opt_present("autoconf") {
        config::generate()
    } else if matches.opt_present("useconf") {
        config::load_stdin().map_err(|e| format!("stdin: {}", e))?
    } else if let Some(path) = matches.opt_str("useconffile") {
        config::load_file(Path::new(&path)).map_err(|e| format!("{}: {}", path, e))?
    } else {
        eprintln!("No config specified. Use --genconf, --useconf, --useconffile, or --autoconf.");
        print!("{}", opts.usage("Usage: yggstack [OPTIONS]"));
        std::process::exit(1);
    };

    // ── Key/address queries (exit early) ─────────────────────────────────────

    let signing_key = cfg
        .signing_key()
        .map_err(|e| format!("key error: {}", e))?;
    let public_key = signing_key.verifying_key().to_bytes();

    if matches.opt_present("address") {
        println!("{}", config::addr_for_key(&public_key));
        return Ok(());
    }
    if matches.opt_present("subnet") {
        let (ip, plen) = config::subnet_for_key(&public_key);
        println!("{}/{}", ip, plen);
        return Ok(());
    }
    if matches.opt_present("publickey") {
        println!("{}", hex::encode(public_key));
        return Ok(());
    }
    if matches.opt_present("exportkey") {
        // Export as PEM-like hex for compatibility.
        println!("{}", hex::encode(signing_key.to_keypair_bytes()));
        return Ok(());
    }
    if matches.opt_present("normaliseconf") {
        print!("{}", toml::to_string_pretty(&cfg).unwrap_or_default());
        return Ok(());
    }

    // ── Parse forwarding specs ────────────────────────────────────────────────

    let mut local_tcp_mappings: Vec<TcpMapping> = Vec::new();
    for spec in matches.opt_strs("local-tcp") {
        local_tcp_mappings.push(
            TcpMapping::parse_local(&spec)
                .map_err(|e| format!("--local-tcp '{}': {}", spec, e))?,
        );
    }

    let mut local_udp_mappings: Vec<UdpMapping> = Vec::new();
    for spec in matches.opt_strs("local-udp") {
        local_udp_mappings.push(
            UdpMapping::parse_local(&spec)
                .map_err(|e| format!("--local-udp '{}': {}", spec, e))?,
        );
    }

    let mut remote_tcp_mappings: Vec<TcpMapping> = Vec::new();
    for spec in matches.opt_strs("remote-tcp") {
        remote_tcp_mappings.push(
            TcpMapping::parse_remote(&spec)
                .map_err(|e| format!("--remote-tcp '{}': {}", spec, e))?,
        );
    }

    let mut remote_udp_mappings: Vec<UdpMapping> = Vec::new();
    for spec in matches.opt_strs("remote-udp") {
        remote_udp_mappings.push(
            UdpMapping::parse_remote(&spec)
                .map_err(|e| format!("--remote-udp '{}': {}", spec, e))?,
        );
    }

    // ── Start Yggdrasil core ──────────────────────────────────────────────────

    let core = Core::new(signing_key, cfg.clone());
    core.init_links().await;
    core.start().await;

    // Start admin socket (if configured in config, e.g. "tcp://127.0.0.1:9001")
    let _admin = match AdminSocket::new(&cfg.admin_listen, core.clone()).await {
        Ok(admin) => Some(admin),
        Err(e) => {
            tracing::warn!("Failed to start admin socket: {}", e);
            None
        }
    };

    let mtu = core.mtu();
    let rwc = ReadWriteCloser::new(
        core.clone(),
        mtu,
        #[cfg(feature = "ckr")]
        Some(&cfg.tunnel_routing),
        // Upstream's stateful firewall: yggstack does not expose it, so stay
        // disabled and keep the previous packet-filtering behaviour.
        None,
    );
    core.set_path_notify(rwc.clone());

    let our_addr = config::addr_for_key(&public_key);
    tracing::info!("Public key  : {}", hex::encode(public_key));
    tracing::info!("IPv6 address: {}", our_addr);
    let (snet, spfx) = config::subnet_for_key(&public_key);
    tracing::info!("IPv6 subnet : {}/{}", snet, spfx);

    // ── Create netstack ───────────────────────────────────────────────────────

    let netstack = YggNetstack::new(
        rwc.clone(),
        our_addr,
        mtu,
        #[cfg(feature = "ckr")]
        Some(&cfg.tunnel_routing),
    );

    // ── Resolver ──────────────────────────────────────────────────────────────

    let nameserver = matches.opt_str("nameserver").unwrap_or_default();
    if nameserver.is_empty() {
        tracing::warn!("No --nameserver set; SOCKS5/HTTP hostname resolution will only work for .pk.ygg");
    }
    let resolver = Arc::new(NameResolver::new(netstack.clone(), &nameserver));

    // ── Port forwarders ───────────────────────────────────────────────────────

    let (stop_tx, _) = tokio::sync::broadcast::channel::<()>(1);
    let stats = yggstack::stats::ListenerStatsRegistry::new();

    // ── SOCKS5 server ─────────────────────────────────────────────────────────

    if let Some(socks_addr) = matches.opt_str("socks") {
        let addr = if socks_addr.starts_with(':') {
            format!("0.0.0.0{}", socks_addr)
        } else {
            socks_addr
        };
        let server = Arc::new(Socks5Server::new(netstack.clone(), resolver.clone()));
        let addr2 = addr.clone();
        let stop_clone = stop_tx.clone();
        let stats_socks = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = server.serve_tcp(&addr2, stop_clone, stats_socks).await {
                tracing::error!("SOCKS5 server error: {}", e);
            }
        });
    }

    // ── HTTP proxy server ─────────────────────────────────────────────────────

    if let Some(http_addr) = matches.opt_str("http") {
        let addr = if http_addr.starts_with(':') {
            format!("0.0.0.0{}", http_addr)
        } else {
            http_addr
        };
        let server = Arc::new(HttpProxyServer::new(netstack.clone(), resolver.clone()));
        let addr2 = addr.clone();
        let stop_clone = stop_tx.clone();
        let stats_http = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = server.serve_tcp(&addr2, stop_clone, stats_http).await {
                tracing::error!("HTTP proxy server error: {}", e);
            }
        });
    }

    for m in local_tcp_mappings {
        spawn_local_tcp(netstack.clone(), m, stop_tx.clone(), stats.clone());
    }
    for m in local_udp_mappings {
        spawn_local_udp(netstack.clone(), m, stop_tx.clone(), stats.clone());
    }
    for m in remote_tcp_mappings {
        spawn_remote_tcp(netstack.clone(), m, stop_tx.clone(), stats.clone());
    }
    for m in remote_udp_mappings {
        spawn_remote_udp(netstack.clone(), m, stop_tx.clone(), stats.clone());
    }

    // ── Wait for Ctrl-C ───────────────────────────────────────────────────────

    tracing::info!("yggstack running (build #{}); press Ctrl-C or send SIGTERM to exit", BUILD_NUM);

    // Wait for either SIGINT (Ctrl-C) or SIGTERM (sv stop / kill)
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }
    tracing::info!("Shutting down");
    let _ = stop_tx.send(());

    // DHAT profiler (if enabled) will write dhat-heap.json on drop here
    Ok(())
}

fn init_logging(level: &str, logto: Option<&str>) {
    let filter = EnvFilter::new(format!("yggstack={level},yggdrasil={level},ironwood=warn"));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);

    match logto {
        None | Some("stdout") => {
            let _ = subscriber.try_init();
        }
        Some(path) => {
            // Write to file if possible, else fall back to stdout.
            if let Ok(file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = subscriber.with_writer(move || file.try_clone().unwrap()).try_init();
            } else {
                let _ = subscriber.try_init();
            }
        }
    }
}
