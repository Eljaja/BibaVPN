#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

fn main() {
    if let Err(e) = bibavpn_desktop::run() {
        eprintln!("BibaVPN failed to start: {e}");
        std::process::exit(1);
    }
}
