//! Генерация multi-size `.ico` из `branding/biba-vpn-app-icon.png` и привязка к PE (иконка exe в Проводнике).

use std::env;
use std::fs::File;
use std::path::Path;

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let hand_ico = Path::new(&manifest).join("../../branding/biba-vpn-windows.ico");
    let png_path = Path::new(&manifest).join("../../branding/biba-vpn-app-icon.png");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    let ico_path = Path::new(&out_dir).join("bibavpn_app.ico");

    println!("cargo:rerun-if-changed={}", hand_ico.display());
    println!("cargo:rerun-if-changed={}", png_path.display());

    if hand_ico.exists() {
        std::fs::copy(&hand_ico, &ico_path).expect("copy branding/biba-vpn-windows.ico");
    } else if png_path.exists() {
        let img = image::open(&png_path).expect("open branding/biba-vpn-app-icon.png");
        let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);
        for size in [16u32, 24, 32, 48, 64, 128, 256] {
            let rgba = img
                .resize_exact(size, size, image::imageops::FilterType::Lanczos3)
                .to_rgba8();
            let icon_img = ico::IconImage::from_rgba_data(size, size, rgba.into_raw());
            icon_dir.add_entry(ico::IconDirEntry::encode(&icon_img).expect("IconDirEntry::encode"));
        }
        let mut f = File::create(&ico_path).expect("write generatedico");
        icon_dir.write(&mut f).expect("IconDir::write");
    }

    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("windows") && ico_path.exists() {
        let mut res = winresource::WindowsResource::new();
        res.set_icon(ico_path.to_str().expect("utf8 ico path"));
        res.compile().expect("WindowsResource::compile (windres / rc)");
    }
}
