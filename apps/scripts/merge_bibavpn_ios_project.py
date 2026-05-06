#!/usr/bin/env python3
"""Merge BibaVPN Network Extension into Tauri-generated XcodeGen `project.yml`.

Usage (repo root):
  pip install pyyaml
  python3 apps/scripts/merge_bibavpn_ios_project.py apps/bibavpn-desktop/src-tauri/gen/apple

Requires `tauri ios init` to have created gen/apple/project.yml first.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("merge_bibavpn_ios_project: install PyYAML (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: merge_bibavpn_ios_project.py <path-to-gen/apple>", file=sys.stderr)
        sys.exit(2)

    gen_apple = Path(sys.argv[1]).resolve()
    project_yml = gen_apple / "project.yml"
    if not project_yml.is_file():
        print(f"Missing {project_yml} — run `npm run tauri ios init` in bibavpn-desktop first.", file=sys.stderr)
        sys.exit(1)

    raw = project_yml.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    targets = data.setdefault("targets", {})

    ios_targets = [k for k in targets if str(k).endswith("_iOS")]
    if len(ios_targets) != 1:
        print(f"Expected exactly one *_iOS target, got {ios_targets!r}", file=sys.stderr)
        sys.exit(1)
    main_key = ios_targets[0]

    tunnel_dependencies = [
        {"sdk": "NetworkExtension.framework"},
    ]

    fw_dir = gen_apple / "Frameworks" / "Tun2socks.xcframework"
    if fw_dir.is_dir():
        tunnel_dependencies.append({"framework": "Frameworks/Tun2socks.xcframework", "embed": False})

    tunnel_target = {
        "type": "app-extension",
        "platform": "iOS",
        "sources": [{"path": "BibaVpnTunnel"}],
        "settings": {
            "base": {
                "PRODUCT_BUNDLE_IDENTIFIER": "dev.bibavpn.desktop.BibaVpnTunnel",
                "INFOPLIST_FILE": "BibaVpnTunnel/Info.plist",
                "CODE_SIGN_ENTITLEMENTS": "BibaVpnTunnel/BibaVpnTunnel.entitlements",
                "SWIFT_OBJC_BRIDGING_HEADER": "BibaVpnTunnel/BibaVpnTunnel-Bridging-Header.h",
                "HEADER_SEARCH_PATHS": ["$(PROJECT_DIR)/BibaVpnTunnel/include"],
                "LIBRARY_SEARCH_PATHS": [
                    "$(PROJECT_DIR)/BibaVpnTunnel/rust-static/$(CONFIGURATION)-$(PLATFORM_NAME)"
                ],
                "OTHER_LDFLAGS": "-lbibavpn_ffi -lc++",
            }
        },
        "dependencies": tunnel_dependencies,
    }

    targets["BibaVpnTunnel"] = tunnel_target

    main = targets[main_key]
    main.setdefault("dependencies", [])
    main_deps = main["dependencies"]
    ne_sdk = {"sdk": "NetworkExtension.framework"}
    if not any(d == ne_sdk for d in main_deps):
        main_deps.append(ne_sdk)
    embed_tunnel = {"target": "BibaVpnTunnel", "embed": True}
    if not any(
        isinstance(d, dict)
        and d.get("target") == "BibaVpnTunnel"
        and d.get("embed") is True
        for d in main_deps
    ):
        main_deps.append(embed_tunnel)

    project_yml.write_text(yaml.dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"Merged BibaVpnTunnel into {project_yml} (host {main_key}).")


if __name__ == "__main__":
    main()
