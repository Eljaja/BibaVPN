import Darwin
import Foundation
import NetworkExtension

/// Packet Tunnel endpoint for BibaVPN — SOCKS/WSS core runs in Rust (`bibavpn_ffi`), identical JSON shape as Android `nativeStart`.
///
/// **Packet forwarding**: on Android, tun2socks bridges `VpnService` TUN fd ↔ SOCKS. On iOS you still need the equivalent bridge:
/// build [`../../../scripts/build-tun2socks-ios-gomobile.sh`](../../../scripts/build-tun2socks-ios-gomobile.sh), embed `Tun2socks.xcframework`,
/// then extend `completeTunnelForwarding(...)` with the generated Engine API (`gomobile bind ./engine` — verify Swift symbols).
final class PacketTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(options _: [String: NSObjectProtocol]?, completionHandler: @escaping (Error?) -> Void) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol else {
            completionHandler(NSError(domain: "BibaVPN", code: 1, userInfo: [NSLocalizedDescriptionKey: "Not NETunnelProviderProtocol"]))
            return
        }

        let cfgJson = (proto.providerConfiguration?["sessionJson"] as? String) ?? "{}"

        var errOut: UnsafeMutablePointer<CChar>?
        let rc = cfgJson.withCString { bibavpn_ffi_start($0, &errOut) }
        if rc != 0 {
            let msg: String
            if let p = errOut {
                msg = String(cString: p)
                bibavpn_ffi_string_free(p)
            } else {
                msg = "bibavpn_ffi_start rc=\(rc)"
            }
            completionHandler(NSError(domain: "BibaVPN", code: Int(rc), userInfo: [NSLocalizedDescriptionKey: msg]))
            return
        }

        guard let tunNetworkSettings = Self.buildTunnelNetworkSettings(sessionJson: cfgJson) else {
            bibavpn_ffi_stop()
            completionHandler(NSError(domain: "BibaVPN", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid tunnel settings"]))
            return
        }

        setTunnelNetworkSettings(tunNetworkSettings) { err in
            if let err {
                bibavpn_ffi_stop()
                completionHandler(err)
                return
            }
            self.completeTunnelForwarding(sessionJson: cfgJson, completionHandler: completionHandler)
        }
    }

    /// Stub until Tun2socks (or another stack) wires `packetFlow`/`fd:` correctly on iOS.
    private func completeTunnelForwarding(sessionJson: String, completionHandler: @escaping (Error?) -> Void) {
        // Example proxy URL after parity inject (`socks_auth_*`, like [`BibaVpnService.kt`](../../android-bibavpn-extras/java/dev/bibavpn/BibaVpnService.kt)):
        _ = Self.tun2socksProxyURL(fromSessionJson: sessionJson)
        NSLog("[BibaVPN] Tunnel Rust SOCKS ready — Tun2socks not wired; refusing Connected without forwarding")

        bibavpn_ffi_stop()
        let msg =
            "Packet forwarding is not implemented on iOS (Tun2socks not wired). The tunnel cannot start."
        completionHandler(
            NSError(
                domain: "BibaVPN",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: msg],
            ),
        )
    }

    override func stopTunnel(with _: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        bibavpn_ffi_stop()
        completionHandler()
    }

    private static func buildTunnelNetworkSettings(sessionJson: String) -> NEPacketTunnelNetworkSettings? {
        guard let root = parseJsonObject(sessionJson) else { return nil }

        let mtu = 1400
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "192.0.2.1")

        let localIp = "10.10.0.2"
        let ipv4 = NEIPv4Settings(addresses: [localIp], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route.default()]

        var excluded: [NEIPv4Route] = []
        if let host = (root["server_host"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines), !host.isEmpty {
            let ips = resolveIPv4Addresses(host: host)
            if ips.isEmpty {
                NSLog("[BibaVPN] warning: server_host \"\(host)\" has no IPv4 for excludedRoutes — risk of routing loop to VPN server (use IP or fix DNS)")
            }
            for ip in ips {
                excluded.append(NEIPv4Route(destinationAddress: ip, subnetMask: "255.255.255.255"))
            }
        }
        ipv4.excludedRoutes = excluded
        settings.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: ["8.8.8.8", "1.1.1.1"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        settings.mtu = NSNumber(value: mtu)

        return settings
    }

    private static func parseJsonObject(_ s: String) -> [String: Any]? {
        guard let d = s.data(using: .utf8),
              let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any]
        else {
            return nil
        }
        return o
    }

    private static func tun2socksProxyURL(fromSessionJson json: String) -> String {
        guard let o = parseJsonObject(json) else {
            return "socks5://127.0.0.1:1080"
        }
        let rawBind = (o["socks_bind"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty ?? "127.0.0.1:1080"
        let hostPort = rawBind.replacingOccurrences(of: "socks5://", with: "", options: .caseInsensitive)
        let u = (o["socks_auth_user"] as? String) ?? ""
        let p = (o["socks_auth_password"] as? String) ?? ""
        guard !u.isEmpty, !p.isEmpty else {
            NSLog("[BibaVPN] socks_auth missing in session JSON — Tun2socks URL incomplete")
            return "socks5://\(hostPort)"
        }
        return "socks5://\(u):\(p)@\(hostPort)"
    }

    private static func resolveIPv4Addresses(host: String) -> [String] {
        var hints = addrinfo(
            ai_flags: AI_ADDRCONFIG,
            ai_family: AF_INET,
            ai_socktype: SOCK_STREAM,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil,
        )
        var result: UnsafeMutablePointer<addrinfo>?
        let rc = host.withCString { getaddrinfo($0, nil, &hints, &result) }
        guard rc == 0, let first = result else { return [] }
        defer { freeaddrinfo(first) }

        var ips: [String] = []
        var rp: UnsafeMutablePointer<addrinfo>? = first
        while let p = rp {
            if let addr = p.pointee.ai_addr {
                var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(
                    addr,
                    p.pointee.ai_addrlen,
                    &hostname,
                    socklen_t(hostname.count),
                    nil,
                    0,
                    NI_NUMERICHOST,
                ) == 0 {
                    ips.append(String(cString: hostname))
                }
            }
            rp = p.pointee.ai_next
        }
        return ips
    }
}

private extension String {
    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}
