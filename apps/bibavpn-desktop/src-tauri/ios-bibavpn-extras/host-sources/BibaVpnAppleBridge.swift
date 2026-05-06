import Darwin
import Foundation
import NetworkExtension

private let kAppGroup = "group.dev.bibavpn.desktop"
private let kTunnelStarted = "bibavpn_tunnel_started_at"
private let tunnelBundleId = "dev.bibavpn.desktop.BibaVpnTunnel"

/// Rust (`bibavpn-desktop` iOS) calls these `@_cdecl` symbols — link this Swift file into the **host** Tauri app target only.

@_cdecl("bibavpn_ios_tunnel_connect")
public func bibavpn_ios_tunnel_connect(_ jsonUtf8: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let jsonUtf8 else {
        return strdup("null json")
    }
    let json = String(cString: jsonUtf8)

    let sem = DispatchSemaphore(value: 0)
    var errPtr: UnsafeMutablePointer<CChar>?

    NETunnelProviderManager.loadAllFromPreferences { managers, error in
        if let error {
            errPtr = strdup(error.localizedDescription)
            sem.signal()
            return
        }

        let manager: NETunnelProviderManager = {
            if let existing = managers?.first(where: {
                guard let p = $0.protocolConfiguration as? NETunnelProviderProtocol else { return false }
                return p.providerBundleIdentifier == tunnelBundleId
            }) {
                return existing
            }
            return NETunnelProviderManager()
        }()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = tunnelBundleId
        proto.serverAddress = "BibaVPN"
        proto.providerConfiguration = ["sessionJson": json]
        manager.protocolConfiguration = proto
        manager.localizedDescription = "BibaVPN"
        manager.isEnabled = true

        manager.saveToPreferences { saveErr in
            if let saveErr {
                errPtr = strdup(saveErr.localizedDescription)
                sem.signal()
                return
            }
            manager.loadFromPreferences { loadErr in
                if let loadErr {
                    errPtr = strdup(loadErr.localizedDescription)
                    sem.signal()
                    return
                }
                do {
                    try manager.connection.startVPNTunnel()
                    UserDefaults(suiteName: kAppGroup)?.set(CFAbsoluteTimeGetCurrent(), forKey: kTunnelStarted)
                    errPtr = nil
                } catch {
                    errPtr = strdup(error.localizedDescription)
                }
                sem.signal()
            }
        }
    }

    sem.wait()
    return errPtr
}

@_cdecl("bibavpn_ios_tunnel_disconnect")
public func bibavpn_ios_tunnel_disconnect() {
    let sem = DispatchSemaphore(value: 0)
    NETunnelProviderManager.loadAllFromPreferences { managers, _ in
        managers?.forEach { m in
            guard let p = m.protocolConfiguration as? NETunnelProviderProtocol else { return }
            if p.providerBundleIdentifier == tunnelBundleId {
                m.connection.stopVPNTunnel()
            }
        }
        UserDefaults(suiteName: kAppGroup)?.removeObject(forKey: kTunnelStarted)
        sem.signal()
    }
    sem.wait()
}

@_cdecl("bibavpn_ios_tunnel_is_active")
public func bibavpn_ios_tunnel_is_active() -> Bool {
    let sem = DispatchSemaphore(value: 0)
    var on = false
    NETunnelProviderManager.loadAllFromPreferences { managers, _ in
        defer { sem.signal() }
        guard let managers else { return }
        for m in managers {
            guard let p = m.protocolConfiguration as? NETunnelProviderProtocol else { continue }
            guard p.providerBundleIdentifier == tunnelBundleId else { continue }
            switch m.connection.status {
            case .connected, .connecting, .reasserting:
                on = true
            default:
                break
            }
            break
        }
    }
    sem.wait()
    return on
}

@_cdecl("bibavpn_ios_tunnel_session_elapsed_ms")
public func bibavpn_ios_tunnel_session_elapsed_ms() -> UInt64 {
    guard let t = UserDefaults(suiteName: kAppGroup)?.double(forKey: kTunnelStarted), t > 0 else {
        return 0
    }
    let ms = (CFAbsoluteTimeGetCurrent() - t) * 1000
    return UInt64(max(0, ms))
}
