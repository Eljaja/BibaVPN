package dev.bibavpn.core

import android.net.VpnService

/**
 * Исходящие TCP к VPN-серверу должны вызывать [VpnService.protect] до connect.
 * Иначе на части прошивок сокет уходит в TUN и туннель «умирает» после сна/разблокировки,
 * даже при [android.net.VpnService.Builder.addDisallowedApplication].
 */
object VpnProtect {
    @Volatile
    var vpn: VpnService? = null

    @JvmStatic
    fun protectFd(fd: Int): Boolean {
        val s = vpn ?: return false
        return s.protect(fd)
    }
}
