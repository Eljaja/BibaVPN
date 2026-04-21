package dev.bibavpn

/**
 * Официальные и часто используемые хосты операторов (для справки в UI).
 * Сплит-туннель в Android обходит VPN только для **приложений** ([addDisallowedApplication]);
 * трафик браузера к этим доменам не исключается автоматически.
 */
object SplitTunnelOperatorDomains {
    val megafonHosts: List<String> =
        listOf(
            "api.megafon.ru",
            "corp.megafon.ru",
            "dom.megafon.ru",
            "drive.megafon.ru",
            "lk.megafon.ru",
            "megafon.ru",
            "megafon.tv",
            "payment.megafon.ru",
            "static.megafon.ru",
            "tv.megafon.tv",
            "www.megafon.ru",
            "www.megafon.tv",
        ).distinct().sorted()

    val yotaHosts: List<String> =
        listOf(
            "api.yota.ru",
            "my.yota.ru",
            "shop.yota.ru",
            "static.yota.ru",
            "www.yota.ru",
            "yota.ru",
        ).distinct().sorted()
}
