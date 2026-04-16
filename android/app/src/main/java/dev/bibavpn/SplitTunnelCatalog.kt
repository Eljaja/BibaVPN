package dev.bibavpn

/** Группы для UI раздельного туннеля (прямой IP минуя VPN). */
enum class SplitTunnelGroup(val title: String) {
    GOVERNMENT("Государственные"),
    BANKS("Банки"),
    MARKETPLACES("Маркетплейсы"),
}

data class SplitTunnelApp(
    val packageName: String,
    val label: String,
    val group: SplitTunnelGroup,
)

/** Статический каталог известных приложений (имена пакетов — как в Google Play / RuStore). */
object SplitTunnelCatalog {
    val all: List<SplitTunnelApp> =
        listOf(
            SplitTunnelApp("ru.rostel", "Госуслуги", SplitTunnelGroup.GOVERNMENT),
            SplitTunnelApp("ru.oneme.app", "MAX", SplitTunnelGroup.GOVERNMENT),
            SplitTunnelApp("com.vkontakte.android", "ВКонтакте", SplitTunnelGroup.GOVERNMENT),
            SplitTunnelApp("com.idamob.tinkoff.android", "Тинькофф", SplitTunnelGroup.BANKS),
            SplitTunnelApp("ru.sberbankmobile", "Сбербанк", SplitTunnelGroup.BANKS),
            SplitTunnelApp("com.yandex.bank", "Яндекс Банк", SplitTunnelGroup.BANKS),
            SplitTunnelApp("ru.banki.banki", "Банки.ру", SplitTunnelGroup.BANKS),
            SplitTunnelApp("ge.bog.mobilebank", "Bank of Georgia", SplitTunnelGroup.BANKS),
            SplitTunnelApp("ru.vtb24.mobilebanking.android", "ВТБ Онлайн", SplitTunnelGroup.BANKS),
            SplitTunnelApp("ru.alfabank.mobile.android", "Альфа-Банк", SplitTunnelGroup.BANKS),
            SplitTunnelApp("ru.ozon.app.android", "Ozon", SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("ru.beru.android", "Яндекс Маркет", SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("com.valvesoftware.android.steam.community", "Steam", SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("ru.yandex.taxi", "Яндекс Go", SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("ru.yandex.vezet", "Яндекс Везёт", SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("com.deliveryclub", "Delivery Club", SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("ru.yandex.eda", "Яндекс Еда", SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("com.yandex.lavka", "Яндекс Лавка", SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("ru.sbcs.store", "Самокат", SplitTunnelGroup.MARKETPLACES),
        )

    fun allPackageNames(): Set<String> = all.map { it.packageName }.toSet()

    fun forGroup(group: SplitTunnelGroup): List<SplitTunnelApp> = all.filter { it.group == group }
}
