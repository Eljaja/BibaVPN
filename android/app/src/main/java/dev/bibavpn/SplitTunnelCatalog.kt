package dev.bibavpn

import androidx.annotation.StringRes

/** Группы для UI раздельного туннеля (прямой IP минуя VPN). */
enum class SplitTunnelGroup(@StringRes val titleRes: Int) {
    GOVERNMENT(R.string.split_group_government),
    BANKS(R.string.split_group_banks),
    MARKETPLACES(R.string.split_group_marketplaces),
}

data class SplitTunnelApp(
    val packageName: String,
    @StringRes val labelRes: Int,
    val group: SplitTunnelGroup,
)

/** Статический каталог известных приложений (имена пакетов — как в Google Play / RuStore). */
object SplitTunnelCatalog {
    val all: List<SplitTunnelApp> =
        listOf(
            SplitTunnelApp("ru.rostel", R.string.split_app_gosuslugi, SplitTunnelGroup.GOVERNMENT),
            SplitTunnelApp("ru.oneme.app", R.string.split_app_max, SplitTunnelGroup.GOVERNMENT),
            SplitTunnelApp("com.vkontakte.android", R.string.split_app_vk, SplitTunnelGroup.GOVERNMENT),
            SplitTunnelApp("com.idamob.tinkoff.android", R.string.split_app_tinkoff, SplitTunnelGroup.BANKS),
            SplitTunnelApp("ru.sberbankmobile", R.string.split_app_sber, SplitTunnelGroup.BANKS),
            SplitTunnelApp("com.yandex.bank", R.string.split_app_yandex_bank, SplitTunnelGroup.BANKS),
            SplitTunnelApp("ru.banki.banki", R.string.split_app_banki, SplitTunnelGroup.BANKS),
            SplitTunnelApp("ge.bog.mobilebank", R.string.split_app_bog, SplitTunnelGroup.BANKS),
            SplitTunnelApp("ru.vtb24.mobilebanking.android", R.string.split_app_vtb, SplitTunnelGroup.BANKS),
            SplitTunnelApp("ru.alfabank.mobile.android", R.string.split_app_alfa, SplitTunnelGroup.BANKS),
            SplitTunnelApp("ru.ozon.app.android", R.string.split_app_ozon, SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("ru.beru.android", R.string.split_app_beru, SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("com.valvesoftware.android.steam.community", R.string.split_app_steam, SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("ru.yandex.taxi", R.string.split_app_yango, SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("ru.yandex.vezet", R.string.split_app_vezet, SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("com.deliveryclub", R.string.split_app_deliveryclub, SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("ru.yandex.eda", R.string.split_app_eda, SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("com.yandex.lavka", R.string.split_app_lavka, SplitTunnelGroup.MARKETPLACES),
            SplitTunnelApp("ru.sbcs.store", R.string.split_app_samokat, SplitTunnelGroup.MARKETPLACES),
        )

    fun allPackageNames(): Set<String> = all.map { it.packageName }.toSet()

    fun forGroup(group: SplitTunnelGroup): List<SplitTunnelApp> = all.filter { it.group == group }
}
