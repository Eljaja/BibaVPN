import dev.bibavpn.UnlockRestartDecision
import dev.bibavpn.UnlockRestartEvent
import dev.bibavpn.UnlockRestartPolicy

private fun assertSkip(
    label: String,
    event: UnlockRestartEvent,
    now: Long,
    lastOff: Long,
    lastRestart: Long,
    allow: Boolean = true,
    hasConfig: Boolean = true,
) {
    val d =
        UnlockRestartPolicy.decide(
            event = event,
            nowElapsed = now,
            lastScreenOffElapsed = lastOff,
            lastFullStackRestartElapsed = lastRestart,
            allowRestart = allow,
            hasSavedConfig = hasConfig,
        )
    if (d !is UnlockRestartDecision.Skip) {
        throw AssertionError("$label: expected Skip, got $d")
    }
}

private fun assertRestart(
    label: String,
    event: UnlockRestartEvent,
    now: Long,
    lastOff: Long,
    lastRestart: Long,
    allow: Boolean = true,
    hasConfig: Boolean = true,
) {
    val d =
        UnlockRestartPolicy.decide(
            event = event,
            nowElapsed = now,
            lastScreenOffElapsed = lastOff,
            lastFullStackRestartElapsed = lastRestart,
            allowRestart = allow,
            hasSavedConfig = hasConfig,
        )
    if (d !is UnlockRestartDecision.Restart) {
        throw AssertionError("$label: expected Restart, got $d")
    }
}

fun main() {
    // SCREEN_ON bounce: 0 ms and 499 ms since SCREEN_OFF
    assertSkip("bounce_0", UnlockRestartEvent.SCREEN_ON, now = 1000, lastOff = 1000, lastRestart = 0)
    assertSkip("bounce_499", UnlockRestartEvent.SCREEN_ON, now = 1499, lastOff = 1000, lastRestart = 0)

    // 500 ms boundary — not bounce; last restart ≥ 2500 ms ago
    assertRestart(
        "boundary_500",
        UnlockRestartEvent.SCREEN_ON,
        now = 5000,
        lastOff = 4500,
        lastRestart = 2500,
    )

    // USER_PRESENT inside bounce window — must not bounce; last restart ≥ 2500 ms ago
    assertRestart(
        "user_present_in_bounce",
        UnlockRestartEvent.USER_PRESENT,
        now = 5000,
        lastOff = 4900,
        lastRestart = 2500,
    )

    // Throttle at 2499 ms since last restart
    assertSkip(
        "throttle_2499",
        UnlockRestartEvent.SCREEN_ON,
        now = 6000,
        lastOff = 0,
        lastRestart = 3501,
    )

    // allowRestart=false
    assertSkip(
        "disabled",
        UnlockRestartEvent.SCREEN_ON,
        now = 6000,
        lastOff = 0,
        lastRestart = 0,
        allow = false,
    )

    // missing config
    assertSkip(
        "no_config",
        UnlockRestartEvent.SCREEN_ON,
        now = 6000,
        lastOff = 0,
        lastRestart = 0,
        hasConfig = false,
    )

    println("ok")
}
