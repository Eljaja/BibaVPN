package dev.bibavpn

enum class UnlockRestartEvent {
    SCREEN_ON,
    USER_PRESENT,
}

sealed class UnlockRestartDecision {
    data class Skip(val skipReason: String) : UnlockRestartDecision()
    data object Restart : UnlockRestartDecision()
}

object UnlockRestartPolicy {
    const val BOUNCE_THRESHOLD_MS = 500L
    const val THROTTLE_THRESHOLD_MS = 2500L

    fun decide(
        event: UnlockRestartEvent,
        nowElapsed: Long,
        lastScreenOffElapsed: Long,
        lastFullStackRestartElapsed: Long,
        allowRestart: Boolean,
        hasSavedConfig: Boolean,
    ): UnlockRestartDecision {
        if (!allowRestart) {
            return UnlockRestartDecision.Skip("allowRestart=false")
        }
        val sinceScreenOffMs = nowElapsed - lastScreenOffElapsed
        if (event == UnlockRestartEvent.SCREEN_ON && sinceScreenOffMs < BOUNCE_THRESHOLD_MS) {
            return UnlockRestartDecision.Skip("display bounce")
        }
        val sinceLastRestartMs = nowElapsed - lastFullStackRestartElapsed
        if (sinceLastRestartMs < THROTTLE_THRESHOLD_MS) {
            return UnlockRestartDecision.Skip("throttle")
        }
        if (!hasSavedConfig) {
            return UnlockRestartDecision.Skip("no saved config")
        }
        return UnlockRestartDecision.Restart
    }
}
