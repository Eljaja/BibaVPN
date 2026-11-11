package dev.bibavpn

/** Owns the process-global Go engine, whose Stop retains a raw fd and is not idempotent. */
internal class Tun2socksLifecycle(private val stopEngine: () -> Unit) {
    internal enum class Phase { PENDING, CANCELLED, STARTING, RUNNING, STOPPING, CLOSED }

    class Session internal constructor() {
        internal var phase = Phase.PENDING
        internal var cancelled = false
    }

    private val lock = Any()
    private var current: Session? = null

    fun newSession(): Session? = synchronized(lock) {
        if (current != null) null else Session().also { current = it }
    }

    /** The worker alone closes an unstarted fd; a successful native start transfers ownership. */
    fun start(session: Session, startEngine: () -> Unit, closeUnstarted: () -> Unit): Boolean {
        val shouldStart = synchronized(lock) {
            when (session.phase) {
                Phase.PENDING -> {
                    check(current === session)
                    session.phase = Phase.STARTING
                    true
                }
                Phase.CANCELLED -> {
                    session.phase = Phase.CLOSED
                    false
                }
                else -> error("tun2socks session already started")
            }
        }
        if (!shouldStart) {
            closeUnstarted()
            return false
        }
        try {
            startEngine()
        } catch (e: Throwable) {
            try {
                closeUnstarted()
            } catch (closeError: Throwable) {
                e.addSuppressed(closeError)
            } finally {
                finishSession(session)
            }
            throw e
        }
        val cancelled = synchronized(lock) {
            session.phase = if (session.cancelled) Phase.STOPPING else Phase.RUNNING
            session.cancelled
        }
        if (cancelled) finishStop(session)
        return !cancelled
    }

    /** Cancellation never waits for native Start; that worker must stop before releasing its slot. */
    fun stop(session: Session) {
        val shouldStop = synchronized(lock) {
            session.cancelled = true
            when (session.phase) {
                Phase.PENDING -> {
                    session.phase = Phase.CANCELLED
                    current = null
                    false
                }
                Phase.RUNNING -> {
                    session.phase = Phase.STOPPING
                    true
                }
                else -> false
            }
        }
        if (shouldStop) finishStop(session)
    }

    fun isRunning(session: Session): Boolean = synchronized(lock) {
        current === session && session.phase == Phase.RUNNING
    }

    private fun finishStop(session: Session) {
        try {
            stopEngine()
        } finally {
            finishSession(session)
        }
    }

    private fun finishSession(session: Session) = synchronized(lock) {
        check(current === session)
        session.phase = Phase.CLOSED
        current = null
    }
}
