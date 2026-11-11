import dev.bibavpn.Tun2socksLifecycle
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Models the AAR's retained raw descriptor number; recycling changes what a raw close closes. */
private class DescriptorTable : AutoCloseable {
    private val file = File.createTempFile("biba-lifecycle-", ".tmp").apply { writeText("ok") }
    private val descriptors = mutableMapOf<Int, FileInputStream>()
    private val opened = mutableListOf<FileInputStream>()

    fun open(fd: Int): FileInputStream = FileInputStream(file).also {
        descriptors[fd] = it
        opened.add(it)
    }

    fun closeRaw(fd: Int) {
        descriptors.remove(fd)?.close()
    }

    override fun close() {
        opened.forEach { it.close() }
        check(file.delete())
    }
}

private fun await(latch: CountDownLatch) {
    check(latch.await(5, TimeUnit.SECONDS)) { "lifecycle operation did not reach its checkpoint" }
}

private fun join(thread: Thread, failure: AtomicReference<Throwable?>) {
    thread.join(5000)
    check(!thread.isAlive) { "lifecycle operation did not finish" }
    failure.get()?.let { throw AssertionError("lifecycle worker failed", it) }
}

private fun assertClosed(stream: FileInputStream) {
    try {
        stream.read()
        error("descriptor remained open")
    } catch (_: IOException) {
        // The actual stream owned by this descriptor was closed.
    }
}

private fun repeatedStopPreservesRecycledDescriptor() {
    DescriptorTable().use { fds ->
        val lifecycle = Tun2socksLifecycle { fds.closeRaw(127) }
        val session = checkNotNull(lifecycle.newSession())
        val original = fds.open(127)
        check(lifecycle.start(session, startEngine = {}, closeUnstarted = { original.close() }))
        check(lifecycle.isRunning(session))
        lifecycle.stop(session)
        check(!lifecycle.isRunning(session))
        assertClosed(original)
        val recycled = fds.open(127)
        lifecycle.stop(session)
        lifecycle.stop(session)
        check(recycled.read() == 'o'.code) { "repeated stop closed a recycled descriptor" }
    }
}

private fun cancelledStarterCannotOverlapOrStopNewSession() {
    DescriptorTable().use { fds ->
        var engineFd = 127
        val lifecycle = Tun2socksLifecycle { fds.closeRaw(engineFd) }
        val old = checkNotNull(lifecycle.newSession())
        val original = fds.open(127)
        val entered = CountDownLatch(1)
        val finishStart = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>(null)
        val result = AtomicReference<Boolean?>(null)
        val worker = Thread {
            try {
                result.set(lifecycle.start(old, startEngine = {
                    entered.countDown()
                    await(finishStart)
                }, closeUnstarted = { original.close() }))
            } catch (e: Throwable) {
                failure.set(e)
            }
        }.apply { isDaemon = true; start() }
        try {
            await(entered)
            lifecycle.stop(old)
            lifecycle.stop(old)
            check(lifecycle.newSession() == null) { "new engine admitted while cancelled start still owns it" }
        } finally {
            finishStart.countDown()
        }
        join(worker, failure)
        check(result.get() == false) { "cancelled start was reported as running" }
        check(!lifecycle.isRunning(old)) { "cancelled starter published a live tunnel" }
        assertClosed(original)

        val newer = checkNotNull(lifecycle.newSession())
        engineFd = 128
        val active = fds.open(128)
        check(lifecycle.start(newer, startEngine = {}, closeUnstarted = { active.close() }))
        lifecycle.stop(old)
        check(lifecycle.isRunning(newer)) { "stale cancellation changed newer session readiness" }
        check(active.read() == 'o'.code) { "old timeout stopped the newer global engine" }
        lifecycle.stop(newer)
        assertClosed(active)
    }
}

private fun cancellationBeforeWorkerClosesOnlyItsUnstartedDescriptor() {
    DescriptorTable().use { fds ->
        val lifecycle = Tun2socksLifecycle { fds.closeRaw(128) }
        val old = checkNotNull(lifecycle.newSession())
        val abandoned = fds.open(127)
        lifecycle.stop(old)
        val newer = checkNotNull(lifecycle.newSession())
        val active = fds.open(128)
        check(lifecycle.start(newer, startEngine = {}, closeUnstarted = { active.close() }))
        check(!lifecycle.start(old, startEngine = {
            error("cancelled worker entered native start")
        }, closeUnstarted = { abandoned.close() }))
        assertClosed(abandoned)
        lifecycle.stop(old)
        check(active.read() == 'o'.code) { "cancelled worker closed the newer engine descriptor" }
        lifecycle.stop(newer)
    }
}

private fun stopKeepsGlobalOwnershipUntilNativeShutdownCompletes() {
    DescriptorTable().use { fds ->
        val entered = CountDownLatch(1)
        val finishStop = CountDownLatch(1)
        val lifecycle = Tun2socksLifecycle {
            entered.countDown()
            await(finishStop)
            fds.closeRaw(127)
        }
        val session = checkNotNull(lifecycle.newSession())
        val original = fds.open(127)
        check(lifecycle.start(session, startEngine = {}, closeUnstarted = { original.close() }))
        val failure = AtomicReference<Throwable?>(null)
        val worker = Thread {
            try {
                lifecycle.stop(session)
            } catch (e: Throwable) {
                failure.set(e)
            }
        }.apply { isDaemon = true; start() }
        try {
            await(entered)
            check(lifecycle.newSession() == null) { "new start overlapped native stop" }
            lifecycle.stop(session)
            check(!lifecycle.isRunning(session)) { "stopping engine was reported as running" }
        } finally {
            finishStop.countDown()
        }
        join(worker, failure)
        assertClosed(original)
        val recycled = fds.open(127)
        lifecycle.stop(session)
        check(recycled.read() == 'o'.code) { "duplicate shutdown closed the recycled descriptor" }
        val next = checkNotNull(lifecycle.newSession())
        lifecycle.stop(next)
    }
}

private fun failedStartReleasesOnlyUnownedDescriptor() {
    DescriptorTable().use { fds ->
        val recycled = fds.open(127)
        val lifecycle = Tun2socksLifecycle { fds.closeRaw(127) }
        val session = checkNotNull(lifecycle.newSession())
        val unowned = fds.open(128)
        val expected = IllegalStateException("insert failed before native start")
        try {
            lifecycle.start(session, startEngine = { throw expected }, closeUnstarted = { unowned.close() })
            error("start failure was discarded")
        } catch (e: IllegalStateException) {
            check(e === expected)
        }
        assertClosed(unowned)
        lifecycle.stop(session)
        check(recycled.read() == 'o'.code) { "failed start stopped the retained previous native device" }
        val next = checkNotNull(lifecycle.newSession())
        lifecycle.stop(next)
    }
}

fun main() {
    repeatedStopPreservesRecycledDescriptor()
    cancelledStarterCannotOverlapOrStopNewSession()
    cancellationBeforeWorkerClosesOnlyItsUnstartedDescriptor()
    stopKeepsGlobalOwnershipUntilNativeShutdownCompletes()
    failedStartReleasesOnlyUnownedDescriptor()
    println("tun2socks lifecycle regressions passed")
}
