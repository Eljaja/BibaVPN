export function startVisiblePolling({
  target = document,
  task,
  intervalMs,
  setTimeoutFn = window.setTimeout.bind(window),
  clearTimeoutFn = window.clearTimeout.bind(window),
}) {
  let stopped = false;
  let inFlight = false;
  let timer = null;

  function clearTimer() {
    if (timer == null) return;
    clearTimeoutFn(timer);
    timer = null;
  }

  function schedule() {
    clearTimer();
    if (!stopped && target.visibilityState === "visible") {
      timer = setTimeoutFn(run, intervalMs);
    }
  }

  async function run() {
    clearTimer();
    if (stopped || inFlight || target.visibilityState !== "visible") return;
    inFlight = true;
    try {
      await task();
    } finally {
      inFlight = false;
      schedule();
    }
  }

  function onVisibilityChange() {
    if (target.visibilityState === "visible") run();
    else clearTimer();
  }

  target.addEventListener("visibilitychange", onVisibilityChange);
  run();
  return () => {
    stopped = true;
    clearTimer();
    target.removeEventListener("visibilitychange", onVisibilityChange);
  };
}
