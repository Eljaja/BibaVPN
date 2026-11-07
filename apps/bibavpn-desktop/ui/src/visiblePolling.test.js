import assert from "node:assert/strict";
import test from "node:test";
import { startVisiblePolling } from "./visiblePolling.js";

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function harness(initialVisibility = "visible") {
  const target = new EventTarget();
  target.visibilityState = initialVisibility;
  const timers = new Map();
  let nextId = 1;
  return {
    target,
    timers,
    setTimeoutFn(fn) {
      const id = nextId++;
      timers.set(id, fn);
      return id;
    },
    clearTimeoutFn(id) { timers.delete(id); },
    setVisibility(value) {
      target.visibilityState = value;
      target.dispatchEvent(new Event("visibilitychange"));
    },
  };
}

test("visible polling pauses while hidden and runs immediately when visible again", async () => {
  const h = harness("hidden");
  let calls = 0;
  const stop = startVisiblePolling({
    target: h.target,
    task: async () => { calls += 1; },
    intervalMs: 1000,
    setTimeoutFn: h.setTimeoutFn,
    clearTimeoutFn: h.clearTimeoutFn,
  });

  assert.equal(calls, 0);
  assert.equal(h.timers.size, 0);
  h.setVisibility("visible");
  await Promise.resolve();
  assert.equal(calls, 1);
  assert.equal(h.timers.size, 1);
  h.setVisibility("hidden");
  assert.equal(h.timers.size, 0);
  stop();
});

test("visible polling never overlaps a pending task", async () => {
  const h = harness();
  const pending = deferred();
  let calls = 0;
  const stop = startVisiblePolling({
    target: h.target,
    task: () => { calls += 1; return pending.promise; },
    intervalMs: 1000,
    setTimeoutFn: h.setTimeoutFn,
    clearTimeoutFn: h.clearTimeoutFn,
  });

  assert.equal(calls, 1);
  h.setVisibility("hidden");
  h.setVisibility("visible");
  assert.equal(calls, 1);
  pending.resolve();
  await Promise.resolve();
  assert.equal(h.timers.size, 1);
  stop();
});

test("repeated visible events keep only one scheduled poll", async () => {
  const h = harness();
  let calls = 0;
  const stop = startVisiblePolling({
    target: h.target,
    task: async () => { calls += 1; },
    intervalMs: 1000,
    setTimeoutFn: h.setTimeoutFn,
    clearTimeoutFn: h.clearTimeoutFn,
  });
  await Promise.resolve();
  assert.equal(h.timers.size, 1);

  h.setVisibility("visible");
  await Promise.resolve();
  assert.equal(calls, 2);
  assert.equal(h.timers.size, 1);
  stop();
});

test("next poll runs normally and cleanup while in flight leaves no work", async () => {
  const h = harness();
  const second = deferred();
  let calls = 0;
  const stop = startVisiblePolling({
    target: h.target,
    task: () => {
      calls += 1;
      return calls === 1 ? Promise.resolve() : second.promise;
    },
    intervalMs: 1000,
    setTimeoutFn: h.setTimeoutFn,
    clearTimeoutFn: h.clearTimeoutFn,
  });
  await Promise.resolve();
  const [timer] = h.timers.values();
  h.timers.clear();
  timer();
  assert.equal(calls, 2);

  stop();
  second.resolve();
  await Promise.resolve();
  assert.equal(h.timers.size, 0);
  h.setVisibility("visible");
  assert.equal(calls, 2);
});
