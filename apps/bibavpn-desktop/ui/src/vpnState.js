export function acceptSnapshot(current, next) {
  if (current && next.revision < current.revision) return current;
  return next;
}

export function tunnelStatusChanged(snapshot, status) {
  if (!snapshot || !status) return false;
  return status.connected !== snapshot.connected ||
    Boolean(status.error && status.error !== snapshot.error);
}

export function sessionStart(current, next, now) {
  if (!next.connected) return null;
  if (typeof next.vpnSessionUptimeSecs === "number") return now - next.vpnSessionUptimeSecs * 1000;
  return current?.connected ? current.sessionStartedAt ?? now : now;
}
