import test from 'node:test';
import assert from 'node:assert/strict';
import { acceptSnapshot, tunnelStatusChanged } from './vpnState.js';

test('snapshots cannot be rolled back by late events or command replies', () => {
  const current = { revision: 12, connected: true };
  assert.equal(acceptSnapshot(current, { revision: 11, connected: false }), current);
  assert.deepEqual(acceptSnapshot(current, { revision: 13, connected: false }), { revision: 13, connected: false });
});

test('one status observer requests a full snapshot for connection and error transitions', () => {
  const snapshot = { connected: false, error: null, tunnelServer: 'server' };
  assert.equal(tunnelStatusChanged(snapshot, { connected: true }), true);
  assert.equal(tunnelStatusChanged(snapshot, { connected: false, error: 'denied' }), true);
  assert.equal(tunnelStatusChanged(snapshot, { connected: false }), false);
  assert.equal(tunnelStatusChanged(snapshot, null), false);
});

test('pending phases keep refreshing until native shutdown or bootstrap settles', () => {
  for (const phase of ['connecting', 'disconnecting', 'reconnecting']) {
    assert.equal(tunnelStatusChanged({ connected: false, phase }, { connected: false }), true);
  }
  assert.equal(tunnelStatusChanged({ connected: false, phase: 'idle' }, { connected: false }), false);
});

test('session clock survives tab changes and resumes from native uptime', async () => {
  const { sessionStart } = await import('./vpnState.js');
  assert.equal(sessionStart(null, { connected: true, vpnSessionUptimeSecs: 8 }, 100000), 92000);
  assert.equal(sessionStart({ connected: true, sessionStartedAt: 92000 }, { connected: true }, 150000), 92000);
  assert.equal(sessionStart({ connected: true, sessionStartedAt: 92000 }, { connected: false }, 150000), null);
});
