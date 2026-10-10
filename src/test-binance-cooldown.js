import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import crypto from 'node:crypto';

const source = fs.readFileSync(new URL('./server.js', import.meta.url), 'utf8');
const start = source.indexOf('let binanceRetryAt =');
const end = source.indexOf('async function verifyCoinalyze', start);
let now = 1791665443441 + 1000;
let calls = 0;
let saved = 0;
let responseStatus = 418;
const banUntil = now + 3600000;
const context = vm.createContext({
  Date: class extends Date { static now() { return now; } },
  crypto,
  cleanProviderMessage: value => value,
  query: async (_sql, params) => {
    if (params) { saved = JSON.parse(params[0]).retryAt; return { rows: [] }; }
    return { rows: saved ? [{ details: { retryAt: saved } }] : [] };
  },
  fetchWithTimeout: async () => {
    calls++;
    return { ok: responseStatus === 200, status: responseStatus,
      headers: { get: () => null },
      json: async () => ({ msg: `IP banned until ${banUntil}` }) };
  }
});
vm.runInContext(source.slice(start, end), context);
const check = () => context.verifyBinanceFutures('test-key', 'test-secret');
assert.equal((await check()).status, 'failed');
assert.equal(saved, banUntil);
assert.equal(calls, 1);
assert.match((await check()).message, /cooldown/);
assert.equal(calls, 1, 'Cooldown must suppress further provider calls');
now = banUntil + 1;
responseStatus = 200;
assert.equal((await check()).status, 'verified');
assert.equal(calls, 2);
console.log('Ban persistence, request suppression and expiry recovery passed.');
