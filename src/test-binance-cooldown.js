import assert from 'node:assert/strict';
import { verifyViaWorker } from './binance-verification.js';
let calls=0;
const query=async sql=>{
  calls++;
  assert.ok(sql.includes('system_migrations'),'Ban must block before enqueueing');
  return {rows:[{details:{retryAt:Date.now()+3600000}}]};
};
assert.equal((await verifyViaWorker(query,'not-sent','not-sent')).status,'failed');
assert.equal(calls,1);
console.log('PASS: persisted ban blocks verification before any credentials are queued or sent.');
