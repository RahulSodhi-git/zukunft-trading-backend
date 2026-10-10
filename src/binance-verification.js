import crypto from 'node:crypto';
import { encryptForWorker } from './worker-platform.js';

// Verification is performed only by the read-only Oracle verifier. Never fall back
// to Render egress, and never persist plaintext keys or unverified trading keys.
export async function verifyViaWorker(query, apiKey, apiSecret, options = {}) {
  const wait = options.wait || (ms => new Promise(resolve => setTimeout(resolve, ms)));
  const attempts = options.attempts ?? 30;
  const saved = await query("select details from system_migrations where key='binance_request_cooldown'");
  // Preserve the previously reported ban even if it was only held in the old
  // process memory. This migration must not be used to evade a provider ban.
  const retryAt = Math.max(1791665443441, Number(saved.rows[0]?.details?.retryAt || 0));
  if ((options.now || Date.now)() < retryAt) return { status:'failed', message:`Binance cooldown. Retry after ${new Date(retryAt).toISOString()}. No verification request was sent; your existing keys are unchanged.` };
  const id = crypto.randomUUID();
  const ciphertext = encryptForWorker({ apiKey, apiSecret });
  await query('insert into binance_verification_jobs (id,ciphertext) values ($1,$2)', [id,ciphertext]);
  try {
    for (let index=0; index<attempts; index++) {
      await wait(1000);
      const response = await query('select result from binance_verification_jobs where id=$1', [id]);
      if (response.rows[0]?.result) return response.rows[0].result;
    }
    return { status:'failed', message:'Could not load your Binance account: the connection service is busy or unavailable. Your keys were not saved. Please try again later.' };
  } finally {
    await query('delete from binance_verification_jobs where id=$1', [id]);
  }
}
