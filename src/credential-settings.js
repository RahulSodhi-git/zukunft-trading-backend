import { z } from "zod";
import { storeWorkerCredential } from "./worker-platform.js";

const schemas = {
  binance: z.object({ binanceApiKey: z.string().trim().min(16).max(128), binanceApiSecret: z.string().trim().min(16).max(128) }).strict(),
  coinalyze: z.object({ coinalyzeApiKey: z.string().trim().min(12).max(256) }).strict()
};

export function checkReplacement(row, provider, settingsOnly = false) {
  const exists = Boolean(row?.[`${provider}_ciphertext`]);
  if (settingsOnly && !exists && row?.[`${provider}_status`] !== "verified") {
    throw Object.assign(new Error("Connect this service during initial setup first."), { status: 409 });
  }
  if (!exists) return;
  const age = Date.now() - new Date(row.heartbeat_at || 0).getTime();
  if (row.desired_state === "running" || !["paused", "stopped"].includes(row.actual_state)
      || row.credential_version !== row.snapshot_version
      || !Number.isFinite(age) || age < 0 || age > 90000 || Number(row.open_count || 0) !== 0) {
    throw Object.assign(new Error("Pause entries and wait until all positions are closed and the worker confirms paused/stopped before changing API keys."), { status: 409 });
  }
}

export function connectionStatus(row) {
  const binanceConnected = Boolean(row?.binance_ciphertext) && row?.binance_status === "verified";
  const coinalyzeConnected = Boolean(row?.coinalyze_ciphertext) && row?.coinalyze_status === "verified";
  // API setup is independent of capital, worker provisioning and trade execution.
  return { binanceConnected, coinalyzeConnected, connectionsComplete: binanceConnected && coinalyzeConnected };
}

async function connectionRow(query, userId, lock = false) {
  const result = await query(`select s.*,c.binance_ciphertext,c.coinalyze_ciphertext,c.credential_version,
    x.credential_version as snapshot_version,x.actual_state,x.heartbeat_at,coalesce(jsonb_array_length(x.open_positions),0) as open_count
    from client_bot_setups s left join client_bot_credentials c on c.user_id=s.user_id
    left join client_bot_snapshots x on x.user_id=s.user_id where s.user_id=$1
    ${lock ? "for update of s" : ""}`, [userId]);
  return result.rows[0];
}

export function registerCredentialSettings({ app, query, transaction, auth, requireActivePayment,
  asyncRoute, verifyBinanceFutures, verifyCoinalyze }) {
  app.get("/settings/connections", auth, requireActivePayment, asyncRoute(async (req, res) => {
    const row = await connectionRow(query, req.userId);
    let canReplace = true;
    for (const provider of ["binance", "coinalyze"]) {
      try { checkReplacement(row, provider); } catch { canReplace = false; }
    }
    res.json({ connections: {
      ...connectionStatus(row),
      canReplace, message: canReplace ? "Enter new keys to replace an existing connection. Saved keys are never displayed."
        : "Pause entries and wait for all positions to close before replacing keys."
    } });
  }));

  for (const provider of ["binance", "coinalyze"]) {
    app.post([`/onboarding/${provider}`, `/settings/${provider}`], auth, requireActivePayment,
      asyncRoute(async (req, res) => {
        const input = schemas[provider].parse(req.body);
        const settingsOnly = req.path.startsWith("/settings/");
        checkReplacement(await connectionRow(query, req.userId), provider, settingsOnly);
        let verified;
        try {
          verified = provider === "binance"
            ? await verifyBinanceFutures(input.binanceApiKey, input.binanceApiSecret)
            : await verifyCoinalyze(input.coinalyzeApiKey);
        } catch {
          return res.status(502).json({ error: "Connection verification unavailable. Existing credentials are unchanged." });
        }
        if (verified.status !== "verified") {
          return res.status(400).json({ error: verified.message || "Verification failed. Existing credentials are unchanged." });
        }
        const setup = await transaction(async client => {
          const tx = (sql, values) => client.query(sql, values);
          await tx("insert into client_bot_setups (user_id) values ($1) on conflict (user_id) do nothing", [req.userId]);
          checkReplacement(await connectionRow(tx, req.userId, true), provider, settingsOnly);
          await storeWorkerCredential(tx, req.userId, provider, provider === "binance"
            ? { apiKey: input.binanceApiKey, apiSecret: input.binanceApiSecret } : { apiKey: input.coinalyzeApiKey });
          const result = await tx(`update client_bot_setups set ${provider}_status='verified',
            ${provider}_message=$2,${provider}_checked_at=now(),desired_state='paused',
            provisioning_status='pending',updated_at=now() where user_id=$1 returning *`,
            [req.userId, "Verified; credentials encrypted for the customer worker."]);
          return result.rows[0];
        });
        res.json({ setup, note: "Connection saved encrypted. The worker will load the new keys; entries remain paused until you start." });
      }));
  }
}
