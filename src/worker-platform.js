import crypto from "node:crypto";
import { z } from "zod";

const heartbeatSchema = z.object({
  workerId: z.string().trim().min(1).max(80),
  accounts: z.array(z.object({
    userId: z.string().uuid(),
    actualState: z.enum(["provisioning", "paused", "running", "stopped", "error"]),
    error: z.string().max(500).nullable().optional(),
    openPositions: z.array(z.record(z.unknown())).max(100).default([]),
    recentClosedTrades: z.array(z.record(z.unknown())).max(200).default([])
  })).max(500).default([])
});

const controlSchema = z.object({
  action: z.enum(["start", "pause", "stop"])
});

function workerPublicKey() {
  const encoded = String(process.env.WORKER_PUBLIC_KEY_B64 || "").trim();
  if (!encoded) throw Object.assign(new Error("Worker credential encryption is not configured."), { status: 503 });
  try {
    return crypto.createPublicKey(Buffer.from(encoded, "base64").toString("utf8"));
  } catch {
    throw Object.assign(new Error("Worker credential encryption key is invalid."), { status: 503 });
  }
}

function encryptForWorker(value) {
  return crypto.publicEncrypt(
    { key: workerPublicKey(), oaepHash: "sha256", padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    Buffer.from(JSON.stringify(value), "utf8")
  ).toString("base64");
}

function safeEqual(value, expected) {
  const left = Buffer.from(String(value || ""));
  const right = Buffer.from(String(expected || ""));
  return left.length === right.length && left.length > 0 && crypto.timingSafeEqual(left, right);
}

export async function ensureWorkerSchema(query) {
  await query(`
    create table if not exists client_bot_credentials (
      user_id uuid primary key references users(id) on delete cascade,
      binance_ciphertext text,
      coinalyze_ciphertext text,
      credential_version integer not null default 0,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    )
  `);
  await query(`
    create table if not exists client_bot_snapshots (
      user_id uuid primary key references users(id) on delete cascade,
      worker_id text,
      actual_state text not null default 'stopped',
      open_positions jsonb not null default '[]'::jsonb,
      recent_closed_trades jsonb not null default '[]'::jsonb,
      last_error text,
      heartbeat_at timestamptz,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    )
  `);
  await query(`alter table client_bot_setups add column if not exists desired_state text not null default 'paused'`);
  await query(`alter table client_bot_setups add column if not exists provisioning_status text not null default 'waiting'`);
  await query(`alter table client_bot_setups add column if not exists assigned_worker_id text`);
  await query(`alter table client_bot_setups add column if not exists worker_heartbeat_at timestamptz`);
}

export async function storeWorkerCredential(query, userId, provider, credential) {
  const encrypted = encryptForWorker(credential);
  const column = provider === "binance" ? "binance_ciphertext" : "coinalyze_ciphertext";
  await query(
    `insert into client_bot_credentials (user_id,${column},credential_version,updated_at)
     values ($1,$2,1,now())
     on conflict (user_id) do update set
       ${column}=excluded.${column},
       credential_version=client_bot_credentials.credential_version+1,
       updated_at=now()`,
    [userId, encrypted]
  );
}

export async function reconcileProvisioning(query, userId) {
  const result = await query(
    `select s.binance_status,s.coinalyze_status,s.capital_amount,
            c.binance_ciphertext is not null as has_binance,
            c.coinalyze_ciphertext is not null as has_coinalyze
     from client_bot_setups s
     left join client_bot_credentials c on c.user_id=s.user_id
     where s.user_id=$1`,
    [userId]
  );
  const row = result.rows[0];
  const ready = row?.binance_status === "verified"
    && row?.coinalyze_status === "verified"
    && Number(row?.capital_amount || 0) >= 100
    && row?.has_binance
    && row?.has_coinalyze;
  await query(
    `update client_bot_setups
     set provisioning_status=$2,
         setup_completed_at=case when $2='pending' then coalesce(setup_completed_at,now()) else setup_completed_at end,
         updated_at=now()
     where user_id=$1`,
    [userId, ready ? "pending" : "waiting"]
  );
  return ready;
}

export function registerWorkerPlatform({ app, query, auth, requireActivePayment, asyncRoute }) {
  function workerAuth(req, res, next) {
    if (!safeEqual(req.headers["x-worker-token"], process.env.WORKER_TOKEN)) {
      return res.status(401).json({ error: "Unauthorized worker" });
    }
    next();
  }

  app.get("/worker/accounts", workerAuth, asyncRoute(async (req, res) => {
    const result = await query(
      `select s.user_id,u.customer_number,s.capital_amount,s.capital_currency,s.desired_state,
              s.provisioning_status,c.binance_ciphertext,c.coinalyze_ciphertext,c.credential_version
       from client_bot_setups s
       join users u on u.id=s.user_id
       join client_bot_credentials c on c.user_id=s.user_id
       join client_profiles p on p.user_id=s.user_id
       where p.payment_status='active'
         and s.binance_status='verified'
         and s.coinalyze_status='verified'
         and s.capital_amount>= 100
         and c.binance_ciphertext is not null
         and c.coinalyze_ciphertext is not null
       order by s.updated_at asc`
    );
    res.json({ accounts: result.rows });
  }));

  app.post("/worker/heartbeat", workerAuth, asyncRoute(async (req, res) => {
    const data = heartbeatSchema.parse(req.body);
    for (const account of data.accounts) {
      await query(
        `insert into client_bot_snapshots
          (user_id,worker_id,actual_state,open_positions,recent_closed_trades,last_error,heartbeat_at,updated_at)
         values ($1,$2,$3,$4::jsonb,$5::jsonb,$6,now(),now())
         on conflict (user_id) do update set
           worker_id=excluded.worker_id,actual_state=excluded.actual_state,
           open_positions=excluded.open_positions,recent_closed_trades=excluded.recent_closed_trades,
           last_error=excluded.last_error,heartbeat_at=now(),updated_at=now()`,
        [account.userId, data.workerId, account.actualState, JSON.stringify(account.openPositions),
          JSON.stringify(account.recentClosedTrades), account.error || null]
      );
      await query(
        `update client_bot_setups set assigned_worker_id=$2,worker_heartbeat_at=now(),
           provisioning_status=case when $3='error' then 'error' else 'ready' end,
           bot_status=case when $3='running' then 'running' else 'stopped' end,
           updated_at=now() where user_id=$1`,
        [account.userId, data.workerId, account.actualState]
      );
    }
    res.json({ accepted: data.accounts.length });
  }));

  app.get("/bot/overview", auth, requireActivePayment, asyncRoute(async (req, res) => {
    const result = await query(
      `select s.*,coalesce(x.actual_state,'stopped') as actual_state,
              coalesce(x.open_positions,'[]'::jsonb) as open_positions,
              coalesce(x.recent_closed_trades,'[]'::jsonb) as recent_closed_trades,
              x.last_error,x.heartbeat_at
       from client_bot_setups s
       left join client_bot_snapshots x on x.user_id=s.user_id
       where s.user_id=$1`,
      [req.userId]
    );
    res.json({ bot: result.rows[0] || null });
  }));

  app.post("/bot/control", auth, requireActivePayment, asyncRoute(async (req, res) => {
    const data = controlSchema.parse(req.body);
    const current = await query(
      `select s.*,x.heartbeat_at,coalesce(jsonb_array_length(x.open_positions),0) as open_count
       from client_bot_setups s left join client_bot_snapshots x on x.user_id=s.user_id
       where s.user_id=$1`,
      [req.userId]
    );
    const setup = current.rows[0];
    if (!setup || setup.provisioning_status !== "ready") {
      return res.status(409).json({ error: "The customer worker is not ready yet." });
    }
    if (data.action !== "pause" && (!setup.heartbeat_at || Date.now() - new Date(setup.heartbeat_at).getTime() > 90000)) {
      return res.status(409).json({ error: "Worker information is stale. Pause remains available; start/stop require a fresh exchange snapshot." });
    }
    if (data.action === "stop" && Number(setup.open_count || 0) > 0) {
      return res.status(409).json({ error: "Pause entries instead. Stop is blocked while exchange positions are open." });
    }
    const desired = data.action === "start" ? "running" : data.action === "pause" ? "paused" : "stopped";
    const result = await query(
      `update client_bot_setups set desired_state=$2,bot_status_updated_at=now(),updated_at=now()
       where user_id=$1 returning *`,
      [req.userId, desired]
    );
    res.json({ setup: result.rows[0] });
  }));
}

