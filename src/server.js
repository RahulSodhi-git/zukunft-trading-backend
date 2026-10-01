import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import Stripe from "stripe";
import { z } from "zod";
import { query, transaction } from "./db.js";
import { hasSmsConfig, sendAccountCreatedEmail, sendOtpEmail, sendPhoneOtp } from "./mailer.js";

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 5050);
const jwtSecret = process.env.JWT_SECRET || "dev-only-change-me";
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;
const otpTtlMinutes = 2;
const frontendOrigins = String(process.env.FRONTEND_ORIGIN || "http://localhost:5500,http://127.0.0.1:5500")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);
const publicFrontendUrl = String(process.env.PUBLIC_FRONTEND_URL || frontendOrigins.find(origin => origin !== "null") || "http://localhost:5500").replace(/\/$/, "");
let legacyAccountCleanup = { applied: false, deletedUsers: null, remainingUsers: null };

app.set("trust proxy", 1);
app.use(cors({
  origin(origin, cb) {
    if (!origin || frontendOrigins.includes(origin)) cb(null, true);
    else cb(new Error("Origin not allowed"));
  }
}));

app.post("/payments/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(503).json({ error: "Stripe webhook is not configured." });
  }
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === "checkout.session.completed") {
      await activatePaymentFromCheckout(event.data.object);
    } else if (event.type === "customer.subscription.deleted") {
      const subscription = event.data.object;
      const userId = subscription.metadata?.userId;
      if (userId) {
        await query(
          `update client_profiles
           set payment_status='inactive', onboarding_step='payment', updated_at=now()
           where user_id=$1`,
          [userId]
        );
      }
    }
    res.json({ received: true });
  } catch (err) {
    console.error("Stripe webhook processing failed:", err.message);
    res.status(500).json({ error: "Webhook processing failed." });
  }
});

app.use(express.json({ limit: "64kb" }));
app.use(rateLimit({ windowMs: 60_000, limit: 40 }));

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

const signupSchema = z.object({
  accountType: z.literal("pro_live").default("pro_live"),
  firstName: z.string().trim().min(1),
  lastName: z.string().trim().min(1),
  dob: z.string().min(8).nullable().optional(),
  country: z.string().trim().min(1),
  email: z.string().trim().email().transform(v => v.toLowerCase()),
  phoneCode: z.string().trim().nullable().optional(),
  phone: z.string().trim().nullable().optional(),
  password: z.string().min(8).regex(/[A-Z]/).regex(/\d/)
});

const loginSchema = z.object({
  identifier: z.string().trim().min(3),
  password: z.string().optional()
});

const apiKeySchema = z.object({
  binanceApiKey: z.string().trim().min(16),
  binanceApiSecret: z.string().trim().min(16),
  coinalyzeApiKey: z.string().trim().min(12)
});

const capitalSchema = z.object({
  capitalAmount: z.coerce.number().min(50)
});

const botToggleSchema = z.object({
  action: z.enum(["start", "stop"])
});

function normalizePhoneCode(value) {
  const match = String(value || "").match(/\+\d+/);
  return match ? match[0] : String(value || "").trim();
}

function makeOtp() {
  return String(crypto.randomInt(100000, 999999));
}

async function hash(value) {
  return bcrypt.hash(value, 12);
}

async function createOtp(userId, target) {
  await query(
    "delete from otp_codes where (expires_at <= now() or used_at is not null) and created_at < now() - interval '10 minutes'"
  );
  await query(
    "delete from otp_codes where user_id=$1 and target=$2 and expires_at <= now() and used_at is null",
    [userId, target]
  );
  const recent = await query(
    "select id from otp_codes where user_id=$1 and target=$2 and created_at > now() - interval '2 minutes' and used_at is null limit 1",
    [userId, target]
  );
  if (recent.rows.length) {
    const err = new Error("OTP already requested. Please wait 2 minutes before requesting a new code.");
    err.status = 429;
    throw err;
  }
  const code = makeOtp();
  const codeHash = await hash(code);
  await query(
    "insert into otp_codes (user_id, target, code_hash, expires_at) values ($1,$2,$3,now() + ($4 || ' minutes')::interval)",
    [userId, target, codeHash, otpTtlMinutes]
  );
  return code;
}

async function hashOtp(code) {
  return hash(code);
}

async function verifyHash(code, codeHash) {
  return bcrypt.compare(code, codeHash);
}

async function makeCustomerNumber(client) {
  const dateParts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Europe/Berlin",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(new Date());
  const byType = Object.fromEntries(dateParts.map(part => [part.type, part.value]));
  const dateKey = `${byType.year}${byType.month}${byType.day}`;
  const prefix = `A${dateKey}`;

  for (let i = 0; i < 8; i++) {
    const latest = await client.query(
      "select customer_number from users where customer_number like $1 order by length(customer_number) desc, customer_number desc limit 1",
      [`${prefix}%`]
    );
    const lastNumber = latest.rows[0]?.customer_number || "";
    const lastSequence = Number(lastNumber.slice(prefix.length)) || 0;
    const nextSequence = lastSequence + 1 + i;
    const sequenceWidth = Math.max(2, String(nextSequence).length);
    const number = `${prefix}${String(nextSequence).padStart(sequenceWidth, "0")}`;
    const existing = await client.query("select id from users where customer_number=$1 limit 1", [number]);
    if (!existing.rows.length) return number;
  }
  throw new Error("Could not generate customer number.");
}

async function verifyOtp(userId, target, code) {
  const result = await query(
    "select id, code_hash, expires_at from otp_codes where user_id=$1 and target=$2 and used_at is null order by created_at desc limit 1",
    [userId, target]
  );
  const otp = result.rows[0];
  if (!otp) return { ok: false, reason: "missing" };
  if (new Date(otp.expires_at).getTime() <= Date.now()) return { ok: false, reason: "expired" };
  if (!(await bcrypt.compare(code, otp.code_hash))) return { ok: false, reason: "incorrect" };
  await query("update otp_codes set used_at=now() where id=$1", [otp.id]);
  return { ok: true };
}

function issueToken(userId) {
  return jwt.sign({ sub: userId }, jwtSecret, { expiresIn: "7d" });
}

async function ensureRuntimeSchema() {
  await query(`
    create table if not exists client_bot_setups (
      user_id uuid primary key references users(id) on delete cascade,
      binance_status text not null default 'not_connected',
      binance_message text,
      binance_checked_at timestamptz,
      coinalyze_status text not null default 'not_connected',
      coinalyze_message text,
      coinalyze_checked_at timestamptz,
      capital_amount numeric(18,2),
      capital_currency text not null default 'USDT',
      bot_status text not null default 'stopped',
      bot_status_updated_at timestamptz,
      setup_completed_at timestamptz,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      check (binance_status in ('not_connected','verified','failed')),
      check (coinalyze_status in ('not_connected','verified','failed')),
      check (bot_status in ('stopped','running')),
      check (capital_amount is null or capital_amount >= 50)
    )
  `);
  await query(`alter table client_profiles add column if not exists stripe_customer_id text`);
  await query(`alter table client_profiles add column if not exists stripe_subscription_id text`);
  await query(`alter table client_profiles add column if not exists stripe_checkout_session_id text`);
  await query(`alter table client_profiles add column if not exists paid_at timestamptz`);
  legacyAccountCleanup = await transaction(async client => {
    await client.query(`
      create table if not exists system_migrations (
        key text primary key,
        applied_at timestamptz not null default now(),
        details jsonb not null default '{}'::jsonb
      )
    `);
    await client.query("select pg_advisory_xact_lock(hashtext($1))", ["purge_legacy_accounts_20261001"]);
    const existing = await client.query("select details from system_migrations where key=$1", ["purge_legacy_accounts_20261001"]);
    if (existing.rows.length) return { applied: true, ...existing.rows[0].details };

    const before = await client.query("select count(*)::int as count from users");
    await client.query("delete from pending_signups");
    await client.query("delete from users");
    const after = await client.query("select count(*)::int as count from users");
    const details = { deletedUsers: before.rows[0].count, remainingUsers: after.rows[0].count };
    await client.query(
      "insert into system_migrations (key,details) values ($1,$2::jsonb)",
      ["purge_legacy_accounts_20261001", JSON.stringify(details)]
    );
    return { applied: true, ...details };
  });
}

async function activatePaymentFromCheckout(session) {
  const userId = session.client_reference_id || session.metadata?.userId;
  if (
    !userId ||
    session.mode !== "subscription" ||
    session.payment_status !== "paid" ||
    session.currency !== "usd" ||
    Number(session.amount_total) !== 10000 ||
    session.metadata?.plan !== "pro_live"
  ) return false;
  await query(
    `update client_profiles
     set payment_status='active', onboarding_step='api_setup', stripe_customer_id=$2,
         stripe_subscription_id=$3, stripe_checkout_session_id=$4,
         paid_at=coalesce(paid_at,now()), updated_at=now()
     where user_id=$1`,
    [userId, session.customer || null, session.subscription || null, session.id]
  );
  await query("update users set account_status='active', updated_at=now() where id=$1", [userId]);
  await query(
    `update user_plans set status='active', pro_started_at=coalesce(pro_started_at,now()), updated_at=now()
     where user_id=$1 and plan_code='pro_live'`,
    [userId]
  );
  return true;
}

function sendAccountCreatedLater({ email, firstName, customerNumber, accountType }) {
  const delayMs = Number(process.env.ACCOUNT_EMAIL_DELAY_MS || 60000);
  setTimeout(() => {
    sendAccountCreatedEmail({ to: email, firstName, customerNumber, accountType }).catch(err => {
      console.error("Account created email failed:", err.message);
    });
  }, delayMs);
}

async function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  try {
    const payload = jwt.verify(token, jwtSecret);
    req.userId = payload.sub;
    next();
  } catch {
    res.status(401).json({ error: "Unauthorized" });
  }
}

async function requireActivePayment(req, res, next) {
  try {
    const result = await query("select payment_status from client_profiles where user_id=$1", [req.userId]);
    if (result.rows[0]?.payment_status !== "active") {
      return res.status(402).json({ error: "Activate the $100/month Pro subscription before continuing." });
    }
    next();
  } catch (err) {
    next(err);
  }
}

function cleanProviderMessage(value, fallback) {
  const text = String(value || fallback || "Connection check failed.").replace(/\s+/g, " ").trim();
  return text.slice(0, 180);
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 12000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function verifyBinanceFutures(apiKey, apiSecret) {
  const timestamp = Date.now();
  const queryString = `timestamp=${timestamp}&recvWindow=5000`;
  const signature = crypto.createHmac("sha256", apiSecret).update(queryString).digest("hex");
  const url = `https://fapi.binance.com/fapi/v2/account?${queryString}&signature=${signature}`;
  const response = await fetchWithTimeout(url, {
    headers: { "X-MBX-APIKEY": apiKey }
  });
  if (response.ok) return { status: "verified", message: "Binance Futures connection verified. Withdrawal permission is not used." };
  let body = {};
  try { body = await response.json(); } catch {}
  return {
    status: "failed",
    message: cleanProviderMessage(body.msg, `Binance rejected the key check with status ${response.status}.`)
  };
}

async function verifyCoinalyze(apiKey) {
  const response = await fetchWithTimeout("https://api.coinalyze.net/v1/exchanges", {
    headers: { api_key: apiKey }
  });
  if (response.ok) return { status: "verified", message: "Coinalyze connection verified." };

  let retryBody = "";
  const retry = await fetchWithTimeout(`https://api.coinalyze.net/v1/exchanges?api_key=${encodeURIComponent(apiKey)}`);
  if (retry.ok) return { status: "verified", message: "Coinalyze connection verified." };
  try { retryBody = await retry.text(); } catch {}
  return {
    status: "failed",
    message: cleanProviderMessage(retryBody, `Coinalyze rejected the key check with status ${retry.status || response.status}.`)
  };
}

function setupComplete(row) {
  return row?.binance_status === "verified" && row?.coinalyze_status === "verified" && Number(row?.capital_amount || 0) >= 50;
}

async function findUser(identifier) {
  const value = String(identifier).trim().toLowerCase();
  const result = await query(
    `select u.*
     from users u
     left join pro_profiles pp on pp.user_id = u.id
     where (
       lower(u.email)=$1
       or lower(u.customer_number)=$1
       or lower(concat_ws(' ', pp.phone_code, pp.phone_number))=$1
       or lower(pp.phone_number)=$1
     ) and u.account_type='pro_live'
     order by u.created_at desc
     limit 1`,
    [value]
  );
  return result.rows[0];
}

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/health/db", async (req, res) => {
  try {
    const result = await query("select now() as server_time");
    res.json({ ok: true, serverTime: result.rows[0].server_time, legacyAccountCleanup });
  } catch (err) {
    res.status(500).json({
      ok: false,
      message: err.message,
      code: err.code || null
    });
  }
});

app.get("/health/email", async (req, res) => {
  try {
    const testTo = process.env.EMAIL_TEST_TO || process.env.SMTP_USER || "rstrading.zukunft@gmail.com";
    await sendOtpEmail({
      to: testTo,
      code: "123456",
      firstName: "Zukunft",
      purpose: "login"
    });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({
      ok: false,
      message: err.message,
      code: err.code || null,
      command: err.command || null
    });
  }
});

app.get("/countries", asyncRoute(async (req, res) => {
  const result = await query("select name from country_options order by is_default desc, name asc");
  res.json({ countries: result.rows.map(row => row.name) });
}));

app.get("/public/performance", asyncRoute(async (req, res) => {
  res.json({
    connected: false,
    updatedAt: null,
    source: "main_bot",
    metrics: {
      dailyProfitLossPct: null,
      winRatePct: null,
      tradesToday: null,
      backtestPassRatePct: null,
      rulesChecked: null,
      maxDrawdownPct: null
    },
    note: "Awaiting live bot metrics feed."
  });
}));

app.post("/auth/signup", asyncRoute(async (req, res) => {
  const data = signupSchema.parse(req.body);
  const phoneCode = normalizePhoneCode(data.phoneCode);
  if (!data.dob || !data.phoneCode || !data.phone) {
    return res.status(400).json({ error: "Pro account requires date of birth, phone extension and mobile number." });
  }
  if (!hasSmsConfig()) {
    return res.status(503).json({ error: "Phone OTP service is not configured. Pro signup needs SMS verification before account creation." });
  }

  const existingEmail = await query("select id from users where lower(email)=$1 and account_type=$2 limit 1", [data.email, data.accountType]);
  if (existingEmail.rows.length) return res.status(409).json({ error: "Pro account already exists for this email." });

  await query("delete from pending_signups where expires_at <= now()");

  const recentPending = await query(
    "select id from pending_signups where lower(email)=lower($1) and account_type=$2 and last_otp_sent_at > now() - interval '2 minutes' and expires_at > now() limit 1",
    [data.email, data.accountType]
  );
  if (recentPending.rows.length) {
    return res.status(429).json({ error: "OTP already requested. Please wait 2 minutes before requesting a new code." });
  }

  const existingPhone = await query(
    "select user_id from pro_profiles where lower(phone_code)=lower($1) and lower(phone_number)=lower($2) limit 1",
    [phoneCode, data.phone]
  );
  if (existingPhone.rows.length) return res.status(409).json({ error: "Pro account already exists for this phone number." });

  const passwordHash = await hash(data.password);
  const emailOtp = makeOtp();
  const phoneOtp = makeOtp();
  const result = await query(
    `insert into pending_signups
      (account_type, first_name, last_name, country, email, password_hash, date_of_birth, phone_code, phone_number,
       email_otp_hash, phone_otp_hash, expires_at)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now() + ($12 || ' minutes')::interval)
     returning id,email,account_type`,
    [
      data.accountType,
      data.firstName,
      data.lastName,
      data.country,
      data.email,
      passwordHash,
      data.dob,
      phoneCode,
      data.phone,
      await hashOtp(emailOtp),
      phoneOtp ? await hashOtp(phoneOtp) : null,
      otpTtlMinutes
    ]
  );
  const pending = result.rows[0];

  try {
    await sendOtpEmail({
      to: pending.email,
      code: emailOtp,
      firstName: data.firstName,
      purpose: "pro_live_signup"
    });
    await sendPhoneOtp({ to: `${phoneCode}${data.phone}`, code: phoneOtp });
  } catch (err) {
    await query("delete from pending_signups where id=$1", [pending.id]);
    return res.status(503).json({ error: err.message });
  }
  res.status(201).json({
    signupRequestId: pending.id,
    email: pending.email,
    accountType: "pro_live",
    emailOtpSent: true,
    phoneOtpSent: true
  });
}));

app.post("/auth/verify-signup", asyncRoute(async (req, res) => {
  const schema = z.object({ signupRequestId: z.string().uuid(), emailOtp: z.string().length(6), phoneOtp: z.string().length(6).optional().or(z.literal("")) });
  const data = schema.parse(req.body);
  const pendingResult = await query("select * from pending_signups where id=$1 limit 1", [data.signupRequestId]);
  const pending = pendingResult.rows[0];
  if (!pending) return res.status(404).json({ error: "Signup request not found. Please request a new OTP." });
  if (new Date(pending.expires_at).getTime() <= Date.now()) {
    await query("delete from pending_signups where id=$1", [pending.id]);
    return res.status(410).json({ error: "OTP expired. Please request a new OTP." });
  }

  const emailOk = await verifyHash(data.emailOtp, pending.email_otp_hash);
  if (pending.account_type !== "pro_live") return res.status(410).json({ error: "Demo signup is no longer available. Create a Pro account." });
  const phoneOk = await verifyHash(data.phoneOtp || "", pending.phone_otp_hash);
  if (!emailOk || !phoneOk) return res.status(400).json({ error: "Incorrect OTP. Please enter the latest OTP sent to you." });

  const created = await transaction(async client => {
    const existingEmail = await client.query("select id from users where lower(email)=lower($1) and account_type=$2 limit 1", [pending.email, pending.account_type]);
    if (existingEmail.rows.length) throw new Error("Pro account already exists for this email.");
    const existingPhone = await client.query(
      "select user_id from pro_profiles where lower(phone_code)=lower($1) and lower(phone_number)=lower($2) limit 1",
      [pending.phone_code, pending.phone_number]
    );
    if (existingPhone.rows.length) throw new Error("Pro account already exists for this phone number.");

    const customerNumber = await makeCustomerNumber(client);
    const userResult = await client.query(
      `insert into users (customer_number, account_type, first_name, last_name, country, email, password_hash, email_verified, phone_verified, account_status)
       values ($1,$2,$3,$4,$5,$6,$7,true,$8,'pending_payment')
       returning id, customer_number`,
      [customerNumber, pending.account_type, pending.first_name, pending.last_name, pending.country, pending.email, pending.password_hash, pending.account_type === "pro_live"]
    );
    const user = userResult.rows[0];

    await client.query(
      `insert into user_plans (user_id, plan_code, status, demo_started_at, demo_expires_at, pro_started_at)
       values ($1,'pro_live','pending_payment',null,null,null)`,
      [user.id]
    );

    await client.query(
      `insert into pro_profiles (user_id, date_of_birth, phone_code, phone_number, phone_verified)
       values ($1,$2,$3,$4,true)`,
      [user.id, pending.date_of_birth, pending.phone_code, pending.phone_number]
    );

    await client.query("insert into client_profiles (user_id) values ($1)", [user.id]);
    await client.query("insert into client_bot_setups (user_id) values ($1)", [user.id]);
    await client.query("insert into country_options (name) values ($1) on conflict (name) do nothing", [pending.country]);
    await client.query("delete from pending_signups where id=$1", [pending.id]);
    return {
      ...user,
      email: pending.email,
      first_name: pending.first_name
    };
  });

  sendAccountCreatedLater({
    email: created.email,
    firstName: created.first_name,
    customerNumber: created.customer_number,
    accountType: pending.account_type
  });

  res.json({
    accountType: pending.account_type,
    customerNumber: created.customer_number,
    loginRequired: true
  });
}));

app.post("/auth/login", asyncRoute(async (req, res) => {
  const data = loginSchema.parse(req.body);
  const user = await findUser(data.identifier);
  if (!user) return res.status(404).json({ error: "Account not found." });
  if (!data.password || !(await bcrypt.compare(data.password, user.password_hash))) {
    return res.status(401).json({ error: "Incorrect password." });
  }
  let loginOtp;
  try {
    loginOtp = await createOtp(user.id, "login");
  } catch (err) {
    return res.status(err.status || 500).json({ error: err.message });
  }
  try {
    await sendOtpEmail({ to: user.email, code: loginOtp, firstName: user.first_name, purpose: "login" });
  } catch (err) {
    await query("delete from otp_codes where user_id=$1 and target='login' and used_at is null", [user.id]);
    return res.status(503).json({ error: err.message });
  }
  res.json({ userId: user.id, emailOtpSent: true, passwordVerified: true });
}));

app.post("/auth/request-login-otp", asyncRoute(async (req, res) => {
  const data = z.object({ identifier: z.string().trim().min(3) }).parse(req.body);
  const user = await findUser(data.identifier);
  if (!user) return res.status(404).json({ error: "Account not found." });
  let loginOtp;
  try {
    loginOtp = await createOtp(user.id, "login");
  } catch (err) {
    return res.status(err.status || 500).json({ error: err.message });
  }
  try {
    await sendOtpEmail({ to: user.email, code: loginOtp, firstName: user.first_name, purpose: "login" });
  } catch (err) {
    return res.status(503).json({ error: err.message });
  }
  res.json({ userId: user.id, emailOtpSent: true });
}));

app.post("/auth/verify-login-otp", asyncRoute(async (req, res) => {
  const data = z.object({ userId: z.string().uuid(), loginOtp: z.string().length(6) }).parse(req.body);
  const otp = await verifyOtp(data.userId, "login", data.loginOtp);
  if (!otp.ok) {
    if (otp.reason === "expired") return res.status(410).json({ error: "OTP expired. Please request a new OTP." });
    return res.status(400).json({ error: "Incorrect OTP. Please enter the latest OTP sent to you." });
  }
  res.json({ token: issueToken(data.userId) });
}));

app.get("/payments/status", auth, asyncRoute(async (req, res) => {
  const result = await query(
    "select payment_status, paid_at from client_profiles where user_id=$1",
    [req.userId]
  );
  const payment = result.rows[0] || { payment_status: "not_started", paid_at: null };
  res.json({
    plan: "pro_live",
    amount: 100,
    currency: "USD",
    interval: "month",
    status: payment.payment_status,
    paidAt: payment.paid_at,
    checkoutConfigured: Boolean(stripe)
  });
}));

app.post("/payments/checkout", auth, asyncRoute(async (req, res) => {
  if (!stripe) return res.status(503).json({ error: "Payments are not configured yet. Add STRIPE_SECRET_KEY in Render." });
  const userResult = await query(
    `select u.id,u.email,u.customer_number,p.payment_status
     from users u join client_profiles p on p.user_id=u.id
     where u.id=$1 and u.account_type='pro_live'`,
    [req.userId]
  );
  const user = userResult.rows[0];
  if (!user) return res.status(404).json({ error: "Pro account not found." });
  if (user.payment_status === "active") return res.json({ active: true, redirectUrl: `${publicFrontendUrl}/portal.html` });

  const lineItem = process.env.STRIPE_PRICE_ID
    ? { price: process.env.STRIPE_PRICE_ID, quantity: 1 }
    : {
        price_data: {
          currency: "usd",
          unit_amount: 10000,
          recurring: { interval: "month" },
          product_data: { name: "Zukunft Trading Pro" }
        },
        quantity: 1
      };
  const session = await stripe.checkout.sessions.create({
    mode: "subscription",
    customer_email: user.email,
    client_reference_id: user.id,
    line_items: [lineItem],
    success_url: `${publicFrontendUrl}/payment.html?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${publicFrontendUrl}/payment.html?cancelled=1`,
    metadata: { userId: user.id, customerNumber: user.customer_number, plan: "pro_live" },
    subscription_data: { metadata: { userId: user.id, plan: "pro_live" } }
  });
  await query(
    `update client_profiles set payment_status='pending', stripe_checkout_session_id=$2, updated_at=now() where user_id=$1`,
    [req.userId, session.id]
  );
  res.status(201).json({ checkoutUrl: session.url });
}));

app.post("/payments/confirm", auth, asyncRoute(async (req, res) => {
  if (!stripe) return res.status(503).json({ error: "Payments are not configured." });
  const data = z.object({ sessionId: z.string().min(8) }).parse(req.body);
  const session = await stripe.checkout.sessions.retrieve(data.sessionId);
  const sessionUserId = session.client_reference_id || session.metadata?.userId;
  if (sessionUserId !== req.userId) return res.status(403).json({ error: "Payment session does not belong to this account." });
  const active = await activatePaymentFromCheckout(session);
  res.json({ active, status: active ? "active" : session.payment_status });
}));

app.get("/me", auth, asyncRoute(async (req, res) => {
  const result = await query(
    `select u.id,u.customer_number,u.first_name,u.last_name,u.email,u.country,u.created_at,u.account_status,
            up.plan_code as account_type, up.status as plan_status, up.demo_started_at, up.demo_expires_at, up.pro_started_at,
            pp.date_of_birth, pp.phone_code, pp.phone_number, pp.phone_verified,
            case when pp.date_of_birth is null then null else date_part('year', age(current_date, pp.date_of_birth))::int end as age,
            p.payment_status,p.onboarding_step,p.risk_level,
            s.binance_status,s.binance_message,s.binance_checked_at,
            s.coinalyze_status,s.coinalyze_message,s.coinalyze_checked_at,
            s.capital_amount,s.capital_currency,s.bot_status,s.bot_status_updated_at,s.setup_completed_at
     from users u
     left join user_plans up on up.user_id=u.id
     left join pro_profiles pp on pp.user_id=u.id
     left join client_profiles p on p.user_id=u.id
     left join client_bot_setups s on s.user_id=u.id
     where u.id=$1`,
    [req.userId]
  );
  res.json({ user: result.rows[0] });
}));

app.get("/onboarding/status", auth, requireActivePayment, asyncRoute(async (req, res) => {
  await query("insert into client_bot_setups (user_id) values ($1) on conflict (user_id) do nothing", [req.userId]);
  const result = await query("select * from client_bot_setups where user_id=$1", [req.userId]);
  const setup = result.rows[0];
  res.json({ setup, setupComplete: setupComplete(setup) });
}));

app.post("/onboarding/api-keys", auth, requireActivePayment, asyncRoute(async (req, res) => {
  const data = apiKeySchema.parse(req.body);
  const [binance, coinalyze] = await Promise.all([
    verifyBinanceFutures(data.binanceApiKey, data.binanceApiSecret).catch(err => ({
      status: "failed",
      message: cleanProviderMessage(err.message, "Binance connection check failed.")
    })),
    verifyCoinalyze(data.coinalyzeApiKey).catch(err => ({
      status: "failed",
      message: cleanProviderMessage(err.message, "Coinalyze connection check failed.")
    }))
  ]);

  const result = await query(
    `insert into client_bot_setups
      (user_id, binance_status, binance_message, binance_checked_at, coinalyze_status, coinalyze_message, coinalyze_checked_at, updated_at)
     values ($1,$2,$3,now(),$4,$5,now(),now())
     on conflict (user_id) do update set
       binance_status=excluded.binance_status,
       binance_message=excluded.binance_message,
       binance_checked_at=excluded.binance_checked_at,
       coinalyze_status=excluded.coinalyze_status,
       coinalyze_message=excluded.coinalyze_message,
       coinalyze_checked_at=excluded.coinalyze_checked_at,
       setup_completed_at=case
         when excluded.binance_status='verified'
          and excluded.coinalyze_status='verified'
          and client_bot_setups.capital_amount >= 50
         then coalesce(client_bot_setups.setup_completed_at, now())
         else null
       end,
       updated_at=now()
     returning *`,
    [req.userId, binance.status, binance.message, coinalyze.status, coinalyze.message]
  );

  res.json({
    setup: result.rows[0],
    setupComplete: setupComplete(result.rows[0]),
    note: "API keys were verified and discarded. Zukunft Trading does not store Binance or Coinalyze keys."
  });
}));

app.post("/onboarding/capital", auth, requireActivePayment, asyncRoute(async (req, res) => {
  const data = capitalSchema.parse(req.body);
  const result = await query(
    `insert into client_bot_setups (user_id, capital_amount, capital_currency, updated_at)
     values ($1,$2,'USDT',now())
     on conflict (user_id) do update set
       capital_amount=excluded.capital_amount,
       capital_currency='USDT',
       setup_completed_at=case
         when client_bot_setups.binance_status='verified'
          and client_bot_setups.coinalyze_status='verified'
          and excluded.capital_amount >= 50
         then coalesce(client_bot_setups.setup_completed_at, now())
         else null
       end,
       updated_at=now()
     returning *`,
    [req.userId, data.capitalAmount]
  );
  res.json({ setup: result.rows[0], setupComplete: setupComplete(result.rows[0]) });
}));

app.post("/bot/toggle", auth, requireActivePayment, asyncRoute(async (req, res) => {
  const data = botToggleSchema.parse(req.body);
  await query("insert into client_bot_setups (user_id) values ($1) on conflict (user_id) do nothing", [req.userId]);
  const current = await query("select * from client_bot_setups where user_id=$1", [req.userId]);
  if (data.action === "start" && !setupComplete(current.rows[0])) {
    return res.status(409).json({ error: "Complete Binance, Coinalyze and minimum 50 USDT capital setup before starting the bot." });
  }
  const result = await query(
    `update client_bot_setups
     set bot_status=$2, bot_status_updated_at=now(), updated_at=now()
     where user_id=$1
     returning *`,
    [req.userId, data.action === "start" ? "running" : "stopped"]
  );
  res.json({ setup: result.rows[0], setupComplete: setupComplete(result.rows[0]) });
}));

app.use((err, req, res, next) => {
  if (err instanceof z.ZodError) return res.status(400).json({ error: "Invalid input", details: err.errors });
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

export { app };

if (process.argv[1] && process.argv[1].endsWith("server.js")) {
  ensureRuntimeSchema()
    .then(() => {
      app.listen(port, () => {
        console.log(`Zukunft Trading API running on http://localhost:${port}`);
      });
    })
    .catch(err => {
      console.error("Startup schema check failed:", err);
      process.exit(1);
    });
}
