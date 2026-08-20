import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { query, transaction } from "./db.js";
import { hasSmsConfig, sendAccountCreatedEmail, sendOtpEmail, sendPhoneOtp } from "./mailer.js";

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 5050);
const jwtSecret = process.env.JWT_SECRET || "dev-only-change-me";
const otpTtlMinutes = 2;
const frontendOrigins = String(process.env.FRONTEND_ORIGIN || "null")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

app.set("trust proxy", 1);
app.use(cors({
  origin(origin, cb) {
    if (!origin || frontendOrigins.includes("null") || frontendOrigins.includes(origin)) cb(null, true);
    else cb(new Error("Origin not allowed"));
  }
}));
app.use(express.json({ limit: "64kb" }));
app.use(rateLimit({ windowMs: 60_000, limit: 40 }));

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

const signupSchema = z.object({
  accountType: z.enum(["starter_demo", "pro_live"]).default("starter_demo"),
  demoExpiresInDays: z.number().int().positive().max(30).nullable().optional(),
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

async function makeCustomerNumber(client, accountType) {
  const prefix = accountType === "pro_live" ? "P" : "D";
  for (let i = 0; i < 8; i++) {
    const number = `${prefix}${new Date().getFullYear()}${crypto.randomInt(100000, 999999)}`;
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

async function findUser(identifier) {
  const value = String(identifier).trim().toLowerCase();
  const result = await query(
    `select u.*
     from users u
     left join pro_profiles pp on pp.user_id = u.id
     where lower(u.email)=$1
        or lower(u.customer_number)=$1
        or lower(concat_ws(' ', pp.phone_code, pp.phone_number))=$1
        or lower(pp.phone_number)=$1
     order by case when u.account_type='pro_live' then 0 else 1 end, u.created_at desc
     limit 1`,
    [value]
  );
  return result.rows[0];
}

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/health/db", asyncRoute(async (req, res) => {
  const result = await query("select now() as server_time");
  res.json({ ok: true, serverTime: result.rows[0].server_time });
}));

app.get("/countries", asyncRoute(async (req, res) => {
  const result = await query("select name from country_options order by is_default desc, name asc");
  res.json({ countries: result.rows.map(row => row.name) });
}));

app.post("/auth/signup", asyncRoute(async (req, res) => {
  const data = signupSchema.parse(req.body);
  const pro = data.accountType === "pro_live";
  const phoneCode = pro ? normalizePhoneCode(data.phoneCode) : null;
  if (pro && (!data.dob || !data.phoneCode || !data.phone)) {
    return res.status(400).json({ error: "Pro account requires date of birth, phone extension and mobile number." });
  }
  if (pro && !hasSmsConfig()) {
    return res.status(503).json({ error: "Phone OTP service is not configured. Pro signup needs SMS verification before account creation." });
  }

  const existingEmail = await query("select id from users where lower(email)=$1 and account_type=$2 limit 1", [data.email, data.accountType]);
  if (existingEmail.rows.length) return res.status(409).json({ error: `${pro ? "Pro" : "Demo"} account already exists for this email.` });

  await query("delete from pending_signups where expires_at <= now()");

  const recentPending = await query(
    "select id from pending_signups where lower(email)=lower($1) and account_type=$2 and last_otp_sent_at > now() - interval '2 minutes' and expires_at > now() limit 1",
    [data.email, data.accountType]
  );
  if (recentPending.rows.length) {
    return res.status(429).json({ error: "OTP already requested. Please wait 2 minutes before requesting a new code." });
  }

  if (pro) {
    const existingPhone = await query(
      "select user_id from pro_profiles where lower(phone_code)=lower($1) and lower(phone_number)=lower($2) limit 1",
      [phoneCode, data.phone]
    );
    if (existingPhone.rows.length) return res.status(409).json({ error: "Pro account already exists for this phone number." });
  }

  const passwordHash = await hash(data.password);
  const emailOtp = makeOtp();
  const phoneOtp = pro ? makeOtp() : null;
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
      pro ? data.dob : null,
      phoneCode,
      pro ? data.phone : null,
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
      purpose: data.accountType === "pro_live" ? "pro_live_signup" : "starter_demo_signup"
    });
    if (pro) {
      await sendPhoneOtp({ to: `${phoneCode}${data.phone}`, code: phoneOtp });
    }
  } catch (err) {
    await query("delete from pending_signups where id=$1", [pending.id]);
    return res.status(503).json({ error: err.message });
  }
  res.status(201).json({
    signupRequestId: pending.id,
    email: pending.email,
    accountType: data.accountType,
    demoExpiresInDays: data.accountType === "starter_demo" ? 2 : null,
    emailOtpSent: true,
    phoneOtpSent: Boolean(phoneOtp),
    demoMode: true
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
  const phoneOk = pending.account_type === "pro_live" ? await verifyHash(data.phoneOtp || "", pending.phone_otp_hash) : true;
  if (!emailOk || !phoneOk) return res.status(400).json({ error: "Incorrect OTP. Please enter the latest OTP sent to you." });

  const created = await transaction(async client => {
    const existingEmail = await client.query("select id from users where lower(email)=lower($1) and account_type=$2 limit 1", [pending.email, pending.account_type]);
    if (existingEmail.rows.length) throw new Error(`${pending.account_type === "pro_live" ? "Pro" : "Demo"} account already exists for this email.`);
    if (pending.account_type === "pro_live") {
      const existingPhone = await client.query(
        "select user_id from pro_profiles where lower(phone_code)=lower($1) and lower(phone_number)=lower($2) limit 1",
        [pending.phone_code, pending.phone_number]
      );
      if (existingPhone.rows.length) throw new Error("Pro account already exists for this phone number.");
    }

    const customerNumber = await makeCustomerNumber(client, pending.account_type);
    const userResult = await client.query(
      `insert into users (customer_number, account_type, first_name, last_name, country, email, password_hash, email_verified, phone_verified, account_status)
       values ($1,$2,$3,$4,$5,$6,$7,true,$8,'active')
       returning id, customer_number`,
      [customerNumber, pending.account_type, pending.first_name, pending.last_name, pending.country, pending.email, pending.password_hash, pending.account_type === "pro_live"]
    );
    const user = userResult.rows[0];

    await client.query(
      `insert into user_plans (user_id, plan_code, status, demo_started_at, demo_expires_at, pro_started_at)
       values ($1,$2,'active',
         case when $2='starter_demo' then now() else null end,
         case when $2='starter_demo' then now() + interval '2 days' else null end,
         case when $2='pro_live' then now() else null end
       )`,
      [user.id, pending.account_type]
    );

    if (pending.account_type === "pro_live") {
      await client.query(
        `insert into pro_profiles (user_id, date_of_birth, phone_code, phone_number, phone_verified)
         values ($1,$2,$3,$4,true)`,
        [user.id, pending.date_of_birth, pending.phone_code, pending.phone_number]
      );
    }

    await client.query("insert into client_profiles (user_id) values ($1)", [user.id]);
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

  res.json({ token: issueToken(created.id), accountType: pending.account_type, customerNumber: created.customer_number });
}));

app.post("/auth/login", asyncRoute(async (req, res) => {
  const data = loginSchema.parse(req.body);
  const user = await findUser(data.identifier);
  if (!user) return res.status(404).json({ error: "Account not found." });
  if (!data.password || !(await bcrypt.compare(data.password, user.password_hash))) {
    return res.status(401).json({ error: "Incorrect password." });
  }
  res.json({ token: issueToken(user.id) });
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

app.get("/me", auth, asyncRoute(async (req, res) => {
  const result = await query(
    `select u.id,u.customer_number,u.first_name,u.last_name,u.email,u.country,u.created_at,u.account_status,
            up.plan_code as account_type, up.status as plan_status, up.demo_started_at, up.demo_expires_at, up.pro_started_at,
            pp.date_of_birth, pp.phone_code, pp.phone_number, pp.phone_verified,
            case when pp.date_of_birth is null then null else date_part('year', age(current_date, pp.date_of_birth))::int end as age,
            p.payment_status,p.onboarding_step,p.capital_amount,p.risk_level
     from users u
     left join user_plans up on up.user_id=u.id
     left join pro_profiles pp on pp.user_id=u.id
     left join client_profiles p on p.user_id=u.id
     where u.id=$1`,
    [req.userId]
  );
  res.json({ user: result.rows[0] });
}));

app.use((err, req, res, next) => {
  if (err instanceof z.ZodError) return res.status(400).json({ error: "Invalid input", details: err.errors });
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

export { app };

if (process.argv[1] && process.argv[1].endsWith("server.js")) {
  app.listen(port, () => {
    console.log(`Zukunft Trading API running on http://localhost:${port}`);
  });
}
