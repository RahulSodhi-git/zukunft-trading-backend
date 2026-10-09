import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import { pool, transaction } from "./db.js";

dotenv.config();

const email = String(process.env.SETUP_ACCOUNT_EMAIL || process.env.SMTP_USER || "").trim().toLowerCase();
const suppliedPassword = String(process.env.SETUP_ACCOUNT_PASSWORD || "").trim();
const password = suppliedPassword || `ZT-${crypto.randomBytes(12).toString("base64url")}9A`;
const customerNumber = "ZT-SETUP-001";

if (!email) {
  console.error("Set SETUP_ACCOUNT_EMAIL in .env, or configure SMTP_USER, before creating the setup account.");
  process.exit(1);
}

if (password.length < 12 || !/[A-Z]/.test(password) || !/\d/.test(password)) {
  console.error("SETUP_ACCOUNT_PASSWORD must be at least 12 characters and include an uppercase letter and a number.");
  process.exit(1);
}

const passwordHash = await bcrypt.hash(password, 12);

const account = await transaction(async client => {
  const existing = await client.query(
    "select id from users where lower(email)=lower($1) and account_type='pro_live' limit 1",
    [email]
  );

  let userId;
  if (existing.rows.length) {
    userId = existing.rows[0].id;
    await client.query(
      `update users
       set customer_number=$2, password_hash=$3, email_verified=true, phone_verified=true,
           account_status='active', updated_at=now()
       where id=$1`,
      [userId, customerNumber, passwordHash]
    );
  } else {
    const created = await client.query(
      `insert into users
        (customer_number,account_type,first_name,last_name,country,email,password_hash,email_verified,phone_verified,account_status)
       values ($1,'pro_live','Setup','Owner','Germany',$2,$3,true,true,'active')
       returning id`,
      [customerNumber, email, passwordHash]
    );
    userId = created.rows[0].id;
  }

  await client.query(
    `insert into user_plans (user_id,plan_code,status,pro_started_at)
     values ($1,'pro_live','active',now())
     on conflict (user_id) do update set
       plan_code='pro_live', status='active', pro_started_at=coalesce(user_plans.pro_started_at,now()), updated_at=now()`,
    [userId]
  );
  await client.query(
    `insert into pro_profiles (user_id,date_of_birth,phone_code,phone_number,phone_verified)
     values ($1,'1990-01-01','+49','0000000001',true)
     on conflict (user_id) do update set phone_verified=true, updated_at=now()`,
    [userId]
  );
  await client.query(
    `insert into client_profiles (user_id,payment_status,onboarding_step,paid_at)
     values ($1,'active','api_setup',now())
     on conflict (user_id) do update set
       payment_status='active', onboarding_step='api_setup', paid_at=coalesce(client_profiles.paid_at,now()), updated_at=now()`,
    [userId]
  );
  await client.query(
    "insert into client_bot_setups (user_id) values ($1) on conflict (user_id) do nothing",
    [userId]
  );

  return { userId, email, customerNumber };
});

console.log(JSON.stringify({
  ...account,
  password,
  paymentStatus: "active",
  note: "This is the only pre-activated setup account. Normal accounts still require payment."
}, null, 2));

await pool.end();
