import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { app } from "./server.js";
import { pool, query } from "./db.js";

function post(port, path, body) {
  return fetch(`http://127.0.0.1:${port}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  }).then(async response => ({
    status: response.status,
    body: await response.json()
  }));
}

function authed(port, path, token, method = "GET", body) {
  return fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: body ? JSON.stringify(body) : undefined
  }).then(async response => ({ status: response.status, body: await response.json() }));
}

async function createPending({ email, accountType = "pro_live", emailOtp, phoneOtp, expires = "2 minutes" }) {
  const passwordHash = await bcrypt.hash("Password1", 12);
  const emailOtpHash = await bcrypt.hash(emailOtp, 12);
  const phoneOtpHash = phoneOtp ? await bcrypt.hash(phoneOtp, 12) : null;
  const result = await query(
    `insert into pending_signups
      (account_type, first_name, last_name, country, email, password_hash, date_of_birth, phone_code, phone_number,
       email_otp_hash, phone_otp_hash, expires_at)
     values ($1,'Flow','Test','Germany',$2,$3,$4,$5,$6,$7,$8,now()+interval '2 minutes')
     returning id`,
    [
      accountType,
      email,
      passwordHash,
      accountType === "pro_live" ? "2000-01-01" : null,
      accountType === "pro_live" ? "+49" : null,
      accountType === "pro_live" ? String(1700000000 + Math.floor(Math.random() * 999999)) : null,
      emailOtpHash,
      phoneOtpHash
    ]
  );
  return result.rows[0].id;
}

const server = app.listen(0, async () => {
  const port = server.address().port;
  const email = `flow-${Date.now()}@example.com`;
  const expiredEmail = `expired-${Date.now()}@example.com`;
  let exitCode = 0;

  try {
    const proId = await createPending({ email, accountType: "pro_live", emailOtp: "222222", phoneOtp: "333333" });
    const wrongPro = await post(port, "/auth/verify-signup", { signupRequestId: proId, emailOtp: "222222", phoneOtp: "000000" });
    const afterWrongPro = await query("select count(*)::int as count from users where email=$1 and account_type='pro_live'", [email]);
    const rightPro = await post(port, "/auth/verify-signup", { signupRequestId: proId, emailOtp: "222222", phoneOtp: "333333" });

    const expiredId = await createPending({ email: expiredEmail, emailOtp: "444444", phoneOtp: "555555" });
    await query("update pending_signups set expires_at=now()-interval '1 second' where id=$1", [expiredId]);
    const expiredResult = await post(port, "/auth/verify-signup", { signupRequestId: expiredId, emailOtp: "444444", phoneOtp: "555555" });

    const legacyDemoEmail = `legacy-demo-${Date.now()}@example.com`;
    const demoId = await createPending({ email: legacyDemoEmail, accountType: "starter_demo", emailOtp: "111111" });
    const demoResult = await post(port, "/auth/verify-signup", { signupRequestId: demoId, emailOtp: "111111" });

    const users = await query(
      `select u.id,u.customer_number,u.account_type,u.account_status,p.payment_status
       from users u join client_profiles p on p.user_id=u.id where u.email=$1`,
      [email]
    );
    const token = jwt.sign({ sub: users.rows[0].id }, process.env.JWT_SECRET || "dev-only-change-me", { expiresIn: "5m" });
    const paymentStatus = await authed(port, "/payments/status", token);
    const unpaidOnboarding = await authed(port, "/onboarding/status", token);
    console.log(JSON.stringify({
      wrongProStatus: wrongPro.status,
      proUsersAfterWrongPhone: afterWrongPro.rows[0].count,
      proStatus: rightPro.status,
      proCustomer: rightPro.body.customerNumber,
      expiredStatus: expiredResult.status,
      legacyDemoRejectedStatus: demoResult.status,
      paymentStatus: paymentStatus.status,
      unpaidOnboardingStatus: unpaidOnboarding.status,
      finalUsers: users.rows
    }, null, 2));
    await query("delete from pending_signups where email=$1", [legacyDemoEmail]);
  } catch (err) {
    exitCode = 1;
    console.error(err);
  } finally {
    await query("delete from users where email in ($1,$2)", [email, expiredEmail]);
    await query("delete from pending_signups where email in ($1,$2)", [email, expiredEmail]);
    await new Promise(resolve => server.close(resolve));
    await pool.end();
    process.exit(exitCode);
  }
});
