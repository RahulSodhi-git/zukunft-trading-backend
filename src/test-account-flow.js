import bcrypt from "bcryptjs";
import { app } from "./server.js";
import { query } from "./db.js";

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

async function createPending({ email, accountType, emailOtp, phoneOtp }) {
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
      accountType === "pro_live" ? "1701234567" : null,
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

  try {
    const demoId = await createPending({ email, accountType: "starter_demo", emailOtp: "111111" });
    const wrongDemo = await post(port, "/auth/verify-signup", { signupRequestId: demoId, emailOtp: "000000" });
    const afterWrongDemo = await query("select count(*)::int as count from users where email=$1", [email]);
    const rightDemo = await post(port, "/auth/verify-signup", { signupRequestId: demoId, emailOtp: "111111" });

    const proId = await createPending({ email, accountType: "pro_live", emailOtp: "222222", phoneOtp: "333333" });
    const wrongPro = await post(port, "/auth/verify-signup", { signupRequestId: proId, emailOtp: "222222", phoneOtp: "000000" });
    const afterWrongPro = await query("select count(*)::int as count from users where email=$1 and account_type='pro_live'", [email]);
    const rightPro = await post(port, "/auth/verify-signup", { signupRequestId: proId, emailOtp: "222222", phoneOtp: "333333" });

    const expiredPasswordHash = await bcrypt.hash("Password1", 12);
    const expiredOtpHash = await bcrypt.hash("444444", 12);
    const expired = await query(
      `insert into pending_signups (account_type, first_name, last_name, country, email, password_hash, email_otp_hash, expires_at)
       values ('starter_demo','Expired','Test','Germany',$1,$2,$3,now()-interval '1 second') returning id`,
      [expiredEmail, expiredPasswordHash, expiredOtpHash]
    );
    const expiredResult = await post(port, "/auth/verify-signup", { signupRequestId: expired.rows[0].id, emailOtp: "444444" });

    const users = await query("select customer_number, account_type from users where email=$1 order by account_type", [email]);
    console.log(JSON.stringify({
      wrongDemoStatus: wrongDemo.status,
      usersAfterWrongDemo: afterWrongDemo.rows[0].count,
      demoStatus: rightDemo.status,
      demoCustomer: rightDemo.body.customerNumber,
      wrongProStatus: wrongPro.status,
      proUsersAfterWrongPhone: afterWrongPro.rows[0].count,
      proStatus: rightPro.status,
      proCustomer: rightPro.body.customerNumber,
      expiredStatus: expiredResult.status,
      finalUsers: users.rows
    }, null, 2));
  } finally {
    await query("delete from users where email in ($1,$2)", [email, expiredEmail]);
    await query("delete from pending_signups where email in ($1,$2)", [email, expiredEmail]);
    server.close();
  }
});
