import assert from "node:assert/strict";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

process.env.PAYPAL_MODE = "sandbox";
process.env.PAYPAL_CLIENT_ID = "test-client";
process.env.PAYPAL_CLIENT_SECRET = "test-secret";

const realFetch = globalThis.fetch;
let paypalUserId;

globalThis.fetch = async (url, options = {}) => {
  const value = String(url);
  if (value === "https://api-m.sandbox.paypal.com/v1/oauth2/token") {
    return new Response(JSON.stringify({ access_token: "test-access-token" }), { status: 200, headers: { "Content-Type": "application/json" } });
  }
  if (value === "https://api-m.sandbox.paypal.com/v2/checkout/orders" && options.method === "POST") {
    const body = JSON.parse(options.body);
    paypalUserId = body.purchase_units[0].custom_id;
    assert.equal(body.purchase_units[0].amount.value, "100.00");
    assert.equal(body.purchase_units[0].amount.currency_code, "USD");
    return new Response(JSON.stringify({
      id: "TEST-PAYPAL-ORDER-100",
      status: "PAYER_ACTION_REQUIRED",
      links: [{ rel: "payer-action", href: "https://www.sandbox.paypal.com/checkoutnow?token=TEST-PAYPAL-ORDER-100" }]
    }), { status: 201, headers: { "Content-Type": "application/json" } });
  }
  if (value.endsWith("/v2/checkout/orders/TEST-PAYPAL-ORDER-100/capture") && options.method === "POST") {
    return new Response(JSON.stringify({
      id: "TEST-PAYPAL-ORDER-100",
      status: "COMPLETED",
      purchase_units: [{
        custom_id: paypalUserId,
        amount: { currency_code: "USD", value: "100.00" },
        payments: { captures: [{ id: "TEST-CAPTURE-100", status: "COMPLETED", amount: { currency_code: "USD", value: "100.00" } }] }
      }]
    }), { status: 201, headers: { "Content-Type": "application/json" } });
  }
  return realFetch(url, options);
};

const [{ app }, { pool, query }] = await Promise.all([import("./server.js"), import("./db.js")]);

function api(port, path, token, body) {
  return realFetch(`http://127.0.0.1:${port}${path}`, {
    method: body ? "POST" : "GET",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: body ? JSON.stringify(body) : undefined
  }).then(async response => ({ status: response.status, body: await response.json() }));
}

const server = app.listen(0, async () => {
  const email = `paypal-flow-${Date.now()}@example.com`;
  let userId;
  let exitCode = 0;
  try {
    const passwordHash = await bcrypt.hash("Password1", 12);
    const created = await query(
      `insert into users (customer_number,account_type,first_name,last_name,country,email,password_hash,email_verified,phone_verified,account_status)
       values ($1,'pro_live','PayPal','Flow','India',$2,$3,true,false,'pending_payment') returning id`,
      [`PAYPAL${Date.now()}`, email, passwordHash]
    );
    userId = created.rows[0].id;
    await query("insert into user_plans (user_id,plan_code,status) values ($1,'pro_live','pending_payment')", [userId]);
    await query("insert into pro_profiles (user_id,date_of_birth,phone_code,phone_number,phone_verified) values ($1,'2000-01-01','+91',$2,false)", [userId, String(9000000000 + Math.floor(Math.random() * 99999999))]);
    await query("insert into client_profiles (user_id) values ($1)", [userId]);
    await query("insert into client_bot_setups (user_id) values ($1)", [userId]);

    const token = jwt.sign({ sub: userId }, process.env.JWT_SECRET || "dev-only-change-me", { expiresIn: "5m" });
    const checkout = await api(server.address().port, "/payments/checkout", token, {});
    assert.equal(checkout.status, 201);
    assert.equal(checkout.body.orderId, "TEST-PAYPAL-ORDER-100");

    const confirm = await api(server.address().port, "/payments/confirm", token, { orderId: checkout.body.orderId });
    assert.equal(confirm.status, 200);
    assert.equal(confirm.body.active, true);

    const payment = await query("select payment_status,paypal_order_id,paypal_capture_id from client_profiles where user_id=$1", [userId]);
    assert.deepEqual(payment.rows[0], {
      payment_status: "active",
      paypal_order_id: "TEST-PAYPAL-ORDER-100",
      paypal_capture_id: "TEST-CAPTURE-100"
    });
    console.log(JSON.stringify({ checkoutStatus: checkout.status, confirmStatus: confirm.status, payment: payment.rows[0] }, null, 2));
  } catch (err) {
    exitCode = 1;
    console.error(err);
  } finally {
    if (userId) await query("delete from users where id=$1", [userId]);
    await new Promise(resolve => server.close(resolve));
    await pool.end();
    globalThis.fetch = realFetch;
    process.exitCode = exitCode;
  }
});
