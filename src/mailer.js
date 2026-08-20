import nodemailer from "nodemailer";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is missing. Configure SMTP in .env to send OTP emails.`);
  return value;
}

export function hasEmailConfig() {
  return process.env.EMAIL_DELIVERY_MODE === "console" || Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

function labelForPurpose(purpose) {
  if (purpose === "starter_demo_signup") return "Free Demo account verification";
  if (purpose === "pro_live_signup") return "Pro Live account verification";
  if (purpose === "login") return "login verification";
  return "account verification";
}

export async function sendOtpEmail({ to, code, firstName, purpose = "account" }) {
  const label = labelForPurpose(purpose);
  if (process.env.EMAIL_DELIVERY_MODE === "console") {
    console.log(`[Zukunft OTP] ${label} email=${to} code=${code}`);
    return;
  }

  if (!hasEmailConfig()) {
    throw new Error("Email OTP service is not configured. Add SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS and SMTP_FROM in .env.");
  }

  const transporter = nodemailer.createTransport({
    host: required("SMTP_HOST"),
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || "false").toLowerCase() === "true",
    auth: {
      user: required("SMTP_USER"),
      pass: required("SMTP_PASS")
    }
  });

  await transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject: `Your Zukunft Trading ${label} code`,
    text: `Hello ${firstName || ""},\n\nYour Zukunft Trading ${label} code is: ${code}\n\nThis code expires in 2 minutes. If you did not request this, ignore this email.\n\nZukunft Trading\n`,
    html: `
      <div style="font-family:Arial,sans-serif;background:#050915;color:#eef6ff;padding:28px">
        <div style="max-width:560px;margin:auto;border:1px solid #1faee8;border-radius:20px;padding:26px;background:linear-gradient(180deg,#0d1b35,#07101f)">
          <div style="font-size:13px;letter-spacing:3px;text-transform:uppercase;color:#22d3ee;font-weight:800;margin-bottom:14px">Zukunft Trading</div>
          <h2 style="margin:0 0 12px;color:#f3f7ff">Verify your ${label}</h2>
          <p style="color:#c6d4ea;line-height:1.55">Hello ${firstName || ""},</p>
          <p style="color:#c6d4ea;line-height:1.55">Use this OTP to continue your Zukunft Trading setup. Your account will be created only after this code is verified.</p>
          <div style="font-size:30px;font-weight:800;letter-spacing:6px;color:#22d3ee;margin:18px 0">${code}</div>
          <p style="color:#9fb0ca;line-height:1.55">This code expires in <b>2 minutes</b>. If you did not request this, ignore this email.</p>
        </div>
      </div>
    `
  });
}

export async function sendAccountCreatedEmail({ to, firstName, customerNumber, accountType }) {
  const planName = accountType === "pro_live" ? "Pro Live" : "Free Demo";
  if (process.env.EMAIL_DELIVERY_MODE === "console") {
    console.log(`[Zukunft Account] ${planName} email=${to} customer=${customerNumber}`);
    return;
  }

  if (!hasEmailConfig()) {
    throw new Error("Email service is not configured. Add SMTP settings in .env.");
  }

  const transporter = nodemailer.createTransport({
    host: required("SMTP_HOST"),
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || "false").toLowerCase() === "true",
    auth: {
      user: required("SMTP_USER"),
      pass: required("SMTP_PASS")
    }
  });

  await transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject: `Your Zukunft Trading ${planName} account is ready`,
    text: `Hello ${firstName || ""},\n\nYour Zukunft Trading ${planName} account has been created.\n\nYour Zukunft ID is: ${customerNumber}\n\nKeep this ID for account support and future dashboard access.\n\nZukunft Trading\n`,
    html: `
      <div style="font-family:Arial,sans-serif;background:#050915;color:#eef6ff;padding:28px">
        <div style="max-width:560px;margin:auto;border:1px solid #1faee8;border-radius:20px;padding:26px;background:linear-gradient(180deg,#0d1b35,#07101f)">
          <div style="font-size:13px;letter-spacing:3px;text-transform:uppercase;color:#22d3ee;font-weight:800;margin-bottom:14px">Zukunft Trading</div>
          <h2 style="margin:0 0 12px;color:#f3f7ff">Your ${planName} account is ready</h2>
          <p style="color:#c6d4ea;line-height:1.55">Hello ${firstName || ""},</p>
          <p style="color:#c6d4ea;line-height:1.55">Your account has been created and verified successfully.</p>
          <div style="margin:20px 0;padding:18px;border-radius:16px;background:#081426;border:1px solid rgba(34,211,238,.35)">
            <div style="font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#8fa5c9;font-weight:800">Your Zukunft ID</div>
            <div style="font-size:28px;font-weight:900;letter-spacing:2px;color:#22d3ee;margin-top:8px">${customerNumber}</div>
          </div>
          <p style="color:#9fb0ca;line-height:1.55">Keep this ID for account support and future dashboard access.</p>
        </div>
      </div>
    `
  });
}

export function hasSmsConfig() {
  return Boolean(process.env.SMS_WEBHOOK_URL);
}

export async function sendPhoneOtp({ to, code }) {
  if (!hasSmsConfig()) {
    throw new Error("Phone OTP service is not configured. Add SMS_WEBHOOK_URL in .env before Pro phone verification can be used.");
  }

  const response = await fetch(process.env.SMS_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      to,
      message: `Your Zukunft Trading verification code is ${code}.`
    })
  });

  if (!response.ok) {
    throw new Error("Phone OTP could not be sent. Please try again.");
  }
}
