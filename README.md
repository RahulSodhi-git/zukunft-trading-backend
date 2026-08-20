# Zukunft Trading Backend

Local PostgreSQL-backed API for client signup, OTP verification and login.

## Current backend slice

This backend currently handles the account layer only:

- Free Demo signup: stores a pending signup first, sends email OTP, then creates the account only after email OTP is correct.
- Pro Live signup: stores a pending signup first, then creates the account only after email OTP and phone OTP are both correct.
- Free Demo account: first name, last name, country, email, password hash, 2-day demo plan, customer number starting with `D`.
- Pro Live account: common user row plus Pro profile with DOB and phone, customer number starting with `P`.
- The same email can have one Demo account and one Pro account. Duplicate Demo-for-same-email or duplicate Pro-for-same-email is blocked.
- Passwords are stored as bcrypt hashes, never as plain text.
- Binance API keys are not stored in the database.
- Only one signup OTP request is allowed per email every 2 minutes.
- OTP codes expire after 2 minutes. A wrong OTP does not create an account; the same latest OTP can still be retried until it expires.

## Setup

1. Copy `.env.example` to `.env`.
2. Put your local PostgreSQL password in `DATABASE_URL`.
3. Create the database:

```powershell
& "C:\Program Files\PostgreSQL\18\bin\createdb.exe" -h localhost -U postgres zukunft_trading
```

4. Install packages and migrate:

```powershell
npm install
npm run db:migrate
npm run dev
```

The API runs at `http://localhost:5050`.

OTP codes are sent by email through SMTP. They are never returned to the frontend or shown on the account form.
Pro phone OTP requires `SMS_WEBHOOK_URL` before Pro signup can be used.

For local testing without SMTP, set this in `.env`:

```text
EMAIL_DELIVERY_MODE=console
```

The OTP will print in the backend terminal only. Do not use console mode for live deployment.

Run the account-flow verification test:

```powershell
npm run test:account
```

## Live deployment notes

Deploy this backend separately from the frontend. Good beginner options are Render, Railway, or a VPS.

Required environment variables:

```text
PORT=5050
DATABASE_URL=postgres://...
JWT_SECRET=use-a-long-random-secret
FRONTEND_ORIGIN=https://zukunfttrading.com,https://www.zukunfttrading.com
EMAIL_DELIVERY_MODE=smtp
SMTP_HOST=smtp provider host
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=no-reply@zukunfttrading.com
SMTP_PASS=smtp password or app password
SMTP_FROM="Zukunft Trading <no-reply@zukunfttrading.com>"
SMS_WEBHOOK_URL=
ACCOUNT_EMAIL_DELAY_MS=60000
```

After deployment, point the frontend API to:

```text
https://api.zukunfttrading.com
```

## Account tables

- `users`: common account identity.
- `pending_signups`: temporary unverified signup data.
- `user_plans`: `starter_demo` or `pro_live`, including demo expiry.
- `pro_profiles`: Pro-only fields, created only for Pro users.
- `otp_codes`: hashed email, phone and login OTPs.
