# Zukunft Trading Backend

PostgreSQL-backed API for Pro signup, OTP verification, Stripe subscription payment and bot onboarding.

## Current backend slice

The backend handles the complete Pro onboarding gate:

- Pro Live signup creates a pending signup and creates the account only after email and phone OTP verification.
- Login requires the password followed by an email OTP.
- Stripe Checkout activates the $100/month Pro subscription.
- API verification, capital setup and bot controls require an active payment.
- Customer numbers use `AyyyymmddNN` based on the Europe/Berlin business date.
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
PUBLIC_FRONTEND_URL=https://zukunfttrading.com
SMTP_HOST=smtp provider host
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=no-reply@zukunfttrading.com
SMTP_PASS=smtp password or app password
SMTP_FROM="Zukunft Trading <no-reply@zukunfttrading.com>"
SMS_WEBHOOK_URL=
ACCOUNT_EMAIL_DELAY_MS=60000
STRIPE_SECRET_KEY=sk_live_or_test_key
STRIPE_PRICE_ID=price_optional_existing_100_usd_monthly_price
STRIPE_WEBHOOK_SECRET=whsec_from_stripe_webhook
```

After deployment, point the frontend API to:

```text
https://api.zukunfttrading.com
```

Configure the Stripe webhook endpoint as:

```text
https://zukunft-trading-backend.onrender.com/payments/webhook
```

Subscribe it to `checkout.session.completed` and `customer.subscription.deleted`. If `STRIPE_PRICE_ID` is empty, the backend creates a $100 USD monthly line item directly in each Checkout Session.

## Account tables

- `users`: common account identity.
- `pending_signups`: temporary unverified signup data.
- `user_plans`: active Pro plan and subscription state. Legacy demo rows can remain for historical compatibility but cannot be created or used by the API.
- `pro_profiles`: Pro-only fields, created only for Pro users.
- `otp_codes`: hashed email, phone and login OTPs.
- `client_profiles`: payment state and Stripe references.
- `client_bot_setups`: API connection status, capital and bot state. API secrets are never stored.
