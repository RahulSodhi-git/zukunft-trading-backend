create extension if not exists pgcrypto;

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  customer_number text unique,
  account_type text not null default 'starter_demo' check (account_type in ('starter_demo','pro_live')),
  first_name text not null,
  last_name text not null,
  country text not null,
  email text not null,
  password_hash text not null,
  email_verified boolean not null default false,
  account_status text not null default 'pending_verification',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

do $$
begin
  if exists (select 1 from information_schema.columns where table_name='users' and column_name='date_of_birth') then
    alter table users alter column date_of_birth drop not null;
  end if;

  if exists (select 1 from information_schema.columns where table_name='users' and column_name='phone') then
    alter table users alter column phone drop not null;
  end if;

  if exists (select 1 from pg_constraint where conname='users_phone_key') then
    alter table users drop constraint users_phone_key;
  end if;

  if exists (select 1 from pg_constraint where conname='users_email_key') then
    alter table users drop constraint users_email_key;
  end if;
end $$;

alter table users add column if not exists phone_verified boolean not null default false;
alter table users add column if not exists customer_number text unique;
alter table users add column if not exists account_type text not null default 'starter_demo';
alter table users drop column if exists date_of_birth;
alter table users drop column if exists phone;
alter table users drop column if exists phone_code;

create table if not exists pending_signups (
  id uuid primary key default gen_random_uuid(),
  account_type text not null check (account_type in ('starter_demo','pro_live')),
  first_name text not null,
  last_name text not null,
  country text not null,
  email text not null,
  password_hash text not null,
  date_of_birth date,
  phone_code text,
  phone_number text,
  email_otp_hash text not null,
  phone_otp_hash text,
  email_verified_at timestamptz,
  phone_verified_at timestamptz,
  expires_at timestamptz not null,
  last_otp_sent_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (
    (account_type = 'starter_demo' and date_of_birth is null and phone_code is null and phone_number is null and phone_otp_hash is null)
    or
    (account_type = 'pro_live' and date_of_birth is not null and phone_code is not null and phone_number is not null and phone_otp_hash is not null)
  )
);

create table if not exists plans (
  code text primary key,
  name text not null,
  created_at timestamptz not null default now()
);

insert into plans (code, name) values
  ('starter_demo', 'Starter Demo'),
  ('pro_live', 'Pro Live')
on conflict (code) do nothing;

create table if not exists user_plans (
  user_id uuid primary key references users(id) on delete cascade,
  plan_code text not null references plans(code),
  status text not null default 'pending_verification',
  demo_started_at timestamptz,
  demo_expires_at timestamptz,
  pro_started_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (
    (plan_code = 'starter_demo' and demo_started_at is not null and demo_expires_at is not null)
    or
    (plan_code = 'pro_live')
  )
);

create table if not exists pro_profiles (
  user_id uuid primary key references users(id) on delete cascade,
  date_of_birth date not null,
  phone_code text not null,
  phone_number text not null,
  phone_verified boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (phone_code, phone_number)
);

create table if not exists otp_codes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  target text not null check (target in ('email','phone','login')),
  code_hash text not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  token_hash text not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create table if not exists client_profiles (
  user_id uuid primary key references users(id) on delete cascade,
  payment_status text not null default 'not_started',
  onboarding_step text not null default 'account_verification',
  capital_amount numeric(18,2),
  risk_level text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists country_options (
  name text primary key,
  is_default boolean not null default false,
  created_at timestamptz not null default now()
);

drop table if exists exchange_api_keys;

create index if not exists idx_otp_codes_user_target on otp_codes(user_id, target);
create index if not exists idx_sessions_user_id on sessions(user_id);
create index if not exists idx_user_plans_plan_code on user_plans(plan_code);
create index if not exists idx_pending_signups_email on pending_signups(lower(email));
create index if not exists idx_users_customer_number on users(customer_number);
create unique index if not exists idx_users_email_account_type on users(lower(email), account_type);

insert into country_options (name, is_default) values
  ('Germany', true),('India', true),('United States', true),('United Kingdom', true),('United Arab Emirates', true),
  ('France', true),('Italy', true),('Spain', true),('Netherlands', true),('Switzerland', true),('Austria', true),
  ('Belgium', true),('Sweden', true),('Norway', true),('Denmark', true),('Finland', true),('Ireland', true),
  ('Poland', true),('Portugal', true),('Greece', true),('Turkey', true),('Singapore', true),('Japan', true),
  ('South Korea', true),('China', true),('Hong Kong', true),('Thailand', true),('Malaysia', true),('Indonesia', true),
  ('Philippines', true),('Vietnam', true),('Australia', true),('Canada', true),('Brazil', true),('South Africa', true),
  ('Saudi Arabia', true),('Qatar', true),('Kuwait', true),('Other', true)
on conflict (name) do nothing;
