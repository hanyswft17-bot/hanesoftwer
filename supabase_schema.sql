-- HANI SOFTWARE: starter schema for Supabase Auth.
-- Review and run in a NEW Supabase project. Do not use custom password tables.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  phone text unique,
  role text not null default 'customer' check (role in ('customer','admin','dealer','distributor')),
  wallet_usd numeric(14,2) not null default 0 check (wallet_usd >= 0),
  created_at timestamptz not null default now()
);

create table if not exists public.settings (
  key text primary key,
  value text not null,
  updated_at timestamptz not null default now()
);
insert into public.settings(key,value) values ('usd_rate_sdg','3000')
on conflict (key) do nothing;

create table if not exists public.categories (
  id text primary key,
  name_ar text not null,
  name_en text not null,
  icon text,
  active boolean not null default true,
  sort_order int not null default 0
);

create table if not exists public.services (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  category_id text references public.categories(id),
  name_ar text not null,
  name_en text not null,
  description_ar text,
  description_en text,
  price numeric(14,2) not null default 0 check (price >= 0),
  currency text not null default 'USD' check (currency in ('USD','SDG')),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id),
  service_id uuid not null references public.services(id),
  customer_note text,
  device_identifier text,
  price_original numeric(14,2) not null,
  currency_original text not null check (currency_original in ('USD','SDG')),
  usd_rate_at_order numeric(14,2) not null,
  charged_usd numeric(14,2) not null check (charged_usd >= 0),
  status text not null default 'new' check (status in ('new','processing','completed','rejected','needs_info')),
  admin_reply text,
  created_at timestamptz not null default now()
);

create table if not exists public.wallet_transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id),
  order_id uuid references public.orders(id),
  kind text not null check (kind in ('topup','service_charge','refund','admin_adjustment')),
  amount_usd numeric(14,2) not null,
  balance_after_usd numeric(14,2) not null check (balance_after_usd >= 0),
  description text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.topup_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id),
  username text,
  email text,
  amount_sdg numeric(14,2) not null check (amount_sdg > 0),
  payment_reference text,
  note text,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now(),
  check (username is not null or email is not null)
);

create index if not exists orders_user_created_idx on public.orders(user_id,created_at desc);
create index if not exists wallet_user_created_idx on public.wallet_transactions(user_id,created_at desc);
create index if not exists services_category_idx on public.services(category_id,active);

-- Role helper reads role from the signed-in user's own profile.
create or replace function public.current_user_role()
returns text language sql stable security definer set search_path=public
as $$ select role from public.profiles where id=auth.uid() $$;

alter table public.profiles enable row level security;
alter table public.settings enable row level security;
alter table public.categories enable row level security;
alter table public.services enable row level security;
alter table public.orders enable row level security;
alter table public.wallet_transactions enable row level security;
alter table public.topup_requests enable row level security;

-- Profiles: customers can read/update only their own non-privileged fields.
create policy "profiles read own or admin" on public.profiles for select to authenticated
using (id=auth.uid() or public.current_user_role()='admin');
create policy "profiles update own basic" on public.profiles for update to authenticated
using (id=auth.uid()) with check (id=auth.uid() and role = (select p.role from public.profiles p where p.id=auth.uid()));

-- Public catalog read; writes restricted to admin.
create policy "active categories readable" on public.categories for select to anon,authenticated using (active or public.current_user_role()='admin');
create policy "active services readable" on public.services for select to anon,authenticated using (active or public.current_user_role()='admin');
create policy "admin manage categories" on public.categories for all to authenticated using (public.current_user_role()='admin') with check (public.current_user_role()='admin');
create policy "admin manage services" on public.services for all to authenticated using (public.current_user_role()='admin') with check (public.current_user_role()='admin');
create policy "settings read authenticated" on public.settings for select to authenticated using (true);
create policy "admin manage settings" on public.settings for all to authenticated using (public.current_user_role()='admin') with check (public.current_user_role()='admin');

create policy "orders owner or admin read" on public.orders for select to authenticated using (user_id=auth.uid() or public.current_user_role()='admin');
create policy "admin update orders" on public.orders for update to authenticated using (public.current_user_role()='admin') with check (public.current_user_role()='admin');
create policy "wallet owner or admin read" on public.wallet_transactions for select to authenticated using (user_id=auth.uid() or public.current_user_role()='admin');
create policy "topups owner or admin read" on public.topup_requests for select to authenticated using (user_id=auth.uid() or public.current_user_role()='admin');
create policy "topups owner create" on public.topup_requests for insert to authenticated with check (user_id=auth.uid());
create policy "admin update topups" on public.topup_requests for update to authenticated using (public.current_user_role()='admin') with check (public.current_user_role()='admin');

-- Do not allow browser clients to directly insert orders or wallet ledger entries.
revoke insert, update, delete on public.orders from anon,authenticated;
revoke insert, update, delete on public.wallet_transactions from anon,authenticated;
revoke update, delete on public.profiles from anon,authenticated;
grant select on public.categories,public.services to anon,authenticated;
grant select on public.profiles,public.orders,public.wallet_transactions,public.topup_requests,public.settings to authenticated;
grant insert on public.topup_requests to authenticated;

-- IMPORTANT:
-- Create a SECURITY DEFINER RPC / Edge Function for order placement and wallet debit.
-- It must validate auth.uid(), active service, current exchange rate, sufficient balance,
-- insert the order and ledger entry, and debit the wallet in one database transaction.
-- Do not trust a price, currency conversion, user_id, role, or balance sent by the browser.
-- Promote the first admin manually from the SQL editor after creating their Auth account:
-- update public.profiles set role='admin' where id='AUTH-USER-UUID';
