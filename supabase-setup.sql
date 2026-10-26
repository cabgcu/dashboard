-- ============================================================
-- CAB Event Dashboard — Supabase setup for the login screen
--
-- Run it in Supabase → SQL Editor for the same project the VIP Check In
-- app uses (it relies on verify_admin_password from that app's
-- supabase-setup.sql, section 5). Safe to run more than once; no data is
-- dropped or overwritten.
--
-- The dashboard password is kept here only as a bcrypt hash, next to the
-- Google Sheet ID, in a table with RLS on and no policies, so the page's
-- publishable key can't read either one. The page only gets the Sheet ID
-- back from dashboard_login() after the right password is entered.
-- ============================================================

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.dashboard_secret (
    id            int primary key default 1 check (id = 1),
    password_hash text not null,
    sheet_id      text not null
);

alter table public.dashboard_secret enable row level security;
revoke all on public.dashboard_secret from anon, authenticated;

-- Tells the page whether to show "Create a password" or "Log in".
create or replace function public.dashboard_is_setup()
returns boolean language sql stable security definer set search_path = public as $$
    select exists (select 1 from public.dashboard_secret where id = 1)
$$;

-- Returns the Sheet ID when the password is right, otherwise null.
create or replace function public.dashboard_login(pass text)
returns text language sql stable security definer set search_path = public, extensions as $$
    select sheet_id from public.dashboard_secret
    where id = 1 and password_hash = extensions.crypt(coalesce(pass, ''), password_hash)
$$;

-- First-time setup from the login screen. Only works while no dashboard
-- password exists, and only for someone who knows the VIP Check In staff
-- password. Returns false if the staff password is wrong or setup was
-- already done.
create or replace function public.dashboard_setup(staff_pass text, new_pass text, new_sheet_id text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
    if coalesce(new_pass, '') = '' or coalesce(new_sheet_id, '') = '' then
        raise exception 'Password and Sheet ID are required';
    end if;
    if not public.verify_admin_password(staff_pass) then
        return false;
    end if;
    insert into public.dashboard_secret (id, password_hash, sheet_id)
    values (1, extensions.crypt(new_pass, extensions.gen_salt('bf')), new_sheet_id)
    on conflict (id) do nothing;
    return found;
end $$;

-- Security settings inside the dashboard. Pass null to leave the password
-- or the Sheet ID as it is. Returns false if the current password is wrong.
create or replace function public.dashboard_update(current_pass text, new_pass text, new_sheet_id text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
    if public.dashboard_login(current_pass) is null then
        return false;
    end if;
    update public.dashboard_secret
       set password_hash = case when coalesce(new_pass, '') = '' then password_hash
                                else extensions.crypt(new_pass, extensions.gen_salt('bf')) end,
           sheet_id      = coalesce(nullif(new_sheet_id, ''), sheet_id)
     where id = 1;
    return true;
end $$;

revoke all on function public.dashboard_is_setup() from public;
revoke all on function public.dashboard_login(text) from public;
revoke all on function public.dashboard_setup(text, text, text) from public;
revoke all on function public.dashboard_update(text, text, text) from public;
grant execute on function public.dashboard_is_setup() to anon, authenticated;
grant execute on function public.dashboard_login(text) to anon, authenticated;
grant execute on function public.dashboard_setup(text, text, text) to anon, authenticated;
grant execute on function public.dashboard_update(text, text, text) to anon, authenticated;

-- Forgot the dashboard password? Run this on its own, then reload the
-- dashboard: it shows the "Create a password" screen again (you'll need the
-- VIP Check In password and the Google Sheet link).
-- delete from public.dashboard_secret where id = 1;
