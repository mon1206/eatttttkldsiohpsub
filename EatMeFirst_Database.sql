-- EatMeFirst Premium | Supabase PostgreSQL
-- Run once in Supabase > SQL Editor (with the project owner's privileges).
-- This script deliberately does NOT create an admin with a hard-coded email.
-- After signing up normally, grant admin using the separate SQL in SETUP.md.

create table if not exists public.emf_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create or replace function public.emf_is_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists(select 1 from public.emf_admins where user_id = (select auth.uid()));
$$;
revoke all on function public.emf_is_admin() from public;
grant execute on function public.emf_is_admin() to authenticated;

create table if not exists public.emf_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null default '',
  created_at timestamptz not null default now(),
  disabled boolean not null default false
);

create or replace function public.emf_user_created()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.emf_profiles(id,email,created_at)
  values (new.id,coalesce(new.email,''),coalesce(new.created_at,now()))
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;
drop trigger if exists emf_on_auth_user_created on auth.users;
create trigger emf_on_auth_user_created after insert on auth.users
for each row execute function public.emf_user_created();

-- Fill profiles for accounts that existed before this migration.
insert into public.emf_profiles(id,email,created_at)
select id,coalesce(email,''),coalesce(created_at,now()) from auth.users
on conflict (id) do update set email = excluded.email;

-- Maintain the displayed email if a member changes their login email.
create or replace function public.emf_user_email_changed()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  update public.emf_profiles set email=coalesce(new.email,'') where id=new.id;
  return new;
end;
$$;
drop trigger if exists emf_on_auth_user_updated on auth.users;
create trigger emf_on_auth_user_updated after update of email on auth.users
for each row execute function public.emf_user_email_changed();

create table if not exists public.emf_pantry (
  user_id uuid primary key references auth.users(id) on delete cascade,
  foods jsonb not null default '[]'::jsonb check(jsonb_typeof(foods)='array'),
  shopping jsonb not null default '[]'::jsonb check(jsonb_typeof(shopping)='array'),
  updated_at timestamptz not null default now()
);

create table if not exists public.emf_feedback (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  category text not null check(category in ('general','ai','bug','idea')),
  message text not null check(char_length(message) between 5 and 2000),
  status text not null default 'open' check(status in ('open','resolved')),
  created_at timestamptz not null default now()
);

create table if not exists public.emf_settings (
  id integer primary key check(id=1),
  alert_days integer not null default 3 check(alert_days between 1 and 14),
  announcement text not null default '' check(char_length(announcement)<=200),
  updated_at timestamptz not null default now()
);
insert into public.emf_settings(id) values(1) on conflict(id) do nothing;

create table if not exists public.emf_admin_audit (
  id bigint generated always as identity primary key,
  admin_id uuid not null references auth.users(id),
  action text not null,
  target_user uuid,
  detail jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table public.emf_admins enable row level security;
alter table public.emf_profiles enable row level security;
alter table public.emf_pantry enable row level security;
alter table public.emf_feedback enable row level security;
alter table public.emf_settings enable row level security;
alter table public.emf_admin_audit enable row level security;

-- Permissions: members cannot change admin roles or disabled status.
revoke all on public.emf_admins, public.emf_profiles, public.emf_pantry,
  public.emf_feedback, public.emf_settings, public.emf_admin_audit from anon, authenticated;
grant select on public.emf_admins to authenticated;
grant select on public.emf_profiles to authenticated;
grant select, insert, update on public.emf_pantry to authenticated;
grant select, insert on public.emf_feedback to authenticated;
grant select on public.emf_settings to authenticated;
grant select on public.emf_admin_audit to authenticated;

drop policy if exists emf_admin_self on public.emf_admins;
create policy emf_admin_self on public.emf_admins for select to authenticated
using(user_id=(select auth.uid()));

drop policy if exists emf_profile_view on public.emf_profiles;
create policy emf_profile_view on public.emf_profiles for select to authenticated
using(id=(select auth.uid()) or (select public.emf_is_admin()));

drop policy if exists emf_pantry_read on public.emf_pantry;
create policy emf_pantry_read on public.emf_pantry for select to authenticated
using(user_id=(select auth.uid()) and exists(
  select 1 from public.emf_profiles where id=(select auth.uid()) and not disabled));
drop policy if exists emf_pantry_insert on public.emf_pantry;
create policy emf_pantry_insert on public.emf_pantry for insert to authenticated
with check(user_id=(select auth.uid()) and exists(
  select 1 from public.emf_profiles where id=(select auth.uid()) and not disabled));
drop policy if exists emf_pantry_update on public.emf_pantry;
create policy emf_pantry_update on public.emf_pantry for update to authenticated
using(user_id=(select auth.uid()) and exists(
  select 1 from public.emf_profiles where id=(select auth.uid()) and not disabled))
with check(user_id=(select auth.uid()) and exists(
  select 1 from public.emf_profiles where id=(select auth.uid()) and not disabled));

drop policy if exists emf_feedback_view on public.emf_feedback;
create policy emf_feedback_view on public.emf_feedback for select to authenticated
using(user_id=(select auth.uid()) or (select public.emf_is_admin()));
drop policy if exists emf_feedback_insert on public.emf_feedback;
create policy emf_feedback_insert on public.emf_feedback for insert to authenticated
with check(user_id=(select auth.uid()) and status='open' and exists(
  select 1 from public.emf_profiles where id=(select auth.uid()) and not disabled));

drop policy if exists emf_settings_read on public.emf_settings;
create policy emf_settings_read on public.emf_settings for select to authenticated using(true);

drop policy if exists emf_audit_admin_read on public.emf_admin_audit;
create policy emf_audit_admin_read on public.emf_admin_audit for select to authenticated
using((select public.emf_is_admin()));

-- SQL functions run with privileges but verify the caller's admin role first.
create or replace function public.emf_admin_overview()
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare result jsonb;
begin
  if not public.emf_is_admin() then raise exception 'not authorized' using errcode='42501'; end if;
  with all_food as (
    select j.item from public.emf_pantry p cross join lateral jsonb_array_elements(p.foods) as j(item)
  )
  select jsonb_build_object(
    'members', (select count(*) from public.emf_profiles),
    'enabled_members',(select count(*) from public.emf_profiles where not disabled),
    'active_30d',(select count(*) from public.emf_pantry where updated_at>=now()-interval '30 days'),
    'foods',(select count(*) from all_food),
    'in_fridge',(select count(*) from all_food where item->>'status'='active'),
    'eaten',(select count(*) from all_food where item->>'status'='eaten'),
    'wasted',(select count(*) from all_food where item->>'status'='wasted'),
    'soon',(select count(*) from all_food where item->>'status'='active' and item->>'expiry'
      between current_date::text and (current_date+(select alert_days from public.emf_settings where id=1))::text),
    'expired',(select count(*) from all_food where item->>'status'='active' and item->>'expiry'<current_date::text),
    'feedback_open',(select count(*) from public.emf_feedback where status='open')
  ) into result;
  return result;
end; $$;

create or replace function public.emf_admin_members()
returns table(id uuid,email text,joined_at timestamptz,disabled boolean,food_count bigint,pantry_updated_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
begin
  if not public.emf_is_admin() then raise exception 'not authorized' using errcode='42501'; end if;
  return query select p.id,p.email,p.created_at,p.disabled,
    coalesce(jsonb_array_length(pa.foods),0)::bigint,pa.updated_at
  from public.emf_profiles p left join public.emf_pantry pa on pa.user_id=p.id
  order by p.created_at desc limit 1000;
end; $$;

create or replace function public.emf_admin_insights()
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare result jsonb;
begin
  if not public.emf_is_admin() then raise exception 'not authorized' using errcode='42501'; end if;
  with flat as (select j.item from public.emf_pantry p cross join lateral jsonb_array_elements(p.foods) as j(item)),
  cat as (select coalesce(nullif(item->>'category',''),'other') as name,count(*)::int as value from flat group by 1 order by 2 desc),
  trend as (select d::date as day, count(p.id)::int as value from generate_series(current_date-6,current_date,'1 day'::interval) d
    left join public.emf_profiles p on p.created_at::date=d::date group by d::date order by d::date)
  select jsonb_build_object(
    'categories',coalesce((select jsonb_agg(jsonb_build_object('name',name,'value',value)) from cat),'[]'::jsonb),
    'registrations',coalesce((select jsonb_agg(jsonb_build_object('day',day,'value',value)) from trend),'[]'::jsonb),
    'used_value',coalesce((select sum(case when item->>'status'='eaten' then
       case when (item->>'price') ~ '^[0-9]+(\.[0-9]+)?$' then (item->>'price')::numeric else 0 end else 0 end) from flat),0),
    'wasted_value',coalesce((select sum(case when item->>'status'='wasted' then
       case when (item->>'price') ~ '^[0-9]+(\.[0-9]+)?$' then (item->>'price')::numeric else 0 end else 0 end) from flat),0)
  ) into result;
  return result;
end; $$;

create or replace function public.emf_admin_set_disabled(target_id uuid, new_disabled boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
  if not public.emf_is_admin() then raise exception 'not authorized' using errcode='42501'; end if;
  if target_id=auth.uid() then raise exception 'cannot disable your own admin account'; end if;
  if exists(select 1 from public.emf_admins where user_id=target_id) then
    raise exception 'cannot disable another admin in this panel';
  end if;
  update public.emf_profiles set disabled=new_disabled where id=target_id;
  if not found then raise exception 'member not found'; end if;
  insert into public.emf_admin_audit(admin_id,action,target_user,detail)
  values(auth.uid(),'member_status',target_id,jsonb_build_object('disabled',new_disabled));
end; $$;

create or replace function public.emf_admin_resolve_feedback(target_id uuid, new_status text)
returns void language plpgsql security definer set search_path='' as $$
begin
  if not public.emf_is_admin() then raise exception 'not authorized' using errcode='42501'; end if;
  if new_status not in ('open','resolved') then raise exception 'invalid status'; end if;
  update public.emf_feedback set status=new_status where id=target_id;
  if not found then raise exception 'feedback not found'; end if;
  insert into public.emf_admin_audit(admin_id,action,detail)
  values(auth.uid(),'feedback_status',jsonb_build_object('feedback_id',target_id,'status',new_status));
end; $$;

create or replace function public.emf_admin_update_settings(new_alert_days integer,new_announcement text)
returns void language plpgsql security definer set search_path='' as $$
begin
  if not public.emf_is_admin() then raise exception 'not authorized' using errcode='42501'; end if;
  if new_alert_days not between 1 and 14 or char_length(new_announcement)>200 then
    raise exception 'invalid settings';
  end if;
  update public.emf_settings set alert_days=new_alert_days,announcement=new_announcement,updated_at=now() where id=1;
  insert into public.emf_admin_audit(admin_id,action,detail)
  values(auth.uid(),'settings_updated',jsonb_build_object('alert_days',new_alert_days));
end; $$;

revoke all on function public.emf_admin_overview(),public.emf_admin_members(),public.emf_admin_insights(),
  public.emf_admin_set_disabled(uuid,boolean),public.emf_admin_resolve_feedback(uuid,text),
  public.emf_admin_update_settings(integer,text) from public;
grant execute on function public.emf_admin_overview(),public.emf_admin_members(),public.emf_admin_insights(),
  public.emf_admin_set_disabled(uuid,boolean),public.emf_admin_resolve_feedback(uuid,text),
  public.emf_admin_update_settings(integer,text) to authenticated;

create index if not exists emf_feedback_created_idx on public.emf_feedback(created_at desc);
create index if not exists emf_profiles_joined_idx on public.emf_profiles(created_at desc);

-- Verify RLS policies before collecting real users' data.
