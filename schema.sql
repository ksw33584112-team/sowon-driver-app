-- ============================================================
-- 소원물류 기사앱 Supabase 스키마 (Phase 1)
-- 프로젝트: xmydkovpxivdyjxagnou  (팀플과 완전 무관)
-- 보안: 기사명+비번 자체 로그인 → RPC(SECURITY DEFINER)로만 접근.
--        테이블 직접 접근은 RLS로 차단(공개키 노출돼도 남의 정산 못 봄).
-- ============================================================
create extension if not exists pgcrypto with schema extensions;

-- ---------- 테이블 ----------
create table if not exists public.drivers (
  id            bigint generated always as identity primary key,
  driver_id     text unique,                 -- 정산 매핑용 ID (예: asdabc02@df)
  name          text not null unique,        -- 기사명 = 로그인 아이디
  rank          text default '일반',          -- 대표/총괄/팀장/조장/일반/백업
  role          text default 'driver',
  password_hash text not null,
  status        text default 'active',
  created_at    timestamptz default now()
);

create table if not exists public.weekly_schedules (
  id          bigint generated always as identity primary key,
  week_start  date not null,
  work_date   date not null,
  route       text,
  driver_name text,
  camp        text,
  changed_by  text,
  updated_at  timestamptz default now(),
  unique(work_date, route)
);

create table if not exists public.schedule_changes (
  id          bigint generated always as identity primary key,
  work_date   date, route text,
  old_driver  text, new_driver text,
  changed_by  text,
  changed_at  timestamptz default now()
);

create table if not exists public.settle_detail (
  id          bigint generated always as identity primary key,
  driver_name text not null,
  driver_id   text,
  year        int not null,
  month       int not null,
  detail_json jsonb,
  updated_at  timestamptz default now(),
  unique(driver_name, year, month)
);

create table if not exists public.monthly_stats (
  id          bigint generated always as identity primary key,
  driver_id   text,
  driver_name text,
  year        int, month int,
  gross       numeric, net numeric,
  updated_at  timestamptz default now(),
  unique(driver_name, year, month)
);

create table if not exists public.pback_somyeong (
  id          bigint generated always as identity primary key,
  period      text,
  driver_name text,
  route       text,
  photo_url1  text, photo_url2 text,
  reason      text,
  status      text default '제출',
  created_at  timestamptz default now()
);

create table if not exists public.app_settings (
  key        text primary key,
  value      jsonb,
  updated_at timestamptz default now()
);

create table if not exists public.driver_sessions (
  token       uuid primary key default gen_random_uuid(),
  driver_name text not null,
  created_at  timestamptz default now(),
  expires_at  timestamptz default (now() + interval '30 days')
);

-- ---------- RLS: 전부 켜고 정책 없음 = 공개키 직접접근 전면 차단 ----------
alter table public.drivers          enable row level security;
alter table public.weekly_schedules enable row level security;
alter table public.schedule_changes enable row level security;
alter table public.settle_detail    enable row level security;
alter table public.monthly_stats    enable row level security;
alter table public.pback_somyeong   enable row level security;
alter table public.app_settings     enable row level security;
alter table public.driver_sessions  enable row level security;

revoke all on all tables in schema public from anon, authenticated;

-- ---------- 내부: 세션 → 기사 ----------
create or replace function public._session_driver(p_token uuid)
returns public.drivers language plpgsql security definer
set search_path = public, extensions, pg_temp as $$
declare v_name text; v_d public.drivers%rowtype;
begin
  select driver_name into v_name from public.driver_sessions
    where token = p_token and expires_at > now();
  if v_name is null then raise exception 'invalid_or_expired_session'; end if;
  select * into v_d from public.drivers where name = v_name;
  return v_d;
end; $$;

-- ---------- 로그인 ----------
create or replace function public.driver_login(p_name text, p_pw text)
returns table(token uuid, name text, rank text, role text, status text)
language plpgsql security definer
set search_path = public, extensions, pg_temp as $$
declare v_d public.drivers%rowtype; v_tok uuid;
begin
  select * into v_d from public.drivers where drivers.name = p_name;
  if not found then return; end if;
  if v_d.status <> 'active' then return; end if;
  if v_d.password_hash is null
     or v_d.password_hash <> crypt(p_pw, v_d.password_hash) then return; end if;
  insert into public.driver_sessions(driver_name) values (v_d.name)
    returning driver_sessions.token into v_tok;
  return query select v_tok, v_d.name, v_d.rank, v_d.role, v_d.status;
end; $$;

-- ---------- 비밀번호 변경 ----------
create or replace function public.change_password(p_token uuid, p_old text, p_new text)
returns boolean language plpgsql security definer
set search_path = public, extensions, pg_temp as $$
declare v_d public.drivers%rowtype;
begin
  v_d := public._session_driver(p_token);
  if v_d.password_hash <> crypt(p_old, v_d.password_hash) then return false; end if;
  update public.drivers set password_hash = crypt(p_new, gen_salt('bf')) where name = v_d.name;
  return true;
end; $$;

-- ---------- 정산: 본인 것만 ----------
create or replace function public.get_my_settlement(p_token uuid, p_year int, p_month int)
returns jsonb language plpgsql security definer
set search_path = public, extensions, pg_temp as $$
declare v_d public.drivers%rowtype; v jsonb;
begin
  v_d := public._session_driver(p_token);
  select detail_json into v from public.settle_detail
    where driver_name = v_d.name and year = p_year and month = p_month;
  return v;
end; $$;

create or replace function public.get_my_months(p_token uuid)
returns table(year int, month int, gross numeric, net numeric)
language plpgsql security definer
set search_path = public, extensions, pg_temp as $$
declare v_d public.drivers%rowtype;
begin
  v_d := public._session_driver(p_token);
  return query select m.year, m.month, m.gross, m.net
    from public.monthly_stats m where m.driver_name = v_d.name
    order by m.year desc, m.month desc;
end; $$;

-- ---------- 스케줄: 조회(전체) / 수정(대표·총괄·팀장) ----------
create or replace function public.list_schedules(p_token uuid, p_week_start date)
returns setof public.weekly_schedules language plpgsql security definer
set search_path = public, extensions, pg_temp as $$
declare v_d public.drivers%rowtype;
begin
  v_d := public._session_driver(p_token);
  return query select * from public.weekly_schedules
    where week_start = p_week_start order by work_date, route;
end; $$;

create or replace function public.set_schedule_cell(
  p_token uuid, p_week_start date, p_work_date date,
  p_route text, p_driver text, p_camp text)
returns void language plpgsql security definer
set search_path = public, extensions, pg_temp as $$
declare v_d public.drivers%rowtype; v_old text;
begin
  v_d := public._session_driver(p_token);
  if v_d.rank not in ('대표','총괄','팀장') then raise exception 'no_permission'; end if;
  select driver_name into v_old from public.weekly_schedules
    where work_date = p_work_date and route = p_route;
  insert into public.weekly_schedules(week_start,work_date,route,driver_name,camp,changed_by)
    values (p_week_start,p_work_date,p_route,p_driver,p_camp,v_d.name)
    on conflict(work_date,route) do update
      set driver_name=excluded.driver_name, camp=excluded.camp,
          changed_by=v_d.name, updated_at=now();
  insert into public.schedule_changes(work_date,route,old_driver,new_driver,changed_by)
    values (p_work_date,p_route,v_old,p_driver,v_d.name);
end; $$;

-- ---------- 프백 소명: 제출 / 본인 목록 ----------
create or replace function public.submit_pback(
  p_token uuid, p_period text, p_route text,
  p_photo1 text, p_photo2 text, p_reason text)
returns bigint language plpgsql security definer
set search_path = public, extensions, pg_temp as $$
declare v_d public.drivers%rowtype; v_id bigint;
begin
  v_d := public._session_driver(p_token);
  insert into public.pback_somyeong(period,driver_name,route,photo_url1,photo_url2,reason)
    values (p_period,v_d.name,p_route,p_photo1,p_photo2,p_reason)
    returning id into v_id;
  return v_id;
end; $$;

create or replace function public.list_my_pback(p_token uuid, p_period text)
returns setof public.pback_somyeong language plpgsql security definer
set search_path = public, extensions, pg_temp as $$
declare v_d public.drivers%rowtype;
begin
  v_d := public._session_driver(p_token);
  return query select * from public.pback_somyeong
    where driver_name = v_d.name and (p_period is null or period = p_period)
    order by created_at desc;
end; $$;

-- ---------- 실행권한: 공개키(anon) 는 RPC만 호출 가능 ----------
revoke all on function
  public.driver_login(text,text),
  public.change_password(uuid,text,text),
  public.get_my_settlement(uuid,int,int),
  public.get_my_months(uuid),
  public.list_schedules(uuid,date),
  public.set_schedule_cell(uuid,date,date,text,text,text),
  public.submit_pback(uuid,text,text,text,text,text),
  public.list_my_pback(uuid,text)
  from public;
grant execute on function
  public.driver_login(text,text),
  public.change_password(uuid,text,text),
  public.get_my_settlement(uuid,int,int),
  public.get_my_months(uuid),
  public.list_schedules(uuid,date),
  public.set_schedule_cell(uuid,date,date,text,text,text),
  public.submit_pback(uuid,text,text,text,text,text),
  public.list_my_pback(uuid,text)
  to anon, authenticated;
-- 내부함수 _session_driver 는 외부호출 금지
revoke all on function public._session_driver(uuid) from public, anon, authenticated;

-- ---------- 스토리지: 프백 사진 버킷 ----------
insert into storage.buckets (id, name, public)
  values ('pback-images','pback-images', true)
  on conflict (id) do nothing;

drop policy if exists "pback read" on storage.objects;
create policy "pback read" on storage.objects
  for select to anon, authenticated using (bucket_id = 'pback-images');

drop policy if exists "pback upload" on storage.objects;
create policy "pback upload" on storage.objects
  for insert to anon, authenticated with check (bucket_id = 'pback-images');

-- ---------- 앱 설정 시드 (프백 구글폼 자리) ----------
insert into public.app_settings(key,value) values
  ('pback_config','{"google_form_url":"","entries":{}}'::jsonb)
  on conflict (key) do nothing;

-- ---------- 검증용 테스트 기사 (대표, 비번 1234) ----------
insert into public.drivers(driver_id,name,rank,role,password_hash)
  values ('TEST','테스트대표','대표','manager', crypt('1234', gen_salt('bf')))
  on conflict (name) do nothing;

select 'schema_ok' as result;
