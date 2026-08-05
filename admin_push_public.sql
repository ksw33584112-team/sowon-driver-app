-- ============================================================
-- 소원물류 PC → 클라우드 업로드용 관리자 RPC (Phase 2)
-- service_role(sb_secret) 대신 전용 admin_key로 인증. 폴더 이동 시에도 동일 동작.
-- ============================================================
alter table public.drivers add column if not exists camp text;

-- (관리자키는 저장소에 올리지 않고 별도 주입)

create or replace function public._admin_ok(p_key text)
returns boolean language sql security definer
set search_path = public, pg_temp as $$
  select exists(select 1 from public.app_settings where key='admin_key' and value = to_jsonb(p_key));
$$;

-- 기사 명단 업로드 (신규는 비번 1234, 기존은 비번 유지)
create or replace function public.admin_upsert_drivers(p_key text, p_rows jsonb)
returns int language plpgsql security definer
set search_path = public, extensions, pg_temp as $$
declare r jsonb; n int:=0;
begin
  if not public._admin_ok(p_key) then raise exception 'unauthorized'; end if;
  for r in select * from jsonb_array_elements(p_rows) loop
    insert into public.drivers(driver_id,name,rank,camp,password_hash)
      values (r->>'driver_id', r->>'name', coalesce(r->>'rank','일반'), r->>'camp', crypt('1234', gen_salt('bf')))
      on conflict (name) do update
        set driver_id=excluded.driver_id, rank=excluded.rank, camp=excluded.camp;
    n:=n+1;
  end loop; return n;
end; $$;

-- 주간 스케줄 업로드 (해당 주 통째 교체)
create or replace function public.admin_replace_week(p_key text, p_week_start date, p_rows jsonb)
returns int language plpgsql security definer
set search_path = public, pg_temp as $$
declare r jsonb; n int:=0;
begin
  if not public._admin_ok(p_key) then raise exception 'unauthorized'; end if;
  delete from public.weekly_schedules where week_start = p_week_start;
  for r in select * from jsonb_array_elements(p_rows) loop
    insert into public.weekly_schedules(week_start,work_date,route,driver_name,camp)
      values (p_week_start,(r->>'work_date')::date, r->>'route', r->>'driver_name', r->>'camp')
      on conflict (work_date,route) do update
        set driver_name=excluded.driver_name, camp=excluded.camp, week_start=excluded.week_start, updated_at=now();
    n:=n+1;
  end loop; return n;
end; $$;

-- 월 정산 명세서 업로드
create or replace function public.admin_upsert_settlement(p_key text, p_year int, p_month int, p_rows jsonb)
returns int language plpgsql security definer
set search_path = public, pg_temp as $$
declare r jsonb; n int:=0;
begin
  if not public._admin_ok(p_key) then raise exception 'unauthorized'; end if;
  for r in select * from jsonb_array_elements(p_rows) loop
    insert into public.settle_detail(driver_name,driver_id,year,month,detail_json)
      values (r->>'driver_name', r->>'driver_id', p_year, p_month, coalesce(r->'detail_json','{}'::jsonb))
      on conflict (driver_name,year,month) do update
        set detail_json=excluded.detail_json, driver_id=excluded.driver_id, updated_at=now();
    insert into public.monthly_stats(driver_name,driver_id,year,month,gross,net)
      values (r->>'driver_name', r->>'driver_id', p_year, p_month, (r->>'gross')::numeric, (r->>'net')::numeric)
      on conflict (driver_name,year,month) do update
        set gross=excluded.gross, net=excluded.net, updated_at=now();
    n:=n+1;
  end loop; return n;
end; $$;

revoke all on function public._admin_ok(text) from public, anon, authenticated;
grant execute on function
  public.admin_upsert_drivers(text,jsonb),
  public.admin_replace_week(text,date,jsonb),
  public.admin_upsert_settlement(text,int,int,jsonb)
  to anon, authenticated;

select 'admin_push_ok' as r;
