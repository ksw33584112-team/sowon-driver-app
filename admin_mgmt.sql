-- ============================================================
-- 소원물류 관리자 기능 (권한 관리 + 연락처/차량) — 백엔드
-- 호출자가 대표/관리자일 때만 동작 (_is_admin 검증)
-- ============================================================
alter table public.drivers add column if not exists phone text;
alter table public.drivers add column if not exists vehicle_no text;
alter table public.drivers add column if not exists vehicle_type text;
alter table public.drivers add column if not exists birth text;
alter table public.drivers add column if not exists is_ev boolean default false;
alter table public.drivers add column if not exists is_admin boolean default false;
alter table public.drivers add column if not exists is_public boolean default true;
update public.drivers set is_admin=true where rank='대표';

-- 로그인: is_admin 도 반환하도록 갱신
create or replace function public.driver_login(p_name text, p_pw text)
returns table(token uuid, name text, rank text, role text, status text, is_admin boolean)
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare v_d public.drivers%rowtype; v_tok uuid;
begin
  select * into v_d from public.drivers where drivers.name = p_name;
  if not found then return; end if;
  if v_d.status <> 'active' then return; end if;
  if v_d.password_hash is null or v_d.password_hash <> crypt(p_pw, v_d.password_hash) then return; end if;
  insert into public.driver_sessions(driver_name) values (v_d.name) returning driver_sessions.token into v_tok;
  return query select v_tok, v_d.name, v_d.rank, v_d.role, v_d.status, coalesce(v_d.is_admin,false);
end; $$;

-- 내부: 관리자 확인
create or replace function public._is_admin(p_token uuid)
returns public.drivers language plpgsql security definer set search_path=public,pg_temp as $$
declare v public.drivers%rowtype;
begin
  v := public._session_driver(p_token);
  if v.rank='대표' or coalesce(v.is_admin,false) then return v; end if;
  raise exception 'not_admin';
end; $$;

-- 기사 목록 (관리자)
create or replace function public.admin_list_drivers(p_token uuid)
returns table(name text,driver_id text,rank text,role text,status text,is_admin boolean,is_public boolean,phone text,vehicle_no text,vehicle_type text,birth text,is_ev boolean)
language plpgsql security definer set search_path=public,pg_temp as $$
begin
  perform public._is_admin(p_token);
  return query select d.name,d.driver_id,d.rank,d.role,d.status,coalesce(d.is_admin,false),coalesce(d.is_public,true),
      d.phone,d.vehicle_no,d.vehicle_type,d.birth,coalesce(d.is_ev,false)
    from public.drivers d order by
      case d.rank when '대표' then 0 when '총괄' then 1 when '팀장' then 2 when '조장' then 3 when '일반' then 4 else 5 end, d.name;
end; $$;

-- 기사 정보 수정 (관리자)
create or replace function public.admin_update_driver(
  p_token uuid,p_name text,p_rank text,p_status text,p_is_admin boolean,
  p_phone text,p_vehicle_no text,p_vehicle_type text,p_birth text,p_is_ev boolean,p_is_public boolean)
returns void language plpgsql security definer set search_path=public,pg_temp as $$
begin
  perform public._is_admin(p_token);
  update public.drivers set
    rank=coalesce(p_rank,rank), status=coalesce(p_status,status), is_admin=coalesce(p_is_admin,is_admin),
    phone=coalesce(p_phone,phone), vehicle_no=coalesce(p_vehicle_no,vehicle_no),
    vehicle_type=coalesce(p_vehicle_type,vehicle_type), birth=coalesce(p_birth,birth),
    is_ev=coalesce(p_is_ev,is_ev), is_public=coalesce(p_is_public,is_public)
  where name=p_name;
end; $$;

-- PW 초기화 (관리자)
create or replace function public.admin_reset_pw(p_token uuid,p_name text)
returns void language plpgsql security definer set search_path=public,extensions,pg_temp as $$
begin
  perform public._is_admin(p_token);
  update public.drivers set password_hash=extensions.crypt('1234',extensions.gen_salt('bf')) where name=p_name;
end; $$;

-- 기사 추가 (관리자)
create or replace function public.admin_add_driver(p_token uuid,p_name text,p_rank text,p_phone text,p_vehicle_no text)
returns void language plpgsql security definer set search_path=public,extensions,pg_temp as $$
begin
  perform public._is_admin(p_token);
  insert into public.drivers(name,rank,phone,vehicle_no,password_hash)
    values(p_name,coalesce(nullif(p_rank,''),'일반'),p_phone,p_vehicle_no,extensions.crypt('1234',extensions.gen_salt('bf')))
    on conflict(name) do update set rank=excluded.rank,
      phone=coalesce(excluded.phone,drivers.phone), vehicle_no=coalesce(excluded.vehicle_no,drivers.vehicle_no);
end; $$;

grant execute on function
  public.admin_list_drivers(uuid),
  public.admin_update_driver(uuid,text,text,text,boolean,text,text,text,text,boolean,boolean),
  public.admin_reset_pw(uuid,text),
  public.admin_add_driver(uuid,text,text,text,text)
  to anon, authenticated;
revoke all on function public._is_admin(uuid) from public, anon, authenticated;

select 'admin_mgmt_ok' as r;
