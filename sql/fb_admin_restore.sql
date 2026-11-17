-- 백업 JSON으로 복원 (교수 전용, 2026-11-17 적용). 지우는 동작 없음.
-- p_mode: 'missing' = 빠진 줄만 추가 / 'overwrite' = 추가 + 같은 키는 백업 내용으로 덮어쓰기
-- p_apply=false 이면 바뀔 개수만 셈(미리 보기)
create or replace function public.fb__restore_one(p_table text, p_keys text, p_rows jsonb, p_mode text, p_apply boolean, p_skip_data boolean default false)
returns jsonb language plpgsql security definer set search_path to 'public' as $$
declare cnt jsonb; setlist text; cmp text; k1 text := split_part(replace(p_keys, ' ', ''), ',', 1);
begin
  cmp := case when p_skip_data then 'to_jsonb(c) - ''data'' <> to_jsonb(b) - ''data''' else 'to_jsonb(c) <> to_jsonb(b)' end;
  execute format('select jsonb_build_object(''new'', count(*) filter (where c.%1$I is null), ''changed'', count(*) filter (where c.%1$I is not null and %2$s), ''same'', count(*) filter (where c.%1$I is not null and not (%2$s))) from jsonb_populate_recordset(null::public.%3$I, $1) b left join public.%3$I c using (%4$s)', k1, cmp, p_table, p_keys)
    into cnt using coalesce(p_rows, '[]'::jsonb);
  if p_apply then
    if p_mode = 'overwrite' then
      select string_agg(format('%I = excluded.%I', column_name, column_name), ', ') into setlist
        from information_schema.columns where table_schema = 'public' and table_name = p_table
         and column_name <> all (string_to_array(replace(p_keys, ' ', ''), ','));
      execute format('insert into public.%I select * from jsonb_populate_recordset(null::public.%I, $1) on conflict (%s) do update set %s', p_table, p_table, p_keys, setlist) using coalesce(p_rows, '[]'::jsonb);
    else
      execute format('insert into public.%I select * from jsonb_populate_recordset(null::public.%I, $1) on conflict (%s) do nothing', p_table, p_table, p_keys) using coalesce(p_rows, '[]'::jsonb);
    end if;
  end if;
  return cnt;
end $$;
revoke all on function public.fb__restore_one(text, text, jsonb, text, boolean, boolean) from public, anon, authenticated;

create or replace function public.fb_admin_restore(p_token text, p_tables jsonb, p_mode text, p_apply boolean)
returns jsonb language plpgsql security definer set search_path to 'public' as $$
declare s public.fb_sessions; r jsonb := '{}'; t text[]; files jsonb;
begin
  s := public.fb__admin(p_token);
  if s.token is null then return jsonb_build_object('error','auth'); end if;
  if p_mode not in ('missing','overwrite') then return jsonb_build_object('error','bad_mode'); end if;
  foreach t slice 1 in array array[['fb_settings','key'],['fb_teams','id'],['fb_weeks','week'],['fb_members','student_id'],['fb_submissions','team_id,week'],['fb_feedback','team_id,week']] loop
    r := r || jsonb_build_object(t[1], public.fb__restore_one(t[1], t[2], p_tables->t[1], p_mode, p_apply));
  end loop;
  select coalesce(jsonb_agg(e - 'data'), '[]') into files from jsonb_array_elements(coalesce(p_tables->'fb_files','[]')) e;
  r := r || jsonb_build_object('fb_files', public.fb__restore_one('fb_files', 'id', files, p_mode, false, true));
  return r;
end $$;

create or replace function public.fb_admin_restore_files(p_token text, p_files jsonb, p_mode text)
returns jsonb language plpgsql security definer set search_path to 'public' as $$
declare s public.fb_sessions; rows jsonb;
begin
  s := public.fb__admin(p_token);
  if s.token is null then return jsonb_build_object('error','auth'); end if;
  if p_mode not in ('missing','overwrite') then return jsonb_build_object('error','bad_mode'); end if;
  if jsonb_array_length(coalesce(p_files,'[]')) > 20 then return jsonb_build_object('error','too_many'); end if;
  select coalesce(jsonb_agg(e), '[]') into rows from jsonb_array_elements(coalesce(p_files,'[]')) e where coalesce(e->>'data','') <> '';
  return public.fb__restore_one('fb_files', 'id', rows, p_mode, true);
end $$;

revoke all on function public.fb_admin_restore(text, jsonb, text, boolean) from public;
revoke all on function public.fb_admin_restore_files(text, jsonb, text) from public;
grant execute on function public.fb_admin_restore(text, jsonb, text, boolean) to anon, authenticated;
grant execute on function public.fb_admin_restore_files(text, jsonb, text) to anon, authenticated;
