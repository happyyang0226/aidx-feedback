-- 교수 전용 JSON 백업 함수 (2026-11-17 적용 · 읽기 전용, 기존 데이터 변경 없음)
create or replace function public.fb_admin_backup(p_token text)
returns jsonb language plpgsql security definer set search_path to 'public' as $$
declare s public.fb_sessions;
begin
  s := public.fb__admin(p_token);
  if s.token is null then return jsonb_build_object('error','auth'); end if;
  return jsonb_build_object(
    'app', 'aidx-feedback', 'format', 1, 'exported_at', now(),
    'tables', jsonb_build_object(
      'fb_settings',    coalesce((select jsonb_agg(to_jsonb(x) order by x.key) from public.fb_settings x), '[]'),
      'fb_teams',       coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.id) from public.fb_teams x), '[]'),
      'fb_weeks',       coalesce((select jsonb_agg(to_jsonb(x) order by x.week) from public.fb_weeks x), '[]'),
      'fb_members',     coalesce((select jsonb_agg(to_jsonb(x) order by x.team_id, x.student_id) from public.fb_members x), '[]'),
      'fb_submissions', coalesce((select jsonb_agg(to_jsonb(x) order by x.team_id, x.week) from public.fb_submissions x), '[]'),
      'fb_feedback',    coalesce((select jsonb_agg(to_jsonb(x) order by x.team_id, x.week) from public.fb_feedback x), '[]'),
      'fb_files',       coalesce((select jsonb_agg(to_jsonb(x) - 'data' order by x.team_id, x.week, x.created_at) from public.fb_files x), '[]'),
      'fb_admins',      coalesce((select jsonb_agg(jsonb_build_object('admin_id', x.admin_id, 'name', x.name)) from public.fb_admins x), '[]')
    ));
end $$;

create or replace function public.fb_admin_file_data(p_token text, p_ids uuid[])
returns jsonb language plpgsql security definer set search_path to 'public' as $$
declare s public.fb_sessions;
begin
  s := public.fb__admin(p_token);
  if s.token is null then return jsonb_build_object('error','auth'); end if;
  if coalesce(array_length(p_ids,1),0) > 20 then return jsonb_build_object('error','too_many'); end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id', f.id, 'data', f.data)) from public.fb_files f where f.id = any(p_ids)), '[]');
end $$;

revoke all on function public.fb_admin_backup(text) from public;
revoke all on function public.fb_admin_file_data(text, uuid[]) from public;
grant execute on function public.fb_admin_backup(text) to anon, authenticated;
grant execute on function public.fb_admin_file_data(text, uuid[]) to anon, authenticated;
