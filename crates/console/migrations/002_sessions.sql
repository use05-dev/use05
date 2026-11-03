-- Cloud sessions and CI (D86): reporters with keys made in a member's browser, pinned like
-- machines, that speak for one repository only and are never sent instructions (a session) or
-- only approvals to collect (CI).
alter table machines add column kind text not null default 'machine' check (kind in ('machine', 'session', 'ci'));
alter table machines add column repo_only text;
