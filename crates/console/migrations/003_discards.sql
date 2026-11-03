-- Throwing a task's work away from a phone (D89): the machine that holds the work prepares the
-- discard (what would be lost, sealed), the person's passkey signs it, the machine does it.
create table discards (
    id text primary key check (typeof(id) = 'text'),
    repo_id text not null references repos(id) on delete cascade,
    machine_id text references machines(id) on delete set null,
    member_id text references members(id) on delete set null,
    status text not null default 'preparing',   -- preparing | ready | signed | done | stuck
    prepared text,                             -- the machine's sealed, signed answer
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
