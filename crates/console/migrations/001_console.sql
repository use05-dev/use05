-- The 05 console's database: one SQLite file (D86). It holds who may sign in and approve, which
-- machines and repositories exist (repositories by an opaque id), and sealed records it cannot
-- read. Ids are text; times are text in one format that sorts as time.

create table members (
    id text primary key check (typeof(id) = 'text'),
    name text not null,
    email text,
    email_verified integer not null default 0,
    role text not null check (role in ('admin', 'member')),
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    public blob,                         -- the member's X25519 public key
    pin text                             -- HMAC of its id and public key under the team's pin key
);

create table passkeys (
    id text primary key,
    name text not null,
    sec1 blob not null,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used text,
    member_id text not null references members(id) on delete cascade
);

create table sessions (
    token_hash text primary key,
    passkey_id text references passkeys(id) on delete cascade,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at text not null
);

create table challenges (
    id text primary key check (typeof(id) = 'text'),
    purpose text not null,
    challenge blob not null,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    context text
);

create table invites (
    id text primary key check (typeof(id) = 'text'),
    token_hash text not null unique,
    name text not null,
    role text not null check (role in ('admin', 'member')),
    created_by text references members(id) on delete set null,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    used_at text,
    sealed_bundle blob                   -- the team secret, wrapped by the link's fragment
);

create table email_tokens (
    token_hash text primary key,
    member_id text not null references members(id) on delete cascade,
    email text not null,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

create table team (
    version integer primary key,
    public blob not null,                -- the team's X25519 public key: machines seal to it
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

create table team_grants (
    member_id text not null references members(id) on delete cascade,
    version integer not null references team(version),
    sealed blob not null,                -- the team secret and id key, sealed to the member
    primary key (member_id, version)
);

create table own_grants (
    member_id text not null references members(id) on delete cascade,
    version integer not null references team(version),
    wrapped blob not null,               -- the team bundle, wrapped under a key from the member's own secret
    primary key (member_id, version)
);

create table key_wraps (
    id text primary key check (typeof(id) = 'text'),
    member_id text not null references members(id) on delete cascade,
    kind text not null check (kind in ('passkey', 'recovery')),
    passkey_id text references passkeys(id) on delete cascade,
    wrapped blob not null,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

create table machines (
    id text primary key check (typeof(id) = 'text'),
    name text not null,
    token_hash text not null unique,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen text,
    use05_version text,
    revoked integer not null default 0,
    member_id text references members(id) on delete set null,
    x_pub blob,
    ed_pub blob,
    pin text,                            -- HMAC of its keys under the team's id key, made by a browser
    team_version integer,
    sealed_id_key blob                   -- the team's id key, sealed to the machine by the browser
);

create table pairings (
    id text primary key check (typeof(id) = 'text'),
    machine_name text not null,
    poll_secret_hash text not null,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    approved integer not null default 0,
    denied integer not null default 0,
    token text,
    machine_id text references machines(id) on delete cascade,
    commit_hash blob not null,           -- the machine's keys and nonce, committed before the browser's nonce
    word_hash text not null,             -- the word only its terminal shows: whoever types it claims it
    claimed_by text references members(id) on delete cascade,
    browser_nonce blob,
    x_pub blob,                          -- revealed after the browser's nonce
    ed_pub blob,
    machine_nonce blob
);

create table repos (
    id text primary key,                 -- an HMAC under the team's id key: routable, not readable
    updated_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

create table repo_machines (
    repo_id text not null references repos(id) on delete cascade,
    machine_id text not null references machines(id) on delete cascade,
    last_seen text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    allowed integer not null default 0,
    primary key (repo_id, machine_id)
);

create table records (
    id integer primary key autoincrement,
    kind text not null,                  -- repo | tree | task | event | refusal
    repo_ref text not null,
    ref_key text not null default '',
    machine_id text references machines(id) on delete set null,
    at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    sealed blob not null,                -- sealed to the team's key
    sig blob not null,                   -- the machine's Ed25519 signature
    unique (kind, repo_ref, ref_key)
);
create index records_at on records (at);

create table approval_requests (
    id text primary key check (typeof(id) = 'text'),
    repo_id text not null references repos(id) on delete cascade,
    machine_id text references machines(id) on delete set null,
    status text not null default 'waiting',
    vote text,
    result text,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ref_key text not null default '',
    sealed blob,
    sig blob
);
create unique index approval_requests_ref on approval_requests (repo_id, ref_key);

create table policy_edits (
    id text primary key check (typeof(id) = 'text'),
    repo_id text not null references repos(id) on delete cascade,
    machine_id text references machines(id) on delete set null,
    status text not null default 'waiting',
    prepared text,
    reason text,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    member_id text references members(id) on delete set null
);

-- A person's testing sign-off from a phone (D87): their machine prepares it, their passkey signs.
create table signoffs (
    id text primary key check (typeof(id) = 'text'),
    repo_id text not null references repos(id) on delete cascade,
    machine_id text references machines(id) on delete set null,
    member_id text references members(id) on delete set null,
    status text not null default 'preparing',   -- preparing | ready | signed | filed | stuck
    prepared text,                             -- the machine's sealed, signed answer
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

create table base_policy (
    id integer primary key check (id = 1),
    toml text not null,                  -- sealed to the team
    updated_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

create table instructions (
    id text primary key check (typeof(id) = 'text'),
    machine_id text not null references machines(id) on delete cascade,
    kind text not null,
    payload text not null,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    delivered_at text,
    done_at text,
    result text
);

create table alerts (
    id integer primary key autoincrement,
    kind text not null,
    subject text not null,
    body text not null,
    link text,
    sent integer not null default 0,
    error text,
    at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    member_id text references members(id) on delete cascade,
    to_address text
);

create table audit (
    id integer primary key autoincrement,
    at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    actor text not null,
    action text not null,
    detail text not null default '{}'
);
