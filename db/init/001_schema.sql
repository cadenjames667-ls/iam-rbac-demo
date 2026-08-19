-- users: one row per login identity. Passwords are never stored in plain
-- text — password_hash holds a bcrypt hash, which is always 60 chars.
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(60) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,  -- lets us disable a login without deleting the row (keeps audit history intact)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- roles: the job titles in the RBAC model (Teller, Branch Manager, etc).
-- Roles hold no logic themselves — they're just a name that permissions attach to.
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

-- permissions: the atomic actions the system can gate (view_accounts, approve_transactions, ...).
-- Code checks against these, never against role names directly — that's what keeps
-- authorization logic decoupled from "who happens to be called what."
CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

-- role_permissions: many-to-many join between roles and permissions.
-- No surrogate id — the (role_id, permission_id) pair IS the primary key,
-- so the database itself refuses a duplicate grant instead of relying on app code to catch it.
CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- user_roles: many-to-many join between users and roles (a user can hold multiple roles).
-- ON DELETE CASCADE: deleting a role automatically cleans up every user's grant of it,
-- so we never end up with a dangling role_id pointing at nothing.
CREATE TABLE user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- audit_log: the compliance trail. Deliberately looser than the auth tables above —
-- user_id is nullable (ON DELETE SET NULL keeps old log rows even if a user is later removed),
-- and username_attempted is a plain text field so a FAILED login with a bogus/unknown
-- username still gets recorded with what was actually typed, instead of being dropped
-- because it can't satisfy a foreign key.
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username_attempted VARCHAR(50),
    action VARCHAR(100) NOT NULL,       -- e.g. 'login', 'view_accounts', 'edit_accounts'
    resource VARCHAR(100),              -- e.g. which account/record was touched, if any
    success BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);