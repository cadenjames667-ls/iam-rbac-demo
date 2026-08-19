-- Roles: the job titles that exist at this fictional bank branch.
INSERT INTO roles (name) VALUES
    ('Teller'),
    ('Branch Manager'),
    ('Auditor'),
    ('IT Admin');

-- Permissions: the atomic actions the app will actually check against in code.
INSERT INTO permissions (name) VALUES
    ('view_accounts'),
    ('edit_accounts'),
    ('approve_transactions'),
    ('view_audit_log'),
    ('manage_roles');

-- Role -> permission grants, modeled on real separation-of-duties in banking:
--   Teller          - front-line staff, can look accounts up but not touch them
--   Branch Manager  - can edit accounts and approve transactions (real authority)
--   Auditor         - can view accounts and the audit trail, but CANNOT edit or
--                      approve anything - an auditor who could act on what they're
--                      reviewing would defeat the point of having an auditor
--   IT Admin        - full access, including the audit log, for system administration
--
-- We join on role/permission NAME rather than hardcoding numeric ids, because
-- SERIAL ids depend on insert order - matching by name is self-documenting and
-- doesn't break if someone reorders the INSERTs above.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE (r.name, p.name) IN (
    ('Teller',         'view_accounts'),
    ('Branch Manager', 'view_accounts'),
    ('Branch Manager', 'edit_accounts'),
    ('Branch Manager', 'approve_transactions'),
    ('Auditor',        'view_accounts'),
    ('Auditor',        'view_audit_log'),
    ('IT Admin',       'view_accounts'),
    ('IT Admin',       'edit_accounts'),
    ('IT Admin',       'approve_transactions'),
    ('IT Admin',       'view_audit_log'),
    ('IT Admin', 'manage_roles')
);