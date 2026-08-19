import os
import bcrypt
import psycopg2

# One fake user per role, so each permission level has a login to test with.
SEED_USERS = [
    ("jsmith_teller",   "TellerPass123!",  "Teller"),
    ("mgarcia_manager", "ManagerPass123!", "Branch Manager"),
    ("rlee_auditor",    "AuditorPass123!", "Auditor"),
    ("admin_it",        "AdminPass123!",   "IT Admin"),
]

def get_connection():
    return psycopg2.connect(
        host=os.environ["IAM_DB_HOST"],
        port=os.environ["IAM_DB_PORT"],
        user=os.environ["IAM_DB_USER"],
        password=os.environ["IAM_DB_PASSWORD"],
        dbname=os.environ["IAM_DB_NAME"],
    )

def main():
    conn = get_connection()
    cur = conn.cursor()

    for username, plain_password, role_name in SEED_USERS:
        # bcrypt.hashpw needs bytes in, and generates a random salt per call -
        # that's why two users with the identical password still get totally
        # different hashes stored in the db (this is what defeats rainbow tables).
        password_hash = bcrypt.hashpw(
            plain_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        # ON CONFLICT DO NOTHING makes this safe to re-run - if you run the
        # script twice, it won't error or create duplicate users.
        cur.execute(
            """
            INSERT INTO users (username, password_hash)
            VALUES (%s, %s)
            ON CONFLICT (username) DO NOTHING
            RETURNING id
            """,
            (username, password_hash),
        )
        row = cur.fetchone()
        if row is None:
            # Insert was skipped because the user already existed - look up
            # its id so we can still make sure the role assignment below runs.
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
        user_id = row[0]

        cur.execute("SELECT id FROM roles WHERE name = %s", (role_name,))
        role_id = cur.fetchone()[0]

        cur.execute(
            """
            INSERT INTO user_roles (user_id, role_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            """,
            (user_id, role_id),
        )

        print(f"Seeded {username} ({role_name})")

    conn.commit()
    cur.close()
    conn.close()

if __name__ == "__main__":
    main()