from functools import wraps
from flask import abort
import os
import bcrypt
import psycopg2
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
# Signs the session cookie so a user can't forge/tamper with it client-side.
# Flask raises an error at runtime if this isn't set.
app.secret_key = os.environ["FLASK_SECRET_KEY"]


def get_db_connection():
    return psycopg2.connect(
        host=os.environ["IAM_DB_HOST"],
        port=os.environ["IAM_DB_PORT"],
        user=os.environ["IAM_DB_USER"],
        password=os.environ["IAM_DB_PASSWORD"],
        dbname=os.environ["IAM_DB_NAME"],
    )
def get_user_permissions(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT DISTINCT p.name
        FROM permissions p
        JOIN role_permissions rp ON rp.permission_id = p.id
        JOIN user_roles ur ON ur.role_id = rp.role_id
        WHERE ur.user_id = %s
        """,
        (user_id,),
    )
    permissions = {row[0] for row in cur.fetchall()}
    cur.close()
    conn.close()
    return permissions

def write_audit_log(user_id, username_attempted, action, resource, success):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO audit_log (user_id, username_attempted, action, resource, success)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (user_id, username_attempted, action, resource, success),
    )
    conn.commit()
    cur.close()
    conn.close()

def require_permission(permission_name):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))

            user_id = session["user_id"]
            username = session["username"]
            permissions = get_user_permissions(user_id)
            allowed = permission_name in permissions

            # action records WHICH permission was checked, resource records
            # WHICH route was hit - together they answer "who tried to do
            # what, where, and did it work."
            write_audit_log(
                user_id=user_id,
                username_attempted=username,
                action=permission_name,
                resource=request.path,
                success=allowed,
            )

            if not allowed:
                abort(403)

            return view_func(*args, **kwargs)
        return wrapped
    return decorator

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, password_hash, is_active FROM users WHERE username = %s",
            (username,),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()

        user_id = row[0] if row else None
        # Short-circuit: if row is None, bcrypt.checkpw never runs - can't
        # check a password hash that doesn't exist.
        password_ok = row is not None and bcrypt.checkpw(
            password.encode("utf-8"), row[1].encode("utf-8")
        )
        is_active = row[2] if row else False
        success = row is not None and is_active and password_ok

        # user_id is None here only when the username itself doesn't exist -
        # that's exactly the case audit_log's nullable user_id + separate
        # username_attempted column was designed for back in Phase 1.
        write_audit_log(
            user_id=user_id,
            username_attempted=username,
            action="login",
            resource=None,
            success=success,
        )

        if not success:
            flash("Invalid username or password")
            return render_template("login.html")

        session["user_id"] = user_id
        session["username"] = username
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT r.name FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = %s
        """,
        (session["user_id"],),
    )
    roles = [r[0] for r in cur.fetchall()]
    cur.close()
    conn.close()

    return render_template("dashboard.html", username=session["username"], roles=roles)

@app.route("/accounts")
@require_permission("view_accounts")
def view_accounts():
    return render_template("accounts.html")


@app.route("/accounts/edit")
@require_permission("edit_accounts")
def edit_accounts():
    return "<h1>Edit Accounts</h1><p>(placeholder - real editing UI comes later)</p><a href='/dashboard'>Back</a>"


@app.route("/transactions/approve")
@require_permission("approve_transactions")
def approve_transactions():
    return "<h1>Approve Transactions</h1><p>(placeholder)</p><a href='/dashboard'>Back</a>"


@app.route("/audit-log")
@require_permission("view_audit_log")
def view_audit_log():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT al.created_at,
               COALESCE(u.username, al.username_attempted) AS username,
               al.action, al.resource, al.success
        FROM audit_log al
        LEFT JOIN users u ON u.id = al.user_id
        ORDER BY al.created_at DESC
        LIMIT 100
        """
    )
    entries = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("audit_log.html", entries=entries)

@app.route("/admin/users")
@require_permission("manage_roles")
def admin_users():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users ORDER BY username")
    users = cur.fetchall()

    cur.execute("SELECT id, name FROM roles ORDER BY name")
    all_roles = cur.fetchall()

    cur.execute(
        """
        SELECT ur.user_id, r.id, r.name
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        """
    )
    role_rows = cur.fetchall()
    cur.close()
    conn.close()

    # Reshape the flat role_rows into {user_id: [(role_id, role_name), ...]}
    # so the template can look up "this user's current roles" directly.
    roles_by_user = {}
    for user_id, role_id, role_name in role_rows:
        roles_by_user.setdefault(user_id, []).append((role_id, role_name))

    return render_template(
        "admin_users.html",
        users=users,
        all_roles=all_roles,
        roles_by_user=roles_by_user,
    )


@app.route("/admin/users/<int:user_id>/assign-role", methods=["POST"])
@require_permission("manage_roles")
def assign_role(user_id):
    role_id = request.form["role_id"]
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
        (user_id, role_id),
    )
    conn.commit()
    cur.close()
    conn.close()

    # "role change" was one of the sensitive actions called out back in
    # Phase 3's plan - this is that promise being kept. require_permission
    # already logged the "manage_roles" check that got us into this route;
    # this is a SECOND, more specific log entry recording exactly what
    # changed (which user, which role).
    write_audit_log(
        user_id=session["user_id"],
        username_attempted=session["username"],
        action="assign_role",
        resource=f"user_id={user_id} role_id={role_id}",
        success=True,
    )

    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/revoke-role", methods=["POST"])
@require_permission("manage_roles")
def revoke_role(user_id):
    role_id = request.form["role_id"]
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM user_roles WHERE user_id = %s AND role_id = %s",
        (user_id, role_id),
    )
    conn.commit()
    cur.close()
    conn.close()

    write_audit_log(
        user_id=session["user_id"],
        username_attempted=session["username"],
        action="revoke_role",
        resource=f"user_id={user_id} role_id={role_id}",
        success=True,
    )

    return redirect(url_for("admin_users"))

    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)