import os
import sqlite3
import smtplib

from functools import wraps
from email.message import EmailMessage

from flask import (
    session,
    redirect,
    url_for,
    flash,
    request
)

from werkzeug.security import check_password_hash

from dotenv import load_dotenv

from database import get_db


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


MAIL_SENDER = os.getenv("MAIL_SENDER")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")


# =========================================================
# GET CURRENT USER
# =========================================================

def get_current_user():

    user_id = session.get("user_id")

    if not user_id:
        return None

    conn = get_db()

    user = conn.execute("""
        SELECT
            id,
            username,
            full_name,
            email,
            role,
            is_active,
            created_at
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    conn.close()

    if user is None:
        session.clear()
        return None

    if not user["is_active"]:
        session.clear()
        return None

    return user


# =========================================================
# LOGIN USER
# =========================================================
def login_user(username, password):

    conn = get_db()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE username = ?
    """, (username,)).fetchone()

    conn.close()

    # -----------------------------------------------------
    # USER NOT FOUND
    # -----------------------------------------------------

    if user is None:

        create_unauthorized_alert(
            username=username,
            action="LOGIN_FAILED",
            ip_address=request.remote_addr,
            description="Login attempted with an unknown username."
        )

        return False, None

    # -----------------------------------------------------
    # ACCOUNT DISABLED
    # -----------------------------------------------------

    if not user["is_active"]:

        create_unauthorized_alert(
            username=username,
            action="LOGIN_FAILED",
            ip_address=request.remote_addr,
            description="Login attempted for a disabled account."
        )

        return False, None

    # -----------------------------------------------------
    # INVALID PASSWORD
    # -----------------------------------------------------

    if not check_password_hash(
        user["password_hash"],
        password
    ):

        create_unauthorized_alert(
            username=username,
            action="LOGIN_FAILED",
            ip_address=request.remote_addr,
            description="Invalid password entered."
        )

        return False, None

    # -----------------------------------------------------
    # SUCCESSFUL LOGIN
    # -----------------------------------------------------

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    conn = get_db()

    conn.execute("""
        INSERT INTO login_attempts (
            username,
            success,
            ip_address
        )
        VALUES (?, ?, ?)
    """, (
        username,
        1,
        request.remote_addr
    ))

    conn.commit()
    conn.close()

    create_audit_log(
        user_id=user["id"],
        action="LOGIN",
        description="Successful login."
    )

    return True, user
    # -----------------------------------------------------
    # USER NOT FOUND
    # -----------------------------------------------------

    if user is None:

        create_unauthorized_alert(
            username=username,
            action="LOGIN_FAILED",
            ip_address=request.remote_addr,
            description="Login attempted with an unknown username."
        )

        return False

    # -----------------------------------------------------
    # ACCOUNT DISABLED
    # -----------------------------------------------------

    if not user["is_active"]:

        create_unauthorized_alert(
            username=username,
            action="LOGIN_FAILED",
            ip_address=request.remote_addr,
            description="Login attempted for a disabled account."
        )

        return False

    # -----------------------------------------------------
    # INVALID PASSWORD
    # -----------------------------------------------------

    if not check_password_hash(
        user["password_hash"],
        password
    ):

        create_unauthorized_alert(
            username=username,
            action="LOGIN_FAILED",
            ip_address=request.remote_addr,
            description="Invalid password entered."
        )

        return False

    # -----------------------------------------------------
    # SUCCESSFUL LOGIN
    # -----------------------------------------------------

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    conn = get_db()

    conn.execute("""
        INSERT INTO login_attempts (
            username,
            success,
            ip_address
        )
        VALUES (?, ?, ?)
    """, (
        username,
        1,
        request.remote_addr
    ))

    conn.commit()
    conn.close()

    create_audit_log(
        user_id=user["id"],
        action="LOGIN",
        description="Successful login."
    )

    return True


# =========================================================
# LOGOUT USER
# =========================================================

def logout_user():

    user_id = session.get("user_id")

    if user_id:

        create_audit_log(
            user_id=user_id,
            action="LOGOUT",
            description="User logged out."
        )

    session.clear()


# =========================================================
# LOGIN REQUIRED
# =========================================================

def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please login to continue.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        user = get_current_user()

        if user is None:

            flash(
                "Your session is invalid. Please login again.",
                "danger"
            )

            return redirect(
                url_for("login")
            )

        return f(*args, **kwargs)

    return decorated_function


# =========================================================
# ROLE REQUIRED
# =========================================================

def role_required(*allowed_roles):

    def decorator(f):

        @wraps(f)
        def decorated_function(*args, **kwargs):

            user = get_current_user()

            if user is None:

                flash(
                    "Please login to continue.",
                    "warning"
                )

                return redirect(
                    url_for("login")
                )

            if user["role"] not in allowed_roles:

                create_unauthorized_alert(
                    username=user["username"],
                    action="UNAUTHORIZED_ACCESS",
                    ip_address=request.remote_addr,
                    description=(
                        f"Unauthorized access attempted "
                        f"to {request.path}"
                    )
                )

                flash(
                    "You are not authorized to access this page.",
                    "danger"
                )

                return redirect(
                    url_for("dashboard")
                )

            return f(*args, **kwargs)

        return decorated_function

    return decorator


# =========================================================
# AUDIT LOG
# =========================================================

def create_audit_log(
    user_id,
    action,
    description
):

    try:

        conn = get_db()

        user_agent = request.headers.get(
            "User-Agent",
            ""
        )

        conn.execute("""
            INSERT INTO audit_logs (
                user_id,
                action,
                description,
                ip_address,
                user_agent
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            user_id,
            action,
            description,
            request.remote_addr,
            user_agent
        ))

        conn.commit()
        conn.close()

    except Exception as e:

        print(
            "Audit log error:",
            e
        )


# =========================================================
# SEND SECURITY EMAIL
# =========================================================

def send_security_email_notification(
    username,
    action,
    ip_address,
    description,
    recipients
):

    if not MAIL_SENDER or not MAIL_PASSWORD:

        print(
            "Email settings are missing from .env"
        )

        return False

    if not recipients:

        print(
            "No authorized email recipients found."
        )

        return False

    try:

        # -------------------------------------------------
        # CREATE EMAIL
        # -------------------------------------------------

        message = EmailMessage()

        message["Subject"] = (
            "Security Alert - Medical Records System"
        )

        message["From"] = MAIL_SENDER

        message["To"] = ", ".join(recipients)

        message.set_content(
            f"""
Medical Records System
Security Alert

An unauthorized or failed security event was detected.

Username:
{username}

Action:
{action}

IP Address:
{ip_address}

Description:
{description}

Time:
{request.date}

Please review the Security Alerts and Audit Logs
inside the Medical Records System.

This is an automated security notification.
"""
        )

        # -------------------------------------------------
        # CONNECT TO GMAIL SMTP
        # -------------------------------------------------

        with smtplib.SMTP(
            "smtp.gmail.com",
            587
        ) as server:

            server.starttls()

            server.login(
                MAIL_SENDER,
                MAIL_PASSWORD
            )

            server.send_message(
                message
            )

        print(
            "Security email sent successfully."
        )

        return True

    except Exception as e:

        print(
            "Security email error:",
            e
        )

        return False


# =========================================================
# UNAUTHORIZED ACCESS / LOGIN ALERT
# =========================================================

def create_unauthorized_alert(
    username,
    action,
    ip_address,
    description
):

    try:

        conn = get_db()

        # -------------------------------------------------
        # SECURITY ALERT
        # -------------------------------------------------

        conn.execute("""
            INSERT INTO security_alerts (
                username,
                action,
                ip_address,
                description
            )
            VALUES (?, ?, ?, ?)
        """, (
            username,
            action,
            ip_address,
            description
        ))

        # -------------------------------------------------
        # FAILED LOGIN RECORD
        # -------------------------------------------------

        conn.execute("""
            INSERT INTO login_attempts (
                username,
                success,
                ip_address
            )
            VALUES (?, ?, ?)
        """, (
            username,
            0,
            ip_address
        ))

        # -------------------------------------------------
        # GET AUTHORIZED USERS
        # -------------------------------------------------

        authorized_users = conn.execute("""
            SELECT
                id,
                email,
                role
            FROM users
            WHERE is_active = 1
            AND role IN ('admin', 'authorized')
            AND email IS NOT NULL
            AND email != ''
        """).fetchall()

        # -------------------------------------------------
        # IN-APP SECURITY NOTIFICATION
        # -------------------------------------------------

        for user in authorized_users:

            conn.execute("""
                INSERT INTO security_notifications (
                    user_id,
                    title,
                    message,
                    notification_type,
                    is_read
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                user["id"],
                "Security Alert",
                (
                    f"Unauthorized security event detected "
                    f"for username '{username}' "
                    f"from IP {ip_address}."
                ),
                "security",
                0
            ))

        conn.commit()

        # -------------------------------------------------
        # GET EMAIL ADDRESSES
        # -------------------------------------------------

        recipients = [
            user["email"]
            for user in authorized_users
            if user["email"]
        ]

        conn.close()

        # -------------------------------------------------
        # SEND EMAIL
        # -------------------------------------------------

        send_security_email_notification(
            username=username,
            action=action,
            ip_address=ip_address,
            description=description,
            recipients=recipients
        )

    except Exception as e:

        print(
            "Unauthorized alert error:",
            e
        )


# =========================================================
# AUTHORIZED USER CHECK
# =========================================================

def is_authorized_user():

    user = get_current_user()

    if user is None:
        return False

    return user["role"] in [
        "admin",
        "authorized"
    ]


# =========================================================
# CLEAR INVALID SESSION
# =========================================================

def clear_invalid_session():

    user = get_current_user()

    if user is None:

        session.clear()

        return True

    return False