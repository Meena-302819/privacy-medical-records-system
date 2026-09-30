from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
    send_file
)

import sqlite3
import os
import shutil
import time
import secrets
import hashlib
import hmac
import json
import urllib.request
import urllib.error

from datetime import datetime


from dotenv import load_dotenv

from database import init_db, get_db
from encryption import encrypt_data, decrypt_data
from search_security import (
    generate_record_search_tokens,
    create_query_tokens
)

from auth import (
    login_user,
    logout_user,
    get_current_user,
    login_required,
    role_required,
    create_audit_log
)


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)


# =========================================================
# RESEND EMAIL FUNCTION
# =========================================================

def send_resend_email(to_email, subject, body):
    """
    Send email through Resend API.

    RESEND_API_KEY must be configured in the environment.
    MAIL_SENDER is optional and defaults to Resend's onboarding sender.
    """

    api_key = os.getenv("RESEND_API_KEY")

    if not api_key:
        raise RuntimeError(
            "RESEND_API_KEY is not configured."
        )

    sender = os.getenv(
        "MAIL_SENDER",
        "onboarding@resend.dev"
    )

    payload = {
        "from": sender,
        "to": [to_email],
        "subject": subject,
        "text": body
    }

    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "PrivacyMedicalRecordsSystem/1.0"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(
            req,
            timeout=20
        ) as response:
            response_data = response.read().decode("utf-8")
            print("Resend email response:", response_data)
            return True

    except urllib.error.HTTPError as error:
        error_body = error.read().decode(
            "utf-8",
            errors="replace"
        )

        print(
            "Resend API error:",
            error.code,
            error_body
        )

        raise RuntimeError(
            f"Resend email failed: {error_body}"
        )

    except Exception as error:
        print(
            "Resend connection error:",
            error
        )
        raise


load_dotenv()

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "medical-records-system-change-this-secret"
)

app.config["DATABASE"] = "medical_records.db"


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

init_db()


# =========================================================
# CONTEXT PROCESSOR
# =========================================================

@app.context_processor
def inject_user():

    user = get_current_user()

    unread_notifications = 0

    if user:

        conn = get_db()

        row = conn.execute("""
            SELECT COUNT(*) AS count
            FROM security_notifications
            WHERE user_id = ?
            AND is_read = 0
        """, (
            user["id"],
        )).fetchone()

        unread_notifications = row["count"]

        conn.close()

    return {
        "current_user": user,
        "unread_notifications": unread_notifications
    }


# =========================================================
# HELPER - GENERATE PATIENT ID
# =========================================================

def generate_patient_id():

    """
    Generates a unique patient ID.

    Example:
    PATIENT20260927123045123456
    """

    while True:

        patient_id = (
            "PATIENT"
            + datetime.now().strftime(
                "%Y%m%d%H%M%S%f"
            )
        )

        conn = get_db()

        existing = conn.execute("""
            SELECT id
            FROM patients
            WHERE patient_id = ?
        """, (
            patient_id,
        )).fetchone()

        conn.close()

        if existing is None:

            return patient_id


# =========================================================
# HELPER - GENERATE RECORD ID
# =========================================================

def generate_record_id():

    while True:

        record_id = (
            "REC"
            + datetime.now().strftime(
                "%Y%m%d%H%M%S%f"
            )
        )

        conn = get_db()

        existing = conn.execute("""
            SELECT id
            FROM medical_records
            WHERE record_id = ?
        """, (
            record_id,
        )).fetchone()

        conn.close()

        if existing is None:

            return record_id


# =========================================================
# CREATE SEARCH INDEX
# =========================================================

def create_search_index(record_id, fields):

    conn = get_db()

    # Remove existing tokens
    conn.execute("""
        DELETE FROM search_index
        WHERE record_id = ?
    """, (
        record_id,
    ))

    tokens = generate_record_search_tokens(
        fields
    )

    for item in tokens:

        search_token = item["token"]
        field_name = item["field_name"]

        try:

            conn.execute("""
                INSERT INTO search_index
                (
                    record_id,
                    search_token,
                    field_name
                )
                VALUES (?, ?, ?)
            """, (
                record_id,
                search_token,
                field_name
            ))

        except sqlite3.IntegrityError:

            pass

    conn.commit()

    conn.close()


# =========================================================
# UNAUTHORIZED LOGIN ALERT
# =========================================================

def create_login_failure_alert(username):

    """Create website notifications and send email alerts
    to active admin/authorized users when a login fails.
    """

    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "Unknown")

    conn = get_db()

    try:
        # -------------------------------------------------
        # SAVE SECURITY ALERT
        # -------------------------------------------------
        conn.execute("""
            INSERT INTO security_alerts
            (username, action, ip_address, description)
            VALUES (?, ?, ?, ?)
        """, (
            username or "Unknown",
            "FAILED_LOGIN",
            ip_address or "Unknown",
            f"Failed login attempt for username '{username or 'Unknown'}'. User-Agent: {user_agent}"
        ))

        # -------------------------------------------------
        # FIND ACTIVE AUTHORIZED RECIPIENTS
        # -------------------------------------------------
        recipients = conn.execute("""
            SELECT id, username, full_name, email, role
            FROM users
            WHERE is_active = 1
            AND role IN ('admin', 'authorized')
            AND email IS NOT NULL
            AND TRIM(email) != ''
        """).fetchall()

        # -------------------------------------------------
        # CHECK NOTIFICATION RECIPIENT COLUMN
        # Supports both user_id and authorized_user_id schemas.
        # -------------------------------------------------
        notification_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(security_notifications)").fetchall()
        }

        recipient_column = None

        if "user_id" in notification_columns:
            recipient_column = "user_id"
        elif "authorized_user_id" in notification_columns:
            recipient_column = "authorized_user_id"

        # -------------------------------------------------
        # WEBSITE NOTIFICATION
        # -------------------------------------------------
        if recipient_column:
            for recipient in recipients:
                conn.execute(
                    f"""
                    INSERT INTO security_notifications
                    ({recipient_column}, title, message, notification_type, is_read)
                    VALUES (?, ?, ?, ?, 0)
                    """,
                    (
                        recipient["id"],
                        "Unauthorized Login Attempt",
                        f"A failed login attempt was detected for username '{username or 'Unknown'}' from IP {ip_address or 'Unknown'}.'",
                        "security"
                    )
                )

        conn.commit()

        # -------------------------------------------------
        # EMAIL NOTIFICATION
        # -------------------------------------------------
        email_body = f"""
Security Alert

A failed login attempt was detected in the medical records system.

Username: {username or 'Unknown'}
IP Address: {ip_address or 'Unknown'}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

If this activity was not expected, please review the security alerts page.

Medical Records System
"""

        for recipient in recipients:
            try:
                send_resend_email(
                    recipient["email"],
                    "Security Alert - Failed Login Attempt",
                    email_body
                )
            except Exception as email_error:
                print(
                    "Security alert email failed for",
                    recipient["email"],
                    ":",
                    email_error
                )

    except Exception as error:
        conn.rollback()
        print("Unable to create unauthorized login alert:", error)

    finally:
        conn.close()


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if session.get("user_id"):
        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        ).strip()

        print("\n>>> LOGIN POST REQUEST RECEIVED <<<")
        print("Username entered:", username)

        if not username or not password:

            flash(
                "Username and password are required.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        # -------------------------------------------------
        # AUTHENTICATE USER
        # -------------------------------------------------

        user_result = login_user(
            username,
            password
        )

        # login_user() in the current auth module returns
        # (success, user). This handling also safely supports
        # a direct user object/dict if the auth module changes.

        success = False
        user = None

        if isinstance(user_result, tuple):

            if len(user_result) >= 2:
                success = bool(user_result[0])
                user = user_result[1]

        elif isinstance(user_result, dict):

            user = user_result
            success = True

        elif hasattr(user_result, "keys"):

            user = user_result
            success = True

        else:

            success = bool(user_result)

        # -------------------------------------------------
        # INVALID LOGIN
        # -------------------------------------------------

        if not success or user is None:

            print(">>> LOGIN FAILED <<<")

            # Record the unauthorized attempt, create website
            # notifications for authorized users, and send email alerts.
            create_login_failure_alert(username)

            flash(
                "Invalid username or password.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        print(">>> LOGIN PASSWORD VERIFIED <<<")

        # -------------------------------------------------
        # GET USER ID
        # -------------------------------------------------

        if isinstance(user, dict):

            user_id = user.get("id")

        elif hasattr(user, "keys"):

            user_id = user["id"]

        else:

            try:
                user_id = user["id"]
            except (TypeError, KeyError, IndexError):
                user_id = None

        print("User ID:", user_id)

        if not user_id:

            print(">>> USER ID NOT FOUND <<<")

            flash(
                "Unable to identify user account.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        # -------------------------------------------------
        # FETCH FRESH USER DATA
        # -------------------------------------------------

        conn = get_db()

        database_user = conn.execute("""
            SELECT
                id,
                username,
                full_name,
                email,
                role,
                is_active
            FROM users
            WHERE id = ?
        """, (
            user_id,
        )).fetchone()

        conn.close()

        if database_user is None:

            print(">>> USER NOT FOUND IN DATABASE <<<")

            flash(
                "User account not found.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        if not database_user["is_active"]:

            flash(
                "This user account is inactive.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        user_email = database_user["email"]

        print("User email:", user_email)

        if not user_email:

            flash(
                "No registered email found for this account.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        # -------------------------------------------------
        # GENERATE OTP
        # -------------------------------------------------

        otp = f"{secrets.randbelow(1000000):06d}"

        otp_hash = hashlib.sha256(
            otp.encode("utf-8")
        ).hexdigest()

        session["otp_user_id"] = database_user["id"]
        session["otp_username"] = database_user["username"]
        session["otp_hash"] = otp_hash
        session["otp_created_at"] = time.time()
        session["otp_attempts"] = 0

        print(">>> OTP GENERATED <<<")
        print("OTP:", otp)

        full_name = (
            database_user["full_name"]
            or database_user["username"]
        )

        body = f"""
Hello {full_name},

Your login verification code is:

{otp}

This OTP is valid for 5 minutes.

If you did not attempt to log in,
please contact the administrator.

Regards,
Medical Records System
"""

        # -------------------------------------------------
        # SEND OTP EMAIL
        # -------------------------------------------------

        try:

            send_resend_email(
                user_email,
                "Login Verification Code",
                body
            )

            print(">>> OTP EMAIL SENT <<<")

            flash(
                "Verification code sent to your registered email.",
                "success"
            )

            return redirect(
                url_for("verify_otp")
            )

        except Exception as error:

            print()
            print(">>> OTP EMAIL FAILED <<<")
            print("Error:", error)
            print("==============================================")

            session.pop("otp_user_id", None)
            session.pop("otp_username", None)
            session.pop("otp_hash", None)
            session.pop("otp_created_at", None)
            session.pop("otp_attempts", None)

            flash(
                "Unable to send verification code. Check the server terminal.",
                "danger"
            )

            return render_template(
                "login.html"
            )

    return render_template(
        "login.html"
    )


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    if not session.get("otp_user_id"):
        flash(
            "Please login with your username and password first.",
            "danger"
        )
        return redirect(url_for("login"))

    if request.method == "POST":

        entered_otp = request.form.get(
            "otp",
            ""
        ).strip()

        # OTP expiry check — 5 minutes
        otp_created_at = session.get(
            "otp_created_at",
            0
        )

        if time.time() - otp_created_at > 300:

            session.pop("otp_user_id", None)
            session.pop("otp_username", None)
            session.pop("otp_hash", None)
            session.pop("otp_created_at", None)
            session.pop("otp_attempts", None)

            flash(
                "OTP has expired. Please login again.",
                "danger"
            )

            return redirect(
                url_for("login")
            )

        # Maximum 5 attempts
        attempts = session.get(
            "otp_attempts",
            0
        )

        if attempts >= 5:

            session.pop("otp_user_id", None)
            session.pop("otp_username", None)
            session.pop("otp_hash", None)
            session.pop("otp_created_at", None)
            session.pop("otp_attempts", None)

            flash(
                "Too many incorrect OTP attempts. Please login again.",
                "danger"
            )

            return redirect(
                url_for("login")
            )

        # Check OTP
        entered_hash = hashlib.sha256(
            entered_otp.encode()
        ).hexdigest()

        stored_hash = session.get(
            "otp_hash"
        )

        if hmac.compare_digest(
            entered_hash,
            stored_hash
        ):

            user_id = session["otp_user_id"]

            username = session["otp_username"]

            # Create actual login session
            session["user_id"] = user_id
            session["username"] = username

            # Get user role
            conn = get_db()

            user = conn.execute(
                """
                SELECT id, username, role
                FROM users
                WHERE id = ?
                """,
                (user_id,)
            ).fetchone()

            conn.close()

            if user:
                session["role"] = user["role"]

            # Remove temporary OTP data
            session.pop("otp_user_id", None)
            session.pop("otp_username", None)
            session.pop("otp_hash", None)
            session.pop("otp_created_at", None)
            session.pop("otp_attempts", None)

            flash(
                "Login successful.",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        # Wrong OTP
        session["otp_attempts"] = attempts + 1

        remaining = 5 - session["otp_attempts"]

        flash(
            f"Invalid OTP. {remaining} attempt(s) remaining.",
            "danger"
        )

    return render_template(
        "otp.html"
    )

@app.route("/resend-otp")
def resend_otp():

    if not session.get("otp_user_id"):
        flash(
            "Please login first.",
            "danger"
        )
        return redirect(url_for("login"))

    user_id = session["otp_user_id"]

    conn = get_db()

    user = conn.execute(
        """
        SELECT id, username, full_name, email
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    conn.close()

    if not user or not user["email"]:
        flash(
            "Registered email not found.",
            "danger"
        )
        return redirect(url_for("login"))

    # Generate new OTP
    otp = f"{secrets.randbelow(1000000):06d}"

    otp_hash = hashlib.sha256(
        otp.encode()
    ).hexdigest()

    session["otp_hash"] = otp_hash
    session["otp_created_at"] = time.time()
    session["otp_attempts"] = 0

    try:

        body = f"""
Hello {user["full_name"]},

Your new login verification code is:

{otp}

This OTP is valid for 5 minutes.

Regards,
Medical Records System
"""

        send_resend_email(
            user["email"],
            "New Login Verification Code",
            body
        )

        flash(
            "A new verification code has been sent to your email.",
            "success"
        )

    except Exception as e:

        print(
            "Resend OTP email error:",
            e
        )

        flash(
            "Unable to resend verification code.",
            "danger"
        )

    return redirect(
        url_for("verify_otp")
    )
# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    logout_user()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if session.get("user_id"):

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db()

    # -----------------------------------------------------
    # TOTAL PATIENTS
    # -----------------------------------------------------

    patient_count = conn.execute("""
        SELECT COUNT(*) AS count
        FROM patients
    """).fetchone()["count"]

    # -----------------------------------------------------
    # TOTAL MEDICAL RECORDS
    # -----------------------------------------------------

    record_count = conn.execute("""
        SELECT COUNT(*) AS count
        FROM medical_records
    """).fetchone()["count"]

    # -----------------------------------------------------
    # ACTIVE USERS
    # -----------------------------------------------------

    user_count = conn.execute("""
        SELECT COUNT(*) AS count
        FROM users
        WHERE is_active = 1
    """).fetchone()["count"]

    # -----------------------------------------------------
    # UNREAD NOTIFICATIONS
    # -----------------------------------------------------

    notification_count = conn.execute("""
        SELECT COUNT(*) AS count
        FROM security_notifications
        WHERE user_id = ?
        AND is_read = 0
    """, (
        session["user_id"],
    )).fetchone()["count"]

    # -----------------------------------------------------
    # RECENT PATIENTS
    # -----------------------------------------------------

    recent_patients = conn.execute("""
        SELECT
            id,
            patient_id,
            patient_code,
            name,
            gender,
            phone,
            created_at
        FROM patients
        ORDER BY id DESC
        LIMIT 5
    """).fetchall()

    # -----------------------------------------------------
    # RECENT MEDICAL RECORDS
    # -----------------------------------------------------

    recent_records = conn.execute("""
        SELECT
            medical_records.id,
            medical_records.record_id,
            medical_records.patient_id,
            medical_records.created_at,
            patients.patient_code,
            patients.name
        FROM medical_records
        JOIN patients
            ON patients.id = medical_records.patient_id
        ORDER BY medical_records.id DESC
        LIMIT 5
    """).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        patient_count=patient_count,
        record_count=record_count,
        user_count=user_count,
        notification_count=notification_count,
        recent_patients=recent_patients,
        recent_records=recent_records
    )


# =========================================================
# PATIENT LIST
# =========================================================

@app.route("/patients")
@login_required
def patients():

    search = request.args.get(
        "search",
        ""
    ).strip()

    conn = get_db()

    if search:

        patients_list = conn.execute("""
            SELECT
                id,
                patient_id,
                patient_code,
                name,
                date_of_birth,
                gender,
                phone,
                email,
                address,
                blood_group,
                emergency_contact,
                created_at
            FROM patients
            WHERE
                patient_code LIKE ?
                OR patient_id LIKE ?
                OR name LIKE ?
                OR phone LIKE ?
            ORDER BY id DESC
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        )).fetchall()

    else:

        patients_list = conn.execute("""
            SELECT
                id,
                patient_id,
                patient_code,
                name,
                date_of_birth,
                gender,
                phone,
                email,
                address,
                blood_group,
                emergency_contact,
                created_at
            FROM patients
            ORDER BY id DESC
        """).fetchall()

    conn.close()

    return render_template(
        "patients.html",
        patients=patients_list,
        search=search
    )


# =========================================================
# ADD PATIENT
# =========================================================

@app.route(
    "/patients/add",
    methods=["GET", "POST"]
)
@login_required
def add_patient():

    if request.method == "POST":

        # -------------------------------------------------
        # FORM DATA
        # -------------------------------------------------

        patient_id = request.form.get(
            "patient_id",
            ""
        ).strip()

        name = request.form.get(
            "name",
            ""
        ).strip()

        date_of_birth = request.form.get(
            "date_of_birth",
            ""
        ).strip()

        gender = request.form.get(
            "gender",
            ""
        ).strip()

        blood_group = request.form.get(
            "blood_group",
            ""
        ).strip()

        phone = request.form.get(
            "phone",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip()

        address = request.form.get(
            "address",
            ""
        ).strip()

        emergency_contact = request.form.get(
            "emergency_contact",
            ""
        ).strip()


        # -------------------------------------------------
        # REQUIRED FIELDS
        # -------------------------------------------------

        if (
            not patient_id
            or not name
            or not date_of_birth
        ):

            flash(
                "Patient ID, name and date of birth are required.",
                "danger"
            )

            return redirect(
                url_for("add_patient")
            )


        # -------------------------------------------------
        # DATABASE CONNECTION
        # -------------------------------------------------

        conn = get_db()


        # -------------------------------------------------
        # CHECK DUPLICATE PATIENT ID
        # -------------------------------------------------

        existing = conn.execute("""
            SELECT id
            FROM patients
            WHERE patient_id = ?
        """, (
            patient_id,
        )).fetchone()


        if existing:

            conn.close()

            flash(
                "Patient ID already exists.",
                "danger"
            )

            return redirect(
                url_for("add_patient")
            )


        # -------------------------------------------------
        # GENERATE PATIENT CODE
        # -------------------------------------------------

        last_code = conn.execute("""
            SELECT patient_code
            FROM patients
            WHERE patient_code IS NOT NULL
            ORDER BY id DESC
            LIMIT 1
        """).fetchone()


        if (
            last_code
            and last_code["patient_code"]
        ):

            try:

                number = int(
                    last_code["patient_code"].replace(
                        "PAT",
                        ""
                    )
                ) + 1

            except ValueError:

                number = 1

        else:

            number = 1


        patient_code = (
            f"PAT{number:05d}"
        )


        # -------------------------------------------------
        # MAKE SURE PATIENT CODE IS UNIQUE
        # -------------------------------------------------

        while conn.execute("""
            SELECT id
            FROM patients
            WHERE patient_code = ?
        """, (
            patient_code,
        )).fetchone():

            number += 1

            patient_code = (
                f"PAT{number:05d}"
            )


        # -------------------------------------------------
        # INSERT PATIENT
        # -------------------------------------------------

        cursor = conn.execute("""
            INSERT INTO patients
            (
                patient_id,
                patient_code,
                name,
                date_of_birth,
                gender,
                phone,
                email,
                address,
                blood_group,
                emergency_contact,
                created_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            patient_id,
            patient_code,
            name,
            date_of_birth,
            gender,
            phone,
            email,
            address,
            blood_group,
            emergency_contact,
            session["user_id"]
        ))


        database_patient_id = cursor.lastrowid


        conn.commit()

        conn.close()


        # -------------------------------------------------
        # AUDIT LOG
        # -------------------------------------------------

        create_audit_log(
            user_id=session["user_id"],
            action="ADD_PATIENT",
            description=(
                f"Patient added: "
                f"{patient_code} - {name}"
            )
        )


        # -------------------------------------------------
        # SUCCESS
        # -------------------------------------------------

        flash(
            "Patient added successfully.",
            "success"
        )


        return redirect(
            url_for(
                "patient_profile",
                patient_id=database_patient_id
            )
        )


    # -----------------------------------------------------
    # GET REQUEST
    # -----------------------------------------------------

    return render_template(
        "add_patient.html"
    )


# =========================================================
# PATIENT PROFILE
# =========================================================

@app.route(
    "/patients/<int:patient_id>"
)
@login_required
def patient_profile(patient_id):

    conn = get_db()

    # -----------------------------------------------------
    # PATIENT INFORMATION
    # -----------------------------------------------------

    patient = conn.execute("""
        SELECT
            patients.*,
            users.full_name AS created_by_name
        FROM patients
        LEFT JOIN users
            ON users.id = patients.created_by
        WHERE patients.id = ?
    """, (
        patient_id,
    )).fetchone()


    if patient is None:

        conn.close()

        flash(
            "Patient not found.",
            "danger"
        )

        return redirect(
            url_for("patients")
        )


    # -----------------------------------------------------
    # MEDICAL RECORDS
    # -----------------------------------------------------

    medical_records = conn.execute("""
        SELECT
            medical_records.id,
            medical_records.record_id,
            medical_records.created_at,
            medical_records.updated_at
        FROM medical_records
        WHERE medical_records.patient_id = ?
        ORDER BY medical_records.id DESC
    """, (
        patient_id,
    )).fetchall()


    conn.close()


    # -----------------------------------------------------
    # AUDIT
    # -----------------------------------------------------

    create_audit_log(
        user_id=session["user_id"],
        action="VIEW_PATIENT",
        description=(
            f"Viewed patient profile "
            f"{patient['patient_id']}"
        )
    )


    return render_template(
        "patient_profile.html",
        patient=patient,
        medical_records=medical_records
    )


# =========================================================
# MEDICAL RECORD LIST
# =========================================================

@app.route("/records")
@login_required
def records():

    conn = get_db()

    records_list = conn.execute("""
        SELECT
            medical_records.id,
            medical_records.record_id,
            medical_records.patient_id,
            medical_records.created_at,
            medical_records.updated_at,
            patients.patient_code,
            patients.name
        FROM medical_records
        JOIN patients
            ON patients.id = medical_records.patient_id
        ORDER BY medical_records.id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "records.html",
        records=records_list
    )


# =========================================================
# ADD MEDICAL RECORD
# =========================================================

@app.route(
    "/records/add",
    methods=["GET", "POST"]
)
@login_required
def add_record():

    conn = get_db()

    patients_list = conn.execute("""
        SELECT
            id,
            patient_id,
            patient_code,
            name
        FROM patients
        ORDER BY name
    """).fetchall()

    conn.close()


    # =====================================================
    # POST
    # =====================================================

    if request.method == "POST":

        patient_id = request.form.get(
            "patient_id",
            ""
        ).strip()

        diagnosis = request.form.get(
            "diagnosis",
            ""
        ).strip()

        symptoms = request.form.get(
            "symptoms",
            ""
        ).strip()

        medical_history = request.form.get(
            "medical_history",
            ""
        ).strip()

        prescription = request.form.get(
            "prescription",
            ""
        ).strip()

        test_results = request.form.get(
            "test_results",
            ""
        ).strip()

        doctor_notes = request.form.get(
            "doctor_notes",
            ""
        ).strip()


        # -------------------------------------------------
        # PATIENT REQUIRED
        # -------------------------------------------------

        if not patient_id:

            flash(
                "Please select a patient.",
                "danger"
            )

            return render_template(
                "add_record.html",
                patients=patients_list
            )


        # -------------------------------------------------
        # VERIFY PATIENT
        # -------------------------------------------------

        conn = get_db()

        patient = conn.execute("""
            SELECT
                id,
                patient_code,
                name,
                patient_id,
                phone
            FROM patients
            WHERE id = ?
        """, (
            patient_id,
        )).fetchone()


        if patient is None:

            conn.close()

            flash(
                "Selected patient does not exist.",
                "danger"
            )

            return render_template(
                "add_record.html",
                patients=patients_list
            )


        # -------------------------------------------------
        # ENCRYPT MEDICAL INFORMATION
        # -------------------------------------------------

        encrypted_diagnosis = (
            encrypt_data(diagnosis)
            if diagnosis
            else None
        )

        encrypted_symptoms = (
            encrypt_data(symptoms)
            if symptoms
            else None
        )

        encrypted_history = (
            encrypt_data(medical_history)
            if medical_history
            else None
        )

        encrypted_prescription = (
            encrypt_data(prescription)
            if prescription
            else None
        )

        encrypted_test_results = (
            encrypt_data(test_results)
            if test_results
            else None
        )

        encrypted_doctor_notes = (
            encrypt_data(doctor_notes)
            if doctor_notes
            else None
        )


        # -------------------------------------------------
        # GENERATE RECORD ID
        # -------------------------------------------------

        record_id = generate_record_id()


        # -------------------------------------------------
        # INSERT MEDICAL RECORD
        # -------------------------------------------------

        cursor = conn.execute("""
            INSERT INTO medical_records
            (
                record_id,
                patient_id,
                diagnosis,
                symptoms,
                medical_history,
                prescription,
                test_results,
                doctor_notes,
                created_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record_id,
            patient_id,
            encrypted_diagnosis,
            encrypted_symptoms,
            encrypted_history,
            encrypted_prescription,
            encrypted_test_results,
            encrypted_doctor_notes,
            session["user_id"]
        ))


        database_record_id = (
            cursor.lastrowid
        )


        conn.commit()

        conn.close()


        # -------------------------------------------------
        # SEARCH INDEX
        # -------------------------------------------------

        search_fields = {

            "patient_id":
                patient["patient_id"],

            "patient_code":
                patient["patient_code"],

            "patient_name":
                patient["name"],

            "phone":
                patient["phone"],

            "diagnosis":
                diagnosis,

            "symptoms":
                symptoms,

            "medical_history":
                medical_history,

            "prescription":
                prescription,

            "test_results":
                test_results,

            "doctor_notes":
                doctor_notes
        }


        create_search_index(
            database_record_id,
            search_fields
        )


        # -------------------------------------------------
        # AUDIT
        # -------------------------------------------------

        create_audit_log(
            user_id=session["user_id"],
            action="ADD_MEDICAL_RECORD",
            description=(
                f"Medical record {record_id} "
                f"created for "
                f"{patient['patient_code']}"
            )
        )


        flash(
            "Medical record added successfully.",
            "success"
        )


        return redirect(
            url_for(
                "record_detail",
                record_id=database_record_id
            )
        )


    # =====================================================
    # GET
    # =====================================================

    return render_template(
        "add_record.html",
        patients=patients_list
    )


# =========================================================
# MEDICAL RECORD DETAIL
# =========================================================

@app.route(
    "/records/<int:record_id>"
)
@login_required
def record_detail(record_id):

    conn = get_db()

    record = conn.execute("""
        SELECT
            medical_records.*,

            patients.patient_id AS patient_unique_id,
            patients.patient_code,
            patients.name AS patient_name,
            patients.phone AS patient_phone

        FROM medical_records

        JOIN patients
            ON patients.id =
               medical_records.patient_id

        WHERE medical_records.id = ?
    """, (
        record_id,
    )).fetchone()


    conn.close()


    if record is None:

        flash(
            "Medical record not found.",
            "danger"
        )

        return redirect(
            url_for("records")
        )


    # -----------------------------------------------------
    # DECRYPT MEDICAL FIELDS
    # -----------------------------------------------------

    record_data = dict(record)


    for field in [
        "diagnosis",
        "symptoms",
        "medical_history",
        "prescription",
        "test_results",
        "doctor_notes"
    ]:

        try:

            if record_data[field]:

                record_data[field] = decrypt_data(
                    record_data[field]
                )

            else:

                record_data[field] = ""

        except Exception:

            record_data[field] = (
                "[Unable to decrypt]"
            )


    # -----------------------------------------------------
    # AUDIT
    # -----------------------------------------------------

    create_audit_log(
        user_id=session["user_id"],
        action="VIEW_MEDICAL_RECORD",
        description=(
            f"Viewed medical record "
            f"{record['record_id']}"
        )
    )


    return render_template(
        "record_detail.html",
        record=record_data
    )


# =========================================================
# PRIVACY-PRESERVING SEARCH
# =========================================================

@app.route("/search")
@login_required
def search():

    query = request.args.get(
        "q",
        ""
    ).strip()


    if not query:

        return render_template(
            "search.html",
            query="",
            results=[]
        )


    query_tokens = create_query_tokens(
        query
    )


    if not query_tokens:

        return render_template(
            "search.html",
            query=query,
            results=[]
        )


    conn = get_db()


    placeholders = ",".join(
        ["?"] * len(query_tokens)
    )


    # -----------------------------------------------------
    # SEARCH USING HMAC TOKENS
    # -----------------------------------------------------

    query_sql = f"""
        SELECT DISTINCT
            medical_records.id,
            medical_records.record_id,
            medical_records.created_at,
            patients.patient_code,
            patients.name
        FROM medical_records

        JOIN patients
            ON patients.id =
               medical_records.patient_id

        JOIN search_index
            ON search_index.record_id =
               medical_records.id

        WHERE search_index.search_token
              IN ({placeholders})

        ORDER BY medical_records.id DESC
    """


    results = conn.execute(
        query_sql,
        query_tokens
    ).fetchall()


    conn.close()


    # -----------------------------------------------------
    # AUDIT
    # -----------------------------------------------------

    create_audit_log(
        user_id=session["user_id"],
        action="SEARCH_MEDICAL_RECORDS",
        description=(
            "Privacy-preserving search performed."
        )
    )


    return render_template(
        "search.html",
        query=query,
        results=results
    )


# =========================================================
# NOTIFICATIONS
# =========================================================

@app.route("/notifications")
@login_required
def notifications():

    conn = get_db()

    notifications_list = conn.execute("""
        SELECT
            id,
            title,
            message,
            notification_type,
            is_read,
            created_at
        FROM security_notifications
        WHERE user_id = ?
        ORDER BY id DESC
    """, (
        session["user_id"],
    )).fetchall()

    conn.close()

    return render_template(
        "notifications.html",
        notifications=notifications_list
    )


# =========================================================
# MARK NOTIFICATION AS READ
# =========================================================

@app.route(
    "/notifications/read/<int:notification_id>",
    methods=["POST"]
)
@login_required
def mark_notification_read(
    notification_id
):

    conn = get_db()

    conn.execute("""
        UPDATE security_notifications
        SET is_read = 1
        WHERE id = ?
        AND user_id = ?
    """, (
        notification_id,
        session["user_id"]
    ))

    conn.commit()

    conn.close()

    return redirect(
        url_for("notifications")
    )


# =========================================================
# MARK ALL NOTIFICATIONS READ
# =========================================================

@app.route(
    "/notifications/read-all",
    methods=["POST"]
)
@login_required
def mark_all_notifications_read():

    conn = get_db()

    conn.execute("""
        UPDATE security_notifications
        SET is_read = 1
        WHERE user_id = ?
    """, (
        session["user_id"],
    ))

    conn.commit()

    conn.close()

    flash(
        "All notifications marked as read.",
        "success"
    )

    return redirect(
        url_for("notifications")
    )


# =========================================================
# AUDIT LOGS
# =========================================================

@app.route("/audit-logs")
@role_required("admin")
def audit_logs():

    conn = get_db()

    logs = conn.execute("""
        SELECT
            audit_logs.id,
            audit_logs.action,
            audit_logs.description,
            audit_logs.ip_address,
            audit_logs.user_agent,
            audit_logs.created_at,
            users.username
        FROM audit_logs

        LEFT JOIN users
            ON users.id =
               audit_logs.user_id

        ORDER BY audit_logs.id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "audit_logs.html",
        logs=logs
    )


# =========================================================
# SECURITY ALERTS
# =========================================================

@app.route("/security-alerts")
@role_required(
    "admin",
    "authorized"
)
def security_alerts():

    conn = get_db()

    alerts = conn.execute("""
        SELECT
            id,
            username,
            action,
            ip_address,
            description,
            created_at
        FROM security_alerts
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "security_alerts.html",
        alerts=alerts
    )


# =========================================================
# USERS
# =========================================================

@app.route("/users")
@role_required("admin")
def users():

    conn = get_db()

    users_list = conn.execute("""
        SELECT
            id,
            username,
            full_name,
            email,
            role,
            is_active,
            created_at
        FROM users
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "users.html",
        users=users_list
    )


# =========================================================
# ADD USER
# =========================================================

@app.route(
    "/users/add",
    methods=["GET", "POST"]
)
@role_required("admin")
def add_user():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        full_name = request.form.get(
            "full_name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip()

        role = request.form.get(
            "role",
            "authorized"
        ).strip()


        # -------------------------------------------------
        # REQUIRED
        # -------------------------------------------------

        if not username or not password:

            flash(
                "Username and password are required.",
                "danger"
            )

            return render_template(
                "add_user.html"
            )


        # -------------------------------------------------
        # PASSWORD HASH
        # -------------------------------------------------

        from werkzeug.security import (
            generate_password_hash
        )

        password_hash = generate_password_hash(
            password
        )


        conn = get_db()


        try:

            conn.execute("""
                INSERT INTO users
                (
                    username,
                    password_hash,
                    full_name,
                    email,
                    role,
                    is_active
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                username,
                password_hash,
                full_name,
                email,
                role,
                1
            ))

            conn.commit()


        except sqlite3.IntegrityError:

            conn.close()

            flash(
                "Username or email already exists.",
                "danger"
            )

            return render_template(
                "add_user.html"
            )


        conn.close()


        # -------------------------------------------------
        # AUDIT
        # -------------------------------------------------

        create_audit_log(
            user_id=session["user_id"],
            action="ADD_USER",
            description=(
                f"New user created: {username}"
            )
        )


        flash(
            "User created successfully.",
            "success"
        )


        return redirect(
            url_for("users")
        )


    return render_template(
        "add_user.html"
    )


# =========================================================
# REPORTS
# =========================================================

@app.route("/reports")
@login_required
def reports():

    conn = get_db()


    # -----------------------------------------------------
    # TOTAL PATIENTS
    # -----------------------------------------------------

    total_patients = conn.execute("""
        SELECT COUNT(*) AS count
        FROM patients
    """).fetchone()["count"]


    # -----------------------------------------------------
    # TOTAL RECORDS
    # -----------------------------------------------------

    total_records = conn.execute("""
        SELECT COUNT(*) AS count
        FROM medical_records
    """).fetchone()["count"]


    # -----------------------------------------------------
    # TOTAL USERS
    # -----------------------------------------------------

    total_users = conn.execute("""
        SELECT COUNT(*) AS count
        FROM users
        WHERE is_active = 1
    """).fetchone()["count"]


    # -----------------------------------------------------
    # TOTAL NOTIFICATIONS
    # -----------------------------------------------------

    total_notifications = conn.execute("""
        SELECT COUNT(*) AS count
        FROM security_notifications
    """).fetchone()["count"]


    # -----------------------------------------------------
    # TOTAL SECURITY ALERTS
    # -----------------------------------------------------

    total_alerts = conn.execute("""
        SELECT COUNT(*) AS count
        FROM security_alerts
    """).fetchone()["count"]


    # -----------------------------------------------------
    # TOTAL AUDIT LOGS
    # -----------------------------------------------------

    total_audit_logs = conn.execute("""
        SELECT COUNT(*) AS count
        FROM audit_logs
    """).fetchone()["count"]


    # -----------------------------------------------------
    # PATIENT REPORT
    # -----------------------------------------------------

    patients_report = conn.execute("""
        SELECT
            p.id,
            p.patient_id,
            p.patient_code,
            p.name,
            p.phone,
            p.gender,
            p.date_of_birth,
            p.blood_group,
            p.created_at,

            COUNT(mr.id) AS record_count

        FROM patients p

        LEFT JOIN medical_records mr
            ON mr.patient_id = p.id

        GROUP BY
            p.id,
            p.patient_id,
            p.patient_code,
            p.name,
            p.phone,
            p.gender,
            p.date_of_birth,
            p.blood_group,
            p.created_at

        ORDER BY p.id DESC
    """).fetchall()


    # -----------------------------------------------------
    # RECENT MEDICAL RECORDS
    # -----------------------------------------------------

    recent_records = conn.execute("""
        SELECT
            mr.record_id,
            mr.created_at,
            p.patient_id,
            p.patient_code,
            p.name

        FROM medical_records mr

        INNER JOIN patients p
            ON mr.patient_id = p.id

        ORDER BY mr.id DESC

        LIMIT 10
    """).fetchall()


    conn.close()


    # -----------------------------------------------------
    # SEND DATA TO TEMPLATE
    # -----------------------------------------------------

    return render_template(
        "reports.html",

        total_patients=total_patients,

        total_records=total_records,

        total_users=total_users,

        total_notifications=total_notifications,

        total_alerts=total_alerts,

        total_audit_logs=total_audit_logs,

        patients_report=patients_report,

        recent_records=recent_records
    )


# =========================================================
# BACKUP PAGE
# =========================================================

@app.route("/backup")
@role_required("admin")
def backup():

    conn = get_db()

    backups = conn.execute("""
        SELECT
            backup_logs.id,
            backup_logs.file_name,
            backup_logs.backup_type,
            backup_logs.created_at,
            users.username
        FROM backup_logs

        LEFT JOIN users
            ON users.id =
               backup_logs.created_by

        ORDER BY backup_logs.id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "backup.html",
        backups=backups
    )


# =========================================================
# CREATE DATABASE BACKUP
# =========================================================

@app.route(
    "/backup/create",
    methods=["POST"]
)
@role_required("admin")
def create_backup():

    source_database = "medical_records.db"


    if not os.path.exists(
        source_database
    ):

        flash(
            "Database file not found.",
            "danger"
        )

        return redirect(
            url_for("backup")
        )


    backup_folder = "backups"


    os.makedirs(
        backup_folder,
        exist_ok=True
    )


    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )


    backup_filename = (
        f"medical_records_backup_"
        f"{timestamp}.db"
    )


    backup_path = os.path.join(
        backup_folder,
        backup_filename
    )


    try:

        shutil.copy2(
            source_database,
            backup_path
        )


        conn = get_db()


        conn.execute("""
            INSERT INTO backup_logs
            (
                file_name,
                backup_type,
                created_by
            )
            VALUES (?, ?, ?)
        """, (
            backup_filename,
            "database",
            session["user_id"]
        ))


        conn.commit()

        conn.close()


        create_audit_log(
            user_id=session["user_id"],
            action="CREATE_BACKUP",
            description=(
                f"Database backup created: "
                f"{backup_filename}"
            )
        )


        flash(
            "Database backup created successfully.",
            "success"
        )


    except Exception as error:

        flash(
            f"Backup failed: {error}",
            "danger"
        )


    return redirect(
        url_for("backup")
    )


# =========================================================
# DOWNLOAD BACKUP
# =========================================================

@app.route(
    "/backup/download/<path:filename>"
)
@role_required("admin")
def download_backup(filename):

    backup_path = os.path.join(
        "backups",
        filename
    )


    if not os.path.exists(
        backup_path
    ):

        flash(
            "Backup file not found.",
            "danger"
        )

        return redirect(
            url_for("backup")
        )


    create_audit_log(
        user_id=session["user_id"],
        action="DOWNLOAD_BACKUP",
        description=(
            f"Downloaded backup: {filename}"
        )
    )


    return send_file(
        backup_path,
        as_attachment=True
    )


# =========================================================
# API - DASHBOARD STATS
# =========================================================

@app.route(
    "/api/dashboard-stats"
)
@login_required
def dashboard_stats():

    conn = get_db()


    patients_count = conn.execute("""
        SELECT COUNT(*) AS count
        FROM patients
    """).fetchone()["count"]


    records_count = conn.execute("""
        SELECT COUNT(*) AS count
        FROM medical_records
    """).fetchone()["count"]


    users_count = conn.execute("""
        SELECT COUNT(*) AS count
        FROM users
        WHERE is_active = 1
    """).fetchone()["count"]


    alerts_count = conn.execute("""
        SELECT COUNT(*) AS count
        FROM security_alerts
    """).fetchone()["count"]


    conn.close()


    return jsonify({

        "patients":
            patients_count,

        "records":
            records_count,

        "users":
            users_count,

        "security_alerts":
            alerts_count

    })


# =========================================================
# API - PATIENT SEARCH
# =========================================================

@app.route(
    "/api/patients/search"
)
@login_required
def api_patient_search():

    keyword = request.args.get(
        "q",
        ""
    ).strip()


    if not keyword:

        return jsonify([])


    conn = get_db()


    patients_list = conn.execute("""
        SELECT
            id,
            patient_id,
            patient_code,
            name,
            phone
        FROM patients
        WHERE
            patient_code LIKE ?
            OR patient_id LIKE ?
            OR name LIKE ?
            OR phone LIKE ?
        ORDER BY name
        LIMIT 20
    """, (
        f"%{keyword}%",
        f"%{keyword}%",
        f"%{keyword}%",
        f"%{keyword}%"
    )).fetchall()


    conn.close()


    return jsonify([
        dict(patient)
        for patient in patients_list
    ])


# =========================================================
# 404 ERROR
# =========================================================

@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "base.html"
    ), 404


# =========================================================
# 500 ERROR
# =========================================================

@app.errorhandler(500)
def internal_server_error(error):

    return """
    <!DOCTYPE html>

    <html>

    <head>

        <title>
            Server Error
        </title>

        <style>

            body {
                font-family: Arial, sans-serif;
                padding: 50px;
                text-align: center;
            }

            h1 {
                color: #c0392b;
            }

        </style>

    </head>

    <body>

        <h1>
            500 - Internal Server Error
        </h1>

        <p>
            Something went wrong while
            processing your request.
        </p>

        <a href="/dashboard">
            Back to Dashboard
        </a>

    </body>

    </html>
    """, 500


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    print()

    print(
        "=============================================="
    )

    print(
        "   PRIVACY MEDICAL RECORDS SYSTEM"
    )

    print(
        "=============================================="
    )

    print()

    print(
        "Server starting..."
    )

    print()

    print(
        "Login:"
    )

    print(
        "Username : admin"
    )

    print(
        "Password : Admin@123"
    )

    print()

    print(
        "Open browser:"
    )

    print(
        "http://127.0.0.1:5000"
    )

    print()


    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
