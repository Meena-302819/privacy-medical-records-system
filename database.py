import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = "medical_records.db"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# =========================================================
# CREATE TABLES
# =========================================================

def create_tables():

    conn = get_db()
    cursor = conn.cursor()

    # =====================================================
    # USERS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL DEFAULT 'authorized',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # =====================================================
    # PATIENTS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            patient_id TEXT UNIQUE NOT NULL,

            patient_code TEXT UNIQUE,

            name TEXT NOT NULL,

            date_of_birth TEXT,

            gender TEXT,

            phone TEXT,

            email TEXT,

            address TEXT,

            blood_group TEXT,

            emergency_contact TEXT,

            created_by INTEGER,

            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (created_by)
            REFERENCES users(id)
            ON DELETE SET NULL
        )
    """)

    # =====================================================
    # MEDICAL RECORDS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS medical_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            record_id TEXT UNIQUE NOT NULL,

            patient_id INTEGER NOT NULL,

            diagnosis TEXT,

            symptoms TEXT,

            medical_history TEXT,

            prescription TEXT,

            test_results TEXT,

            doctor_notes TEXT,

            created_by INTEGER,

            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (patient_id)
            REFERENCES patients(id)
            ON DELETE CASCADE,

            FOREIGN KEY (created_by)
            REFERENCES users(id)
            ON DELETE SET NULL
        )
    """)

    # =====================================================
    # SEARCH INDEX
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS search_index (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            record_id INTEGER NOT NULL,

            search_token TEXT NOT NULL,

            field_name TEXT NOT NULL,

            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (record_id)
            REFERENCES medical_records(id)
            ON DELETE CASCADE,

            UNIQUE(record_id, search_token)
        )
    """)

    # =====================================================
    # AUDIT LOGS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            action TEXT NOT NULL,

            description TEXT,

            ip_address TEXT,

            user_agent TEXT,

            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE SET NULL
        )
    """)

    # =====================================================
    # SECURITY NOTIFICATIONS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            title TEXT NOT NULL,

            message TEXT NOT NULL,

            notification_type TEXT NOT NULL DEFAULT 'security',

            is_read INTEGER NOT NULL DEFAULT 0,

            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
        )
    """)

    # =====================================================
    # SECURITY ALERTS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT,

            action TEXT NOT NULL,

            ip_address TEXT,

            description TEXT,

            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # =====================================================
    # LOGIN ATTEMPTS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT,

            success INTEGER NOT NULL DEFAULT 0,

            ip_address TEXT,

            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # =====================================================
    # BACKUP LOGS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS backup_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            file_name TEXT NOT NULL,

            backup_type TEXT NOT NULL DEFAULT 'database',

            created_by INTEGER,

            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (created_by)
            REFERENCES users(id)
            ON DELETE SET NULL
        )
    """)

    # =====================================================
    # SYSTEM SETTINGS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            setting_key TEXT UNIQUE NOT NULL,

            setting_value TEXT,

            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # =====================================================
    # SAFE INDEXES
    #
    # IMPORTANT:
    # patient_code index is NOT created here.
    # It will be created AFTER migration.
    # =====================================================

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_patients_patient_id
        ON patients(patient_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_patients_phone
        ON patients(phone)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_medical_records_patient
        ON medical_records(patient_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_search_token
        ON search_index(search_token)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_user
        ON audit_logs(user_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_user
        ON security_notifications(user_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_created
        ON security_alerts(created_at)
    """)

    conn.commit()
    conn.close()


# =========================================================
# DATABASE MIGRATION
# =========================================================

def migrate_database():

    conn = get_db()
    cursor = conn.cursor()

    # =====================================================
    # PATIENTS TABLE
    # =====================================================

    cursor.execute("PRAGMA table_info(patients)")
    patient_columns = [row["name"] for row in cursor.fetchall()]

    # -----------------------------------------------------
    # patient_code
    # -----------------------------------------------------

    if "patient_code" not in patient_columns:

        cursor.execute("""
            ALTER TABLE patients
            ADD COLUMN patient_code TEXT
        """)

        print("Added missing column: patients.patient_code")

    # -----------------------------------------------------
    # Make sure other common patient columns exist
    # -----------------------------------------------------

    if "patient_id" not in patient_columns:

        cursor.execute("""
            ALTER TABLE patients
            ADD COLUMN patient_id TEXT
        """)

        print("Added missing column: patients.patient_id")

    if "name" not in patient_columns:

        cursor.execute("""
            ALTER TABLE patients
            ADD COLUMN name TEXT
        """)

        print("Added missing column: patients.name")

    if "date_of_birth" not in patient_columns:

        cursor.execute("""
            ALTER TABLE patients
            ADD COLUMN date_of_birth TEXT
        """)

        print("Added missing column: patients.date_of_birth")

    if "gender" not in patient_columns:

        cursor.execute("""
            ALTER TABLE patients
            ADD COLUMN gender TEXT
        """)

        print("Added missing column: patients.gender")

    if "phone" not in patient_columns:

        cursor.execute("""
            ALTER TABLE patients
            ADD COLUMN phone TEXT
        """)

        print("Added missing column: patients.phone")

    if "email" not in patient_columns:

        cursor.execute("""
            ALTER TABLE patients
            ADD COLUMN email TEXT
        """)

        print("Added missing column: patients.email")

    if "address" not in patient_columns:

        cursor.execute("""
            ALTER TABLE patients
            ADD COLUMN address TEXT
        """)

        print("Added missing column: patients.address")

    if "blood_group" not in patient_columns:

        cursor.execute("""
            ALTER TABLE patients
            ADD COLUMN blood_group TEXT
        """)

        print("Added missing column: patients.blood_group")

    if "emergency_contact" not in patient_columns:

        cursor.execute("""
            ALTER TABLE patients
            ADD COLUMN emergency_contact TEXT
        """)

        print("Added missing column: patients.emergency_contact")

    if "created_by" not in patient_columns:

        cursor.execute("""
            ALTER TABLE patients
            ADD COLUMN created_by INTEGER
        """)

        print("Added missing column: patients.created_by")

    if "created_at" not in patient_columns:

        cursor.execute("""
            ALTER TABLE patients
            ADD COLUMN created_at TEXT
            DEFAULT CURRENT_TIMESTAMP
        """)

        print("Added missing column: patients.created_at")

    # =====================================================
    # USERS TABLE
    # =====================================================

    cursor.execute("PRAGMA table_info(users)")
    user_columns = [row["name"] for row in cursor.fetchall()]

    if "role" not in user_columns:

        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN role TEXT NOT NULL DEFAULT 'authorized'
        """)

        print("Added missing column: users.role")

    if "is_active" not in user_columns:

        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1
        """)

        print("Added missing column: users.is_active")

    if "full_name" not in user_columns:

        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN full_name TEXT
        """)

        print("Added missing column: users.full_name")

    if "email" not in user_columns:

        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN email TEXT
        """)

        print("Added missing column: users.email")

    # =====================================================
    # MEDICAL RECORDS TABLE
    # =====================================================

    cursor.execute("PRAGMA table_info(medical_records)")
    medical_columns = [row["name"] for row in cursor.fetchall()]

    if "record_id" not in medical_columns:

        cursor.execute("""
            ALTER TABLE medical_records
            ADD COLUMN record_id TEXT
        """)

        print("Added missing column: medical_records.record_id")

    if "patient_id" not in medical_columns:

        cursor.execute("""
            ALTER TABLE medical_records
            ADD COLUMN patient_id INTEGER
        """)

        print("Added missing column: medical_records.patient_id")

    if "diagnosis" not in medical_columns:

        cursor.execute("""
            ALTER TABLE medical_records
            ADD COLUMN diagnosis TEXT
        """)

        print("Added missing column: medical_records.diagnosis")

    if "symptoms" not in medical_columns:

        cursor.execute("""
            ALTER TABLE medical_records
            ADD COLUMN symptoms TEXT
        """)

        print("Added missing column: medical_records.symptoms")

    if "medical_history" not in medical_columns:

        cursor.execute("""
            ALTER TABLE medical_records
            ADD COLUMN medical_history TEXT
        """)

        print("Added missing column: medical_records.medical_history")

    if "prescription" not in medical_columns:

        cursor.execute("""
            ALTER TABLE medical_records
            ADD COLUMN prescription TEXT
        """)

        print("Added missing column: medical_records.prescription")

    if "test_results" not in medical_columns:

        cursor.execute("""
            ALTER TABLE medical_records
            ADD COLUMN test_results TEXT
        """)

        print("Added missing column: medical_records.test_results")

    if "doctor_notes" not in medical_columns:

        cursor.execute("""
            ALTER TABLE medical_records
            ADD COLUMN doctor_notes TEXT
        """)

        print("Added missing column: medical_records.doctor_notes")

    if "created_by" not in medical_columns:

        cursor.execute("""
            ALTER TABLE medical_records
            ADD COLUMN created_by INTEGER
        """)

        print("Added missing column: medical_records.created_by")

    if "created_at" not in medical_columns:

        cursor.execute("""
            ALTER TABLE medical_records
            ADD COLUMN created_at TEXT
            DEFAULT CURRENT_TIMESTAMP
        """)

        print("Added missing column: medical_records.created_at")

    if "updated_at" not in medical_columns:

        cursor.execute("""
            ALTER TABLE medical_records
            ADD COLUMN updated_at TEXT
        """)

        print("Added missing column: medical_records.updated_at")

    conn.commit()
    conn.close()


# =========================================================
# GENERATE PATIENT CODES
# =========================================================

def generate_missing_patient_codes():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id
        FROM patients
        WHERE patient_code IS NULL
           OR patient_code = ''
        ORDER BY id
    """)

    patients = cursor.fetchall()

    for patient in patients:

        patient_db_id = patient["id"]

        patient_code = f"PAT{patient_db_id:05d}"

        # Check duplicate
        cursor.execute("""
            SELECT id
            FROM patients
            WHERE patient_code = ?
        """, (patient_code,))

        existing = cursor.fetchone()

        if existing is None:

            cursor.execute("""
                UPDATE patients
                SET patient_code = ?
                WHERE id = ?
            """, (
                patient_code,
                patient_db_id
            ))

    conn.commit()
    conn.close()

    if patients:
        print("Missing patient codes generated successfully.")


# =========================================================
# CREATE PATIENT CODE INDEX
# =========================================================

def create_patient_code_index():

    conn = get_db()
    cursor = conn.cursor()

    # Now patient_code definitely exists
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_patients_patient_code
        ON patients(patient_code)
    """)

    conn.commit()
    conn.close()


# =========================================================
# CREATE DEFAULT ADMIN
# =========================================================

def create_default_admin():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id
        FROM users
        WHERE username = ?
    """, ("admin",))

    existing_admin = cursor.fetchone()

    if existing_admin is None:

        password_hash = generate_password_hash("Admin@123")

        cursor.execute("""
            INSERT INTO users (
                username,
                password_hash,
                full_name,
                email,
                role,
                is_active
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "admin",
            password_hash,
            "Administrator",
            "sujithram3028@gmail.com",
            "admin",
            1
        ))

        conn.commit()

        print("Default admin account created.")

    else:

        print("Default admin account already exists.")

    conn.close()


# =========================================================
# INITIALIZE DATABASE
# =========================================================

def init_db():

    print()
    print("==============================================")
    print("   PRIVACY MEDICAL RECORDS SYSTEM")
    print("   DATABASE INITIALIZATION")
    print("==============================================")
    print()

    # -----------------------------------------------------
    # 1. Create missing tables
    # -----------------------------------------------------

    create_tables()

    # -----------------------------------------------------
    # 2. Migrate old database
    # -----------------------------------------------------

    migrate_database()

    # -----------------------------------------------------
    # 3. Generate patient codes
    # -----------------------------------------------------

    generate_missing_patient_codes()

    # -----------------------------------------------------
    # 4. Create patient code index
    # -----------------------------------------------------

    create_patient_code_index()

    # -----------------------------------------------------
    # 5. Create default admin
    # -----------------------------------------------------

    create_default_admin()

    print()
    print("==============================================")
    print("   DATABASE INITIALIZED SUCCESSFULLY")
    print("==============================================")
    print()


# =========================================================
# RUN DIRECTLY
# =========================================================

if __name__ == "__main__":
    init_db()
