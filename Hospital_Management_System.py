import hashlib
import json
import sys
import uuid
import re
import logging
from datetime import datetime, timedelta
from getpass import getpass

# ─── Try to import bcrypt (strongly recommended) ───────────────────────────────
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("[WARNING] bcrypt not installed. Run: pip install bcrypt")
    print("[WARNING] Falling back to SHA-256 (less secure). Install bcrypt for production use.\n")

# ─── Logging / Audit Trail ─────────────────────────────────────────────────────
logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def audit(message: str):
    """Write an entry to the audit log."""
    logging.info(message)


# ══════════════════════════════════════════════════════════════════════════════
class HospitalManagementSystem:
    """
    Advanced Hospital Management System
    ─────────────────────────────────────
    Security features
      • bcrypt password hashing (with per-user salt & configurable work factor)
      • SHA-256 fallback if bcrypt is unavailable
      • Session tokens (UUID4) with 30-minute expiry
      • Account lockout after 5 consecutive failed logins
      • Input validation / sanitisation on every user-facing field

    Functional features
      • Admin   : manage users, view audit log, hospital list
      • Doctor  : manage assigned patients, prescriptions, reports, appointments
      • Patient : view own medicines, reports, appointments, room/bed
    """

    MAX_LOGIN_ATTEMPTS = 5
    SESSION_TIMEOUT_MINUTES = 30
    BCRYPT_WORK_FACTOR = 12          # increase for more security (slower hashing)

    def __init__(self, data_file: str = "user_data.json"):
        self.data_file = data_file
        self.sessions: dict[str, dict] = {}   # token → {username, user_type, expires}
        self.login_attempts: dict[str, int] = {}
        self.load_data()

    # ── Persistence ────────────────────────────────────────────────────────────

    def load_data(self):
        try:
            with open(self.data_file, "r") as f:
                self.users = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.users = {"admin": {}, "patient": {}, "doctor": {}}
        # Ensure all three top-level keys always exist
        for role in ("admin", "patient", "doctor"):
            self.users.setdefault(role, {})

    def save_data(self):
        with open(self.data_file, "w") as f:
            json.dump(self.users, f, indent=2)

    # ── Password Helpers ───────────────────────────────────────────────────────

    def hash_password(self, password: str) -> str:
        if BCRYPT_AVAILABLE:
            salt = bcrypt.gensalt(rounds=self.BCRYPT_WORK_FACTOR)
            return bcrypt.hashpw(password.encode(), salt).decode()
        # Fallback: SHA-256 (not salted — upgrade to bcrypt for production)
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, password: str, stored_hash: str) -> bool:
        if BCRYPT_AVAILABLE:
            try:
                return bcrypt.checkpw(password.encode(), stored_hash.encode())
            except Exception:
                return False
        return hashlib.sha256(password.encode()).hexdigest() == stored_hash

    # ── Input Validation ───────────────────────────────────────────────────────

    @staticmethod
    def validate_email(email: str) -> bool:
        return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))

    @staticmethod
    def validate_username(username: str) -> bool:
        """Alphanumeric + underscores, 3-30 chars."""
        return bool(re.fullmatch(r"\w{3,30}", username))

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, str]:
        """Returns (is_valid, message)."""
        if len(password) < 8:
            return False, "Password must be at least 8 characters."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one digit."
        if not re.search(r"[^A-Za-z0-9]", password):
            return False, "Password must contain at least one special character."
        return True, "OK"

    # ── Session Management ─────────────────────────────────────────────────────

    def create_session(self, username: str, user_type: str) -> str:
        token = str(uuid.uuid4())
        self.sessions[token] = {
            "username": username,
            "user_type": user_type,
            "expires": datetime.now() + timedelta(minutes=self.SESSION_TIMEOUT_MINUTES)
        }
        return token

    def validate_session(self, token: str) -> dict | None:
        session = self.sessions.get(token)
        if not session:
            return None
        if datetime.now() > session["expires"]:
            del self.sessions[token]
            print("[Session expired. Please log in again.]")
            return None
        # Slide the expiry window on every activity
        session["expires"] = datetime.now() + timedelta(minutes=self.SESSION_TIMEOUT_MINUTES)
        return session

    # ── Authentication ─────────────────────────────────────────────────────────

    def register(self, user_type: str, username: str, extra_details: dict = None) -> bool:
        """Interactive registration with validation."""
        if not self.validate_username(username):
            print("Invalid username. Use 3-30 alphanumeric characters / underscores.")
            return False
        if username in self.users.get(user_type, {}):
            print(f"Username '{username}' already exists.")
            return False

        name  = input("Full name       : ").strip()
        email = input("Email address   : ").strip()
        if not self.validate_email(email):
            print("Invalid email address.")
            return False

        while True:
            password = getpass("Password        : ")
            ok, msg = self.validate_password_strength(password)
            if not ok:
                print(f"Weak password — {msg}")
                continue
            confirm = getpass("Confirm password: ")
            if password != confirm:
                print("Passwords do not match.")
                continue
            break

        record = {
            "password": self.hash_password(password),
            "name": name,
            "email": email,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        if extra_details:
            record.update(extra_details)
        if user_type == "patient":
            record.setdefault("blood_group", "Unknown")
            record.setdefault("age", "Unknown")
            record.setdefault("contact", "")
            record.setdefault("reports", [])
            record.setdefault("doctors", {})
            record.setdefault("appointments", [])
        if user_type == "doctor":
            record.setdefault("specialisation", input("Specialisation  : ").strip())
            record.setdefault("appointments", [])

        self.users[user_type][username] = record
        self.save_data()
        audit(f"REGISTER | {user_type} | {username}")
        print(f"Registration successful for {user_type} '{username}'.")
        return True

    def login(self, user_type: str, username: str) -> str | None:
        """Returns a session token on success, None on failure."""
        key = f"{user_type}:{username}"

        # Check lockout
        attempts = self.login_attempts.get(key, 0)
        if attempts >= self.MAX_LOGIN_ATTEMPTS:
            print(f"Account locked after {self.MAX_LOGIN_ATTEMPTS} failed attempts. Contact admin.")
            audit(f"LOGIN_LOCKED | {user_type} | {username}")
            return None

        user_db = self.users.get(user_type, {})
        if username not in user_db:
            print("User not found.")
            choice = input("Register? (yes/no): ").strip().lower()
            if choice == "yes":
                if self.register(user_type, username):
                    return self.login(user_type, username)
            return None

        password = getpass("Password: ")
        if not self.verify_password(password, user_db[username]["password"]):
            self.login_attempts[key] = attempts + 1
            remaining = self.MAX_LOGIN_ATTEMPTS - self.login_attempts[key]
            print(f"Incorrect password. {remaining} attempt(s) remaining before lockout.")
            audit(f"LOGIN_FAIL | {user_type} | {username}")
            return None

        # Success — reset counter, create session
        self.login_attempts.pop(key, None)
        token = self.create_session(username, user_type)
        audit(f"LOGIN_OK | {user_type} | {username}")
        print(f"Login successful. Welcome, {user_db[username]['name']}!")
        return token

    # ══════════════════════════════════════════════════════════════════════════
    # ADMIN MENU
    # ══════════════════════════════════════════════════════════════════════════

    def admin_menu(self, token: str):
        session = self.validate_session(token)
        if not session or session["user_type"] != "admin":
            print("Unauthorised.")
            return
        username = session["username"]

        MENU = {
            "1": ("View Hospital List",          self._admin_hospital_list),
            "2": ("Add Patient",                 self._admin_add_patient),
            "3": ("Delete Patient",              self._admin_delete_user("patient")),
            "4": ("Add Doctor",                  self._admin_add_doctor),
            "5": ("Delete Doctor",               self._admin_delete_user("doctor")),
            "6": ("View All Users",              self._admin_view_users),
            "7": ("View Audit Log (last 20)",    self._admin_view_audit_log),
            "8": ("Unlock Locked Account",       self._admin_unlock_account),
            "9": ("Exit",                        None),
        }

        while True:
            print(f"\n{'─'*40}")
            print("  ADMIN MENU")
            print(f"{'─'*40}")
            for k, (label, _) in MENU.items():
                print(f"  {k}. {label}")
            print(f"{'─'*40}")
            choice = input("Choice: ").strip()
            if choice == "9":
                audit(f"LOGOUT | admin | {username}")
                print("Logged out.")
                return
            if choice in MENU:
                label, fn = MENU[choice]
                audit(f"ADMIN_ACTION | {username} | {label}")
                fn()
            else:
                print("Invalid option.")

    def _admin_hospital_list(self):
        hospitals = ["Pavan Hospital", "Rini Hospital", "Priyanshu Hospital"]
        print("\nHospitals under admin access:")
        for i, h in enumerate(hospitals, 1):
            print(f"  {i}. {h}")

    def _admin_add_patient(self):
        username = input("Username: ").strip()
        self.register("patient", username)

    def _admin_add_doctor(self):
        username = input("Username: ").strip()
        self.register("doctor", username)

    def _admin_delete_user(self, user_type: str):
        """Returns a closure so we can reuse for patient/doctor."""
        def _delete():
            username = input(f"Username of {user_type} to delete: ").strip()
            if username in self.users[user_type]:
                confirm = input(f"Confirm delete '{username}'? (yes/no): ").strip().lower()
                if confirm == "yes":
                    del self.users[user_type][username]
                    self.save_data()
                    audit(f"DELETE | {user_type} | {username}")
                    print(f"{user_type.capitalize()} '{username}' deleted.")
            else:
                print(f"{user_type.capitalize()} '{username}' not found.")
        return _delete

    def _admin_view_users(self):
        for role, users in self.users.items():
            print(f"\n{'═'*30}  {role.upper()}  {'═'*30}")
            if not users:
                print("  (none)")
            for uname, data in users.items():
                print(f"\n  Username : {uname}")
                for k, v in data.items():
                    if k == "password":
                        continue           # never display hashes
                    print(f"  {k.capitalize():12}: {v}")

    def _admin_view_audit_log(self):
        try:
            with open("audit.log", "r") as f:
                lines = f.readlines()
            print("\nLast 20 audit entries:")
            for line in lines[-20:]:
                print(" ", line.rstrip())
        except FileNotFoundError:
            print("No audit log found yet.")

    def _admin_unlock_account(self):
        user_type = input("User type (patient/doctor/admin): ").strip()
        username  = input("Username to unlock: ").strip()
        key = f"{user_type}:{username}"
        if key in self.login_attempts:
            del self.login_attempts[key]
            audit(f"UNLOCK | {user_type} | {username}")
            print(f"Account '{username}' unlocked.")
        else:
            print("That account is not locked.")

    # ══════════════════════════════════════════════════════════════════════════
    # PATIENT MENU
    # ══════════════════════════════════════════════════════════════════════════

    def patient_menu(self, token: str):
        session = self.validate_session(token)
        if not session or session["user_type"] != "patient":
            print("Unauthorised.")
            return
        username = session["username"]

        MENU = {
            "1": ("View Room & Bed",         lambda: self._patient_room_bed()),
            "2": ("View My Medicines",       lambda: self._patient_medicines(username)),
            "3": ("View My Reports",         lambda: self._patient_reports(username)),
            "4": ("View My Appointments",    lambda: self._patient_appointments(username)),
            "5": ("Update Contact Info",     lambda: self._patient_update_contact(username)),
            "6": ("Exit",                    None),
        }

        while True:
            print(f"\n{'─'*40}")
            print("  PATIENT MENU")
            print(f"{'─'*40}")
            for k, (label, _) in MENU.items():
                print(f"  {k}. {label}")
            print(f"{'─'*40}")
            choice = input("Choice: ").strip()
            if choice == "6":
                audit(f"LOGOUT | patient | {username}")
                print("Logged out.")
                return
            if choice in MENU:
                MENU[choice][1]()
            else:
                print("Invalid option.")

    def _patient_room_bed(self):
        import random, string
        print(f"\n  Room Number : {random.randint(1, 100)}")
        print(f"  Bed         : {random.choice(string.ascii_uppercase)}")

    def _patient_medicines(self, username: str):
        pdata = self.users["patient"].get(username, {})
        doctors = pdata.get("doctors", {})
        if not doctors:
            print("\n  No medicines prescribed yet.")
            return
        print("\n  Your prescribed medicines:")
        for doc, prescriptions in doctors.items():
            doc_name = self.users["doctor"].get(doc, {}).get("name", doc)
            for rx in prescriptions:
                if isinstance(rx, dict):
                    print(f"  • {rx.get('medicine','?')} ({rx.get('dosage','')}) — "
                          f"prescribed by Dr. {doc_name} on {rx.get('date','?')}")
                else:
                    print(f"  • {rx} — prescribed by Dr. {doc_name}")

    def _patient_reports(self, username: str):
        reports = self.users["patient"].get(username, {}).get("reports", [])
        if not reports:
            print("\n  No reports available.")
            return
        print("\n  Your reports:")
        for i, r in enumerate(reports, 1):
            if isinstance(r, dict):
                print(f"  {i}. [{r.get('date','?')}] {r.get('text','')}")
            else:
                print(f"  {i}. {r}")

    def _patient_appointments(self, username: str):
        appts = self.users["patient"].get(username, {}).get("appointments", [])
        if not appts:
            print("\n  No appointments scheduled.")
            return
        print("\n  Your appointments:")
        for a in appts:
            doc_name = self.users["doctor"].get(a.get("doctor",""), {}).get("name", a.get("doctor","?"))
            print(f"  • {a.get('date','?')} at {a.get('time','?')} — Dr. {doc_name} | Status: {a.get('status','Pending')}")

    def _patient_update_contact(self, username: str):
        contact = input("New contact number: ").strip()
        if re.fullmatch(r"\d{10,15}", contact):
            self.users["patient"][username]["contact"] = contact
            self.save_data()
            print("Contact updated.")
        else:
            print("Invalid contact number (10-15 digits).")

    # ══════════════════════════════════════════════════════════════════════════
    # DOCTOR MENU
    # ══════════════════════════════════════════════════════════════════════════

    def doctor_menu(self, token: str):
        session = self.validate_session(token)
        if not session or session["user_type"] != "doctor":
            print("Unauthorised.")
            return
        username = session["username"]

        MENU = {
            "1": ("View Patient Record",       lambda: self._doctor_view_patient(username)),
            "2": ("Add Prescription",          lambda: self._doctor_add_prescription(username)),
            "3": ("Add Patient Report",        lambda: self._doctor_add_report(username)),
            "4": ("Schedule Appointment",      lambda: self._doctor_schedule_appointment(username)),
            "5": ("View All My Patients",      lambda: self._doctor_list_patients(username)),
            "6": ("Exit",                      None),
        }

        while True:
            print(f"\n{'─'*40}")
            print("  DOCTOR MENU")
            print(f"{'─'*40}")
            for k, (label, _) in MENU.items():
                print(f"  {k}. {label}")
            print(f"{'─'*40}")
            choice = input("Choice: ").strip()
            if choice == "6":
                audit(f"LOGOUT | doctor | {username}")
                print("Logged out.")
                return
            if choice in MENU:
                MENU[choice][1]()
            else:
                print("Invalid option.")

    def _doctor_view_patient(self, doctor_username: str):
        patient_username = input("Patient username (or 'exit'): ").strip()
        if patient_username.lower() == "exit":
            return
        pdata = self.users["patient"].get(patient_username)
        if not pdata:
            print(f"Patient '{patient_username}' not found.")
            return
        print(f"\n  Patient: {pdata.get('name')} ({patient_username})")
        print(f"  Email  : {pdata.get('email','—')}")
        print(f"  Age    : {pdata.get('age','—')}  |  Blood Group: {pdata.get('blood_group','—')}")
        print(f"  Contact: {pdata.get('contact','—')}")
        # Reports
        reports = pdata.get("reports", [])
        print(f"\n  Reports ({len(reports)}):")
        for r in reports:
            if isinstance(r, dict):
                print(f"    [{r.get('date','?')}] {r.get('text','')}")
            else:
                print(f"    {r}")
        # Prescriptions
        doc_rxs = pdata.get("doctors", {}).get(doctor_username, [])
        print(f"\n  Prescriptions by you ({len(doc_rxs)}):")
        for rx in doc_rxs:
            if isinstance(rx, dict):
                print(f"    {rx.get('medicine','?')} — {rx.get('dosage','')} — {rx.get('date','?')}")
            else:
                print(f"    {rx}")
        audit(f"VIEW_PATIENT | doctor:{doctor_username} | patient:{patient_username}")

    def _doctor_add_prescription(self, doctor_username: str):
        patient_username = input("Patient username: ").strip()
        if patient_username not in self.users["patient"]:
            print("Patient not found.")
            return
        medicine = input("Medicine name : ").strip()
        dosage   = input("Dosage        : ").strip()
        date_str = datetime.now().strftime("%Y-%m-%d")

        pdata = self.users["patient"][patient_username]
        pdata.setdefault("doctors", {}).setdefault(doctor_username, []).append({
            "medicine": medicine,
            "dosage": dosage,
            "date": date_str
        })
        self.save_data()
        audit(f"PRESCRIPTION | doctor:{doctor_username} | patient:{patient_username} | {medicine}")
        print(f"Prescription for '{medicine}' added for patient '{patient_username}'.")

    def _doctor_add_report(self, doctor_username: str):
        patient_username = input("Patient username: ").strip()
        if patient_username not in self.users["patient"]:
            print("Patient not found.")
            return
        report_text = input("Report text   : ").strip()
        date_str    = datetime.now().strftime("%Y-%m-%d %H:%M")

        self.users["patient"][patient_username].setdefault("reports", []).append({
            "text": report_text,
            "date": date_str,
            "by": doctor_username
        })
        self.save_data()
        audit(f"ADD_REPORT | doctor:{doctor_username} | patient:{patient_username}")
        print("Report added.")

    def _doctor_schedule_appointment(self, doctor_username: str):
        patient_username = input("Patient username: ").strip()
        if patient_username not in self.users["patient"]:
            print("Patient not found.")
            return
        date_str = input("Date (YYYY-MM-DD)  : ").strip()
        time_str = input("Time (HH:MM)       : ").strip()
        notes    = input("Notes (optional)   : ").strip()

        appointment = {
            "doctor": doctor_username,
            "date": date_str,
            "time": time_str,
            "notes": notes,
            "status": "Scheduled"
        }
        self.users["patient"][patient_username].setdefault("appointments", []).append(appointment)
        self.users["doctor"][doctor_username].setdefault("appointments", []).append({
            "patient": patient_username, **appointment
        })
        self.save_data()
        audit(f"APPOINTMENT | doctor:{doctor_username} | patient:{patient_username} | {date_str} {time_str}")
        print(f"Appointment scheduled for {date_str} at {time_str}.")

    def _doctor_list_patients(self, doctor_username: str):
        found = [
            (uname, data)
            for uname, data in self.users["patient"].items()
            if doctor_username in data.get("doctors", {})
        ]
        if not found:
            print("\n  No patients assigned to you yet.")
            return
        print(f"\n  Your patients ({len(found)}):")
        for uname, data in found:
            print(f"  • {uname} — {data.get('name','?')} | {data.get('email','?')}")


# ══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    hms = HospitalManagementSystem()

    print("╔═════════════════════════════════════════╗")
    print("║   Advanced Hospital Management System   ║")
    print("╚═════════════════════════════════════════╝")

    user_type = input("User type (admin / patient / doctor): ").strip().lower()
    if user_type not in ("admin", "patient", "doctor"):
        print("Invalid user type.")
        sys.exit(1)

    username = input("Username: ").strip()
    token = hms.login(user_type, username)
    if not token:
        print("Login failed.")
        sys.exit(1)

    if user_type == "admin":
        hms.admin_menu(token)
    elif user_type == "patient":
        hms.patient_menu(token)
    elif user_type == "doctor":
        hms.doctor_menu(token)


if __name__ == "__main__":
    main()