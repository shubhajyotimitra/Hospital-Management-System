# 🏥 Advanced Hospital Management System (Python)

A secure, console-based management system designed for healthcare providers. This system manages three distinct user roles (**Admin**, **Doctor**, and **Patient**) with a heavy emphasis on data security and session integrity.

## ✨ Key Features

### 🛡️ Security First
* **Robust Password Hashing:** Implements `bcrypt` with configurable work factors and unique salts per user. Includes a SHA-256 fallback for compatibility.
* **Session Management:** Uses `UUID4` session tokens with a 30-minute sliding expiry window.
* **Brute-Force Protection:** Automatic account lockout after 5 failed login attempts.
* **Audit Trail:** Every critical action (logins, deletions, prescriptions) is timestamped and recorded in `audit.log`.

### 👥 Multi-Role Functionality
* **Admins:** Manage the user database, unlock accounts, and monitor the system audit logs.
* **Doctors:** Manage patient records, prescribe medications, and schedule appointments.
* **Patients:** View personal health reports, upcoming appointments, and room/bed assignments.

## 🛠️ Tech Stack
* **Language:** Python 3.10+
* **Data Storage:** JSON (File-based persistence)
* **Encryption:** `bcrypt`, `hashlib`
* **Core Modules:** `json`, `uuid`, `re`, `logging`, `datetime`

## 🚀 Getting Started

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/shubhajyotimitra/Hospital-Management-System.git](https://github.com/shubhajyotimitra/Hospital-Management-System.git)

2. **Install Dependencies:**
   pip install bcrypt

3. **Run the Application:**
   python Hospital_Management_System.py

### ✅ Input Validation
The system strictly validates:
* **Emails:** Standard regex verification.
* **Usernames:** Alphanumeric, 3-30 characters.
* **Passwords:** Requires uppercase, digits, and special characters.  