📓 Project Development Logbook
This log documents the technical evolution, security implementations, and architectural decisions for the Hospital Management System.

🛠 Phase 1: Core Architecture & Security

Date: March 28, 2026

Implemented: Developed the primary HospitalManagementSystem class to handle data persistence via JSON.

Security Milestone: Integrated bcrypt for salted password hashing (Work Factor: 12) to ensure industry-standard protection.

Auth System: Built a multi-role login system for Admins, Doctors, and Patients.

Data Integrity: Added regex-based input validation for emails, usernames, and complex password requirements.

🔐 Phase 2: Session & Audit Management

Date: March 28, 2026

Feature: Implemented Session Tokens using uuid4 with a 30-minute sliding expiry window to prevent session hijacking.

Security Feature: Added an Account Lockout mechanism that triggers after 5 failed login attempts.

Observability: Created an automated audit() function that logs all critical actions (prescriptions, deletions, logins) to audit.log.

👨‍⚕️ Phase 3: Role-Based Functional Logic

Date: March 28, 2026

Doctor Module: Developed logic for doctors to view assigned patients, add medical reports, and prescribe medications.

Patient Module: Enabled patients to view personal reports, check room/bed assignments, and track appointments.

Admin Module: Built tools for user management, account unlocking, and hospital list viewing.

🚀 Planned Future Enhancements

[ ] Database Migration: Transition from JSON file storage to SQLite or PostgreSQL for better concurrency.

[ ] GUI Upgrade: Implement a graphical interface using Tkinter or CustomTkinter.

[ ] Email Alerts: Integrate an SMTP server to send appointment reminders to patients.