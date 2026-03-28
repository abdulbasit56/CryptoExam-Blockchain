# auth.py
import json
import os
import threading
import hashlib
from config import STUDENTS_FILE
from pki_handler import PKIHandler


class StudentManager:
    def __init__(self):
        self.students_db = {}
        # Initialize PKI (creates Root CA if missing)
        self.pki = PKIHandler()
        self.load_data()
        self.lock = threading.Lock()

    def register(self, student_id, password):
        """
        Registration Flow:
        1. Check if ID exists.
        2. Hash the password.
        3. Issue a Digital Certificate (PKI).
        4. Store password hash and cert path.
        """
        self.load_data()
        if student_id in self.students_db:
            raise ValueError("ID already exists.")

        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Issue Cert via PKI
        key_path, cert_path = self.pki.issue_certificate(student_id)

        self.students_db[student_id] = {
            'password_hash': password_hash,
            'cert_path': cert_path,
            'key_path': key_path,
            'has_submitted': False,
            'block_index': None,
            'grade': None,
            'status': "Registered"
        }
        self.save_data()
        return key_path, cert_path

    def authenticate(self, student_id, password):
        """
        Two-Factor Authentication:
        1. Verify password hash.
        2. Verify certificate validity.
        """
        self.load_data()
        
        user = self.students_db.get(student_id)
        if not user:
            return False

        # Verify password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if user.get('password_hash') != password_hash:
            return False

        # Verify certificate
        cert_path = user.get('cert_path')
        if not cert_path:
            return False

        return self.pki.verify_certificate(cert_path)

    def record_submission(self, student_id, block_index):

        self.load_data()
        
        if student_id in self.students_db:
            self.students_db[student_id]['has_submitted'] = True
            self.students_db[student_id]['block_index'] = block_index
            self.students_db[student_id]['status'] = "Submitted"
            self.save_data()

    def update_grade(self, student_id, score):
        self.load_data()  # Ensure we have latest data
        if student_id in self.students_db:
            self.students_db[student_id]['grade'] = score
            self.students_db[student_id]['status'] = "Graded"
            self.save_data()

    def save_exam_key(self, student_id, answer_key):
        """
        Stores the correct answer key for a specific student's exam.
        This method is now thread-safe.
        """
        with self.lock:
            # Reload DB to see students who registered after the server started.
            self.load_data()
            
            if student_id in self.students_db:
                self.students_db[student_id]['exam_key'] = answer_key
                self.save_data()
                print(f"[Auth] Saved exam key for {student_id} to disk.")
            else:
                print(f"[Auth] ERROR: Could not save key. Student {student_id} not found in DB.")

    def get_student_data(self, student_id):
        self.load_data() # Ensure fresh data
        return self.students_db.get(student_id)

    def get_all_students(self):
        self.load_data() # Ensure fresh data
        return self.students_db

    def save_data(self):
        with open(STUDENTS_FILE, 'w') as f:
            json.dump(self.students_db, f, indent=2)

    def load_data(self):
        if os.path.exists(STUDENTS_FILE):
            try:
                with open(STUDENTS_FILE, 'r') as f:
                    self.students_db = json.load(f)
            except:
                self.students_db = {}
