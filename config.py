
import os
import csv
import random


DATA_DIR = "data"
CERTS_DIR = os.path.join(DATA_DIR, "certs")
LEDGER_FILE = os.path.join(DATA_DIR, "ledger.json")
STUDENTS_FILE = os.path.join(DATA_DIR, "students.json")
QUESTIONS_FILE = os.path.join(DATA_DIR, "exam_db.csv")  # CSV with id,question,answer

# Ensure directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CERTS_DIR, exist_ok=True)

NUM_QUESTIONS_PER_EXAM = 5  # How many random questions to pick


def _load_exam_bank():
    """Load the full exam bank from CSV; returns list of (question, answer)."""
    bank = []
    if os.path.exists(QUESTIONS_FILE):
        try:
            with open(QUESTIONS_FILE, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    q = row.get("question")
                    a = row.get("answer")
                    if q and a:
                        bank.append((q, a))
        except Exception:
            bank = []

    if not bank:
        bank = [
            ("What is the capital of France?", "Paris"),
            ("What is 2 + 2?", "4"),
            ("Which language is this project written in?", "Python"),
            ("What planet is known as the Red Planet?", "Mars"),
            ("Who wrote 'Hamlet'?", "Shakespeare"),
        ]
    return bank


# Prepare a randomized exam selection and answer key
_BANK = _load_exam_bank()

def generate_random_exam():
    """Generates a random subset of questions and their answer key."""
    # Reload or resample
    sample = _BANK if len(_BANK) <= NUM_QUESTIONS_PER_EXAM else random.sample(_BANK, NUM_QUESTIONS_PER_EXAM)
    
    questions = [q for q, _ in sample]
    answers = {f"Q{i+1}": ans for i, (_, ans) in enumerate(sample)}
    return questions, answers

# Default export for backwards compatibility if needed, though we will mainly use the function
EXAM_QUESTIONS, CORRECT_ANSWERS = generate_random_exam()


# 2048-bit MODP Group (RFC 3526) this is the standart prime number which cryptographers have termed as safe an 
_P_HEX = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
83655D23DCA3AD961C62F356208552BB9ED529077096966D
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9
DE2BCBF6955817183995497CEA956AE515D2261898FA0510
15728E5A8AACAA68FFFFFFFFFFFFFFFF
"""

DH_PRIME_P = int(_P_HEX.replace("\n", ""), 16)
DH_GENERATOR_G = 2

# Network Configuration
SERVER_HOST = 'localhost'
SERVER_PORT = 5001

# Exam Settings
EXAM_TIMEOUT_SECONDS = 60  # 1 minute to complete exam
