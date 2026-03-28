# main.py
import json
import time
import hashlib
import os
import socket
import threading
import sys
from getpass import getpass

# --- Configuration & Utils ---
from config import EXAM_QUESTIONS, CORRECT_ANSWERS, DH_PRIME_P, DH_GENERATOR_G, SERVER_HOST, SERVER_PORT, generate_random_exam, EXAM_TIMEOUT_SECONDS
from utils import aes_encrypt, aes_decrypt, mask_student_id
from blockchain import Blockchain
from auth import StudentManager

# --- The Custom Cryptography Protocols ---
from protocols import DiffieHellman, CustomElGamal, CustomRSA, LamportSignature


blockchain = Blockchain(difficulty=2)
auth = StudentManager()


INSTRUCTOR_KEYS_FILE = os.path.join("data", "instructor_keys.json")

print(">> [System] Loading Instructor Keys...")
if os.path.exists(INSTRUCTOR_KEYS_FILE):
    try:
        with open(INSTRUCTOR_KEYS_FILE, 'r') as f:
            keys_data = json.load(f)
        
        # Load ElGamal
        elgamal_data = keys_data['elgamal']
        instructor_elgamal = CustomElGamal.from_keys(elgamal_data['public'], elgamal_data['private'])
        INSTRUCTOR_ELGAMAL_PUB = instructor_elgamal.public_key()
        
        # Load RSA
        rsa_data = keys_data['rsa']
        instructor_rsa = CustomRSA(rsa_data['n'], rsa_data['A'], rsa_data['a'])
        INSTRUCTOR_RSA_PUB = instructor_rsa.export_public()
        print(">> [System] Keys Loaded from disk.")
    except Exception as e:
        print(f">> [System] Error loading keys ({e}). Regenerating...")
        os.remove(INSTRUCTOR_KEYS_FILE)
        # Fallthrough to generation
        keys_data = None
else:
    keys_data = None

if not keys_data:
    print(">> [System] Generating NEW Instructor Keys (This takes a moment)...")
    # ElGamal
    instructor_elgamal = CustomElGamal(DH_PRIME_P, DH_GENERATOR_G)
    INSTRUCTOR_ELGAMAL_PUB = instructor_elgamal.public_key()
    
    #  RSA
    instructor_rsa = CustomRSA.generate_keys(bits=1024)
    INSTRUCTOR_RSA_PUB = instructor_rsa.export_public()
    
    # Save
    keys_dump = {
        'elgamal': {
            'public': instructor_elgamal.public_key(),
            'private': instructor_elgamal.private_key()
        },
        'rsa': instructor_rsa.export_private()
    }
    with open(INSTRUCTOR_KEYS_FILE, 'w') as f:
        json.dump(keys_dump, f, indent=2)
    print(">> [System] New Keys Generated and Saved.")

print(">> [System] Keys Ready.\n")


#              SERVER LOGIC

def handle_client_connection(client_socket, addr):
    """
    Handles a single student connection:
    1. Receive Student ID.
    2. Perform DH Key Exchange.
    3. Send Encrypted Exam.
    4. Wait for completion signal.
    """
    sid = "Unknown"
    try:
        
        f_stream = client_socket.makefile('rwb', buffering=0)

        # handshake: ID
        line = f_stream.readline()
        if not line: return
        msg = json.loads(line.decode().strip())
        sid = msg.get("student_id", "Unknown")
        print(f"\n[Server] >> User '{sid}' has JOINED the connection from {addr}.", flush=True)

        
        server_dh = DiffieHellman(DH_PRIME_P, DH_GENERATOR_G)
        
        # Send Public Key
        msg_out = json.dumps({"action": "KEY_EXCHANGE", "public_key": server_dh.public})
        f_stream.write(msg_out.encode() + b"\n")
        
        # Receive Client Public Key
        line = f_stream.readline()
        if not line: return
        msg_in = json.loads(line.decode().strip())
        client_pub = msg_in.get("public_key")
        
        # Compute Shared Secret
        shared_secret = server_dh.compute_shared(client_pub)
        session_key = hashlib.sha256(str(shared_secret).encode()).digest()
        print(f"[Server] DEBUG: Shared secret computed. Encrypting exam...", flush=True)

        # 3. Send Encrypted Exam
        try:
            # Generate unique exam for this session
            questions_list, answer_key = generate_random_exam()
            
            
            auth.save_exam_key(sid, answer_key)
            print(f"[Server] >> Assigned unique exam to '{sid}'. Key saved.")
            
            questions_json = json.dumps(questions_list)

            encrypted_exam = aes_encrypt(questions_json, session_key)
            print(f"[Server] DEBUG: Encryption successful ({len(encrypted_exam)} bytes). Sending...", flush=True)
        except Exception as e:
            print(f"[Server] FATAL ERROR during encryption: {e}", flush=True)
            raise e
        
        response = json.dumps({
            "action": "EXAM_DATA", 
            "payload": encrypted_exam.hex(),
            "timeout_seconds": EXAM_TIMEOUT_SECONDS
        })
        f_stream.write(response.encode() + b"\n")
        print(f"[Server] >> Sent exam to '{sid}'. Timeout: {EXAM_TIMEOUT_SECONDS}s. Waiting...", flush=True)

        # Set socket timeout - auto disconnect if student takes too long
        client_socket.settimeout(EXAM_TIMEOUT_SECONDS)

        # 4. Wait for Completion
        try:
            while True:
                line = f_stream.readline()
                if not line: 
                    break 
                msg = json.loads(line.decode().strip())
                if msg.get("action") == "FINISHED":
                    print(f"[Server] >> User '{sid}' has COMPLETED the exam.", flush=True)
                    break
        except socket.timeout:
            print(f"[Server] >> TIMEOUT: User '{sid}' exceeded time limit. Disconnecting.", flush=True)
                
    except Exception as e:
        print(f"[Server] Error with {sid}: {e}", flush=True)
    finally:
        client_socket.close()

def start_server_mode():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((SERVER_HOST, SERVER_PORT))
        server.listen(5)
        print("==============================")
        print(f"   EXAM SERVER RUNNING       ")
        print(f"   Host: {SERVER_HOST} Port: {SERVER_PORT}")
        print("==============================")
        print("[Server] Waiting for students...", flush=True)
        
        while True:
            client, addr = server.accept()
            thread = threading.Thread(target=handle_client_connection, args=(client, addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down...")
    finally:
        server.close()


#              CLIENT LOGIC

def student_menu():
    while True:
        print("\n--- Student Menu ---")
        print("1. Register (Issue Cert)")
        print("2. Login & Take Exam (Online)")
        print("3. View My Grades")
        print("4. Back")
        choice = input("Choice: ")

        if choice == '1':
            sid = input("Enter Student ID: ").strip()
            pwd = getpass("Enter Password: ")
            pwd_confirm = getpass("Confirm Password: ")
            
            if pwd != pwd_confirm:
                print(" Error: Passwords do not match.")
                continue
                
            try:
                key_path, cert_path = auth.register(sid, pwd)
                print(f" Registration Successful!")
                print(f"   Identity Key: {key_path}")
                print(f"   Certificate : {cert_path}")
            except ValueError as e:
                print(f" Error: {e}")

        elif choice == '2':
            sid = input("Student ID: ").strip()
            pwd = getpass("Password: ")
            
            # --- TWO-FACTOR AUTHENTICATION ---
            print(f"\n>> [Auth] Verifying credentials for {sid}...")
            if not auth.authenticate(sid, pwd):
                print("   Authentication Failed: Invalid ID, password, or certificate.")
                continue

            print(">> [Auth] Two-Factor Authentication Passed.")
            
            data = auth.get_student_data(sid)
            if data['has_submitted']:
                print("  You have already submitted this exam.")
                continue
            
            # : CONNECT TO SERVER & HANDSHAKE ---
            print(f"\n>> [Network] Connecting to Server at {SERVER_HOST}:{SERVER_PORT}...")
            
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client_sock.connect((SERVER_HOST, SERVER_PORT))
                
                f_stream = client_sock.makefile('rwb', buffering=0)

                
                f_stream.write(json.dumps({"student_id": sid}).encode() + b"\n")

                
                line = f_stream.readline()
                if not line:
                    print("Error: Server closed connection.")
                    client_sock.close()
                    continue
                msg_in = json.loads(line.decode().strip())
                server_pub = msg_in.get("public_key")

               
                client_dh = DiffieHellman(DH_PRIME_P, DH_GENERATOR_G)
                msg_out = json.dumps({"public_key": client_dh.public})
                f_stream.write(msg_out.encode() + b"\n")

                
                shared_secret = client_dh.compute_shared(server_pub)
                session_key = hashlib.sha256(str(shared_secret).encode()).digest()
                print(f">> [Handshake] Secure Session Established (Key: {str(shared_secret)[:8]}...)")

                
                line = f_stream.readline()
                if not line:
                    print("Error: Failed to receive exam.")
                    client_sock.close()
                    continue
                msg_in = json.loads(line.decode().strip())
                encrypted_hex = msg_in.get("payload")
                timeout_secs = msg_in.get("timeout_seconds", 60)
                
               
                encrypted_bytes = bytes.fromhex(encrypted_hex)
                decrypted_exam_json = aes_decrypt(encrypted_bytes, session_key)
                exam_questions = json.loads(decrypted_exam_json)
                print(">> [Download] Exam Questions Decrypted successfully.")
                print(f">> [Timer] You have {timeout_secs} seconds to complete the exam!")

                # Start background timer
                def timeout_handler():
                    print("\n\n!! TIME'S UP! Exam session expired. !!")
                    print(">> You have been disconnected.")
                    try:
                        client_sock.close()
                    except:
                        pass
                    os._exit(1)  # Force exit
                
                exam_timer = threading.Timer(timeout_secs, timeout_handler)
                exam_timer.daemon = True
                exam_timer.start()

                answers = []
                print("\n--- EXAM START ---")
                for q in exam_questions:

                    ans = input(f"{q}\nAnswer: ").strip()
                    
                    ans_int = int.from_bytes(ans.encode(), 'big')
                    answers.append(ans_int)
                
                # Cancel timer - exam completed in time
                exam_timer.cancel()
                
                print("\n>> [Submission] Encrypting & Signing...")
                
                
                encrypted_answers = []
                temp_elgamal = CustomElGamal.from_keys(INSTRUCTOR_ELGAMAL_PUB, {})
                for ans_int in answers:
                    enc_pair = temp_elgamal.encrypt_int(ans_int)
                    encrypted_answers.append(enc_pair)
                
               
                print(">> [Crypto] Signing with Lamport Scheme...")
                lamport = LamportSignature()
                priv_key, pub_key = lamport.generate_keys()
                payload_str = str(encrypted_answers)
                signature = lamport.sign(payload_str.encode(), priv_key)
                
                
                mask = mask_student_id(sid)
                new_block = blockchain.add_block(
                    student_mask=mask,
                    encrypted_answers=encrypted_answers,
                    lamport_pk=pub_key, 
                    lamport_sig=signature
                )
                
                auth.record_submission(sid, new_block.index)
                print(f"  Exam submitted to Blockchain! Block Index: {new_block.index}")
                
                # Notify Server and Exit
                f_stream.write(json.dumps({"action": "FINISHED"}).encode() + b"\n")
                client_sock.close()
                
            except ConnectionRefusedError:
                print(" Error: Could not connect to Server. Is it running?")
            except Exception as e:
                print(f" Error during exam: {e}")
                
        elif choice == '3':
            sid = input("Student ID: ").strip()
            pwd = getpass("Password: ")
            if auth.authenticate(sid, pwd):
                data = auth.get_student_data(sid)
                if data['status'] == "Graded":
                    print(f"\n>> GRADE REPORT")
                    print(f"   Score: {data['grade']}")
                    sig = data.get('rsa_signature')
                    # print(f"   Instructor Signature: {sig[:30] if sig else 'Not Found'}...")
                    print(f"   (Verified by RSA)")
                elif data['status'] == "Submitted":
                    print("\n>> Status: Submitted (Pending Grading)")
                else:
                    print("\n>> Status: No submission found.")
            else:
                print("Authentication failed.")

        elif choice == '4':
            break

def instructor_menu():
    print("\n--- Instructor Panel ---")
    pwd = getpass("Enter Instructor Password: ")
    if pwd != "admin123":
        print("Access Denied.")
        return

    auth.load_data()  # Refresh student data from disk

    while True:
        print("\n1. View/Grade Pending Submissions")
        print("2. Back")
        choice = input("Choice: ")

        if choice == '1':
            all_students = auth.get_all_students()
            pending = [sid for sid, d in all_students.items() if d['status'] == "Submitted"]
            
            if not pending:
                print("No pending submissions.")
                continue
                
            print(f"\nPending Students: {', '.join(pending)}")
            target_id = input("Enter Student ID to grade: ").strip()
            
            student_data = auth.get_student_data(target_id)
            if not student_data or student_data['status'] != "Submitted":
                print("Invalid student or not ready for grading.")
                continue
            
            # --- AUTOMATED GRADING PROCESS ---
            print(f"\n>> Grading {target_id}...")
            
            #
            block_idx = student_data['block_index']
            block = blockchain.get_block_by_index(block_idx)
            
            if not block:
                print("Error: Block not found.")
                continue

            
            print(">> [1/3] Verifying Lamport Signature...")
            verifier = LamportSignature()
            payload_str = str(block.encrypted_answers)
            
            is_valid = verifier.verify(
                payload_str.encode(), 
                block.lamport_signature, 
                block.lamport_public_key
            )
            
            if not is_valid:
                print(" FRAUD DETECTED: Signature verification failed!")
                continue
            print(" Signature Valid. Student identity confirmed.")
            
          
            print(">> [2/3] Decrypting Answers with ElGamal Private Key...")
            decrypted_answers = []
            try:
                for c1, c2 in block.encrypted_answers:
                    # Decrypt using the Instructor's private instance
                    val = instructor_elgamal.decrypt_int(c1, c2)
                    decrypted_answers.append(val)
            except Exception as e:
                print(f"Decryption failed: {e}")
                continue
                
           
            print(f">> [Grading] Decryption successful. Scoring answers...")
            
            # Retrieve the specific answer key for this student
            student_key = student_data.get('exam_key', {})
            if not student_key:
                print("Warning: No specific exam key found. Using global default (might be wrong).")
                student_key = CORRECT_ANSWERS
            
            score = 0
            for idx, val in enumerate(decrypted_answers, start=1):
                # Reconstruct text answer from integer
                byte_len = max(1, (val.bit_length() + 7) // 8)
                try:
                    ans_text = val.to_bytes(byte_len, "big").decode("utf-8").strip()
                except Exception:
                    ans_text = ""
                
                correct = student_key.get(f"Q{idx}", "").strip()
                
                # DEBUG: Show comparison
                match = ans_text.lower() == correct.lower()
                print(f"   Q{idx}: Student='{ans_text}' | Correct='{correct}' | Match={match}")
                
                if match:
                    score += 1
            
          
            print(">> [3/3] Signing Grade with RSA Private Key...")
            grade_payload = f"Student:{target_id}|Grade:{score}"
            
            # Sign the string
            signature_int = instructor_rsa.sign(grade_payload)
            signature_hex = hex(signature_int)[2:] # Convert to hex for storage
            
           
            auth.update_grade(target_id, score)
            # Save the RSA signature to the student's data in the auth database
            auth.students_db[target_id]['rsa_signature'] = signature_hex
            auth.save_data()
            
            print(f"  Graded Successfully! Score: {score}")
            print(f"   RSA Signature stored: {signature_hex[:20]}...")

        elif choice == '2':
            break

def auditor_menu():
    print("\n--- Auditor View ---")
    print("Verifying Blockchain Integrity...")
    
    valid = True
    corruption_index = None
    
    for i in range(1, len(blockchain.chain)):
        prev = blockchain.chain[i-1]
        curr = blockchain.chain[i]
        
        if curr.previous_hash != prev.hash:
            valid = False
            corruption_index = i
            print(f"\n[!] Broken link detected at Block {i}")
            break
            
        if curr.compute_hash() != curr.hash:
            valid = False
            corruption_index = i
            print(f"\n[!] Hash mismatch detected at Block {i}")
            break
    
    if valid:
        print("[Integrity Check: PASSED] - The Ledger is clean.")
    else:
        print("[Integrity Check: FAILED] - Tampering detected!")
        
        # Attempt 51% Consensus Recovery
        print("\nAttempting 51% Consensus Recovery...")
        
        if blockchain.recover_from_majority():
            print("\n[✓] Chain successfully recovered from backup consensus!")
        else:
            # Recovery failed - ask user what to do
            print("\n[!] Automatic recovery failed.")
            choice = input("Sever corrupted blocks? (y/n): ").strip().lower()
            if choice == 'y':
                blockchain.sever_from(corruption_index)
                print(f"[!] Blocks from index {corruption_index} onwards have been removed.")
            else:
                print("[!] No action taken. Chain remains corrupted.")

    input("\nPress Enter to return...")

def main():
    while True:
        print("\n==============================")
        print("   SECURE EXAM SYSTEM     ")
        print("==============================")
        print("1. Student")
        print("2. Instructor (Admin/Grade)")
        print("3. Auditor")
        print("4. START EXAM SERVER (Host)")
        print("5. Exit")
        
        role = input("Select Option (1-5): ")
        
        if role == '1':
            student_menu()
        elif role == '2':
            instructor_menu()
        elif role == '3':
            auditor_menu()
        elif role == '4':
            start_server_mode()
        elif role == '5':
            print("Exiting...")
            break
        else:
            print("Invalid selection.")

if __name__ == "__main__":
    main()
