# blockchain.py
import time
import json
import hashlib
from dataclasses import dataclass, asdict
from typing import List, Tuple, Any
from config import LEDGER_FILE
import os
import shutil
from collections import Counter

# Backup paths for 51% consensus recovery
BACKUP_PATHS = [
    os.path.join("data", "backup1", "ledger.json"),
    os.path.join("data", "backup2", "ledger.json"),
    os.path.join("data", "backup3", "ledger.json"),
]

@dataclass
class Block:
    index: int
    timestamp: float
    student_mask: str
    
    # NEW: ElGamal Ciphertext. List of (c1, c2) tuples
    encrypted_answers: List[Tuple[int, int]] 
    
    # NEW: Lamport Signature Data
    # We store the Public Key (the "lock") so anyone can verify the signature later
    lamport_public_key: List[str] 
    # We store the Signature (the "keys" revealed by the student)
    lamport_signature: List[str]
    
    previous_hash: str
    nonce: int = 0
    hash: str = ""

    def compute_hash(self) -> str:
        # We must hash ALL critical data to ensure integrity
        block_string = (
            f"{self.index}{self.timestamp}{self.student_mask}"
            f"{str(self.encrypted_answers)}"  # Stringify the list of tuples
            f"{str(self.lamport_public_key)}"
            f"{str(self.lamport_signature)}"
            f"{self.previous_hash}{self.nonce}"
        )
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine(self, difficulty: int = 2):
        prefix = '0' * difficulty
        self.nonce = 0
        while True:
            self.hash = self.compute_hash()
            if self.hash.startswith(prefix):
                return
            self.nonce += 1

class Blockchain:
    def __init__(self, difficulty: int = 2):
        self.chain = []
        self.difficulty = difficulty
        self.load_chain()

    def create_genesis_block(self):
        genesis = Block(0, time.time(), "GENESIS", [], [], [], "0", 0, "")
        genesis.hash = genesis.compute_hash()
        self.chain.append(genesis)

    def add_block(self, student_mask: str, encrypted_answers: List[Tuple[int, int]], 
                  lamport_pk: List[str], lamport_sig: List[str]):
        last = self.chain[-1]
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            student_mask=student_mask,
            encrypted_answers=encrypted_answers,
            lamport_public_key=lamport_pk,
            lamport_signature=lamport_sig,
            previous_hash=last.hash
        )
        new_block.mine(self.difficulty)
        self.chain.append(new_block)
        self.save_chain()
        self.save_to_backups()  # Create backups for 51% consensus
        return new_block

    def get_block_by_index(self, index):
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None

    def save_chain(self):
        with open(LEDGER_FILE, 'w') as f:
            # Helper to convert object to dict, handling tuples
            json.dump([asdict(b) for b in self.chain], f, indent=2)

    def load_chain(self):
        if not os.path.exists(LEDGER_FILE):
            self.create_genesis_block()
            return
        try:
            with open(LEDGER_FILE, 'r') as f:
                data = json.load(f)
                # Reconstruct Block objects from JSON data
                self.chain = []
                for b in data:
                    # JSON loads tuples as lists, we might need to convert them back if strict
                    # For this simulation, list of lists is fine, but let's be safe
                    enc_ans = [tuple(pair) for pair in b['encrypted_answers']]
                    blk = Block(
                        index=b['index'],
                        timestamp=b['timestamp'],
                        student_mask=b['student_mask'],
                        encrypted_answers=enc_ans,
                        lamport_public_key=b['lamport_public_key'],
                        lamport_signature=b['lamport_signature'],
                        previous_hash=b['previous_hash'],
                        nonce=b['nonce'],
                        hash=b['hash']
                    )
                    self.chain.append(blk)
        except Exception as e:
            print(f"[Error] Corrupt ledger: {e}. Starting fresh.")
            self.create_genesis_block()

    def sever_from(self, index):
        """Remove corrupted blocks from the chain."""
        self.chain = self.chain[:index]
        self.save_chain()
        print(f"[Sever] Chain severed at Block {index}. Corrupted blocks removed.")

    def save_to_backups(self):
        """
        Save current chain to all backup locations.
        Called after every successful block addition.
        """
        for backup_path in BACKUP_PATHS:
            try:
                os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                shutil.copy(LEDGER_FILE, backup_path)
            except Exception as e:
                print(f"[Backup] Warning: Could not save to {backup_path}: {e}")
        print(f"[Backup] Chain saved to {len(BACKUP_PATHS)} backup locations.")

    def verify_chain_integrity(self, chain_data):
        """
        Verify if a loaded chain is internally consistent.
        Returns (is_valid, corruption_index)
        """
        if not chain_data or len(chain_data) == 0:
            return False, 0
        
        for i in range(1, len(chain_data)):
            prev = chain_data[i-1]
            curr = chain_data[i]
            
            # Check link
            if curr.get('previous_hash') != prev.get('hash'):
                return False, i
            
            # Reconstruct and verify hash
            enc_ans = [tuple(pair) for pair in curr['encrypted_answers']]
            temp_block = Block(
                index=curr['index'],
                timestamp=curr['timestamp'],
                student_mask=curr['student_mask'],
                encrypted_answers=enc_ans,
                lamport_public_key=curr['lamport_public_key'],
                lamport_signature=curr['lamport_signature'],
                previous_hash=curr['previous_hash'],
                nonce=curr['nonce'],
                hash=curr['hash']
            )
            if temp_block.compute_hash() != curr['hash']:
                return False, i
        
        return True, -1

    def recover_from_majority(self):
        """
        51% CONSENSUS RECOVERY
        
        1. Load all backup chains
        2. Verify each chain's integrity
        3. Find the chain that majority of backups agree on
        4. If majority is valid, restore from it
        
        Returns: True if recovery successful, False otherwise
        """
        print("\n" + "="*50)
        print("   51% CONSENSUS RECOVERY PROTOCOL")
        print("="*50)
        
        valid_chains = []
        
        # Step 1: Collect all valid backup chains
        print("\n[Step 1] Querying backup nodes...")
        for i, backup_path in enumerate(BACKUP_PATHS, 1):
            if os.path.exists(backup_path):
                try:
                    with open(backup_path, 'r') as f:
                        backup_data = json.load(f)
                    
                    # Verify this backup's integrity
                    is_valid, corrupt_idx = self.verify_chain_integrity(backup_data)
                    
                    if is_valid and backup_data:
                        # Use hash of last block as chain identifier
                        chain_id = backup_data[-1].get('hash', '')
                        chain_length = len(backup_data)
                        valid_chains.append({
                            'id': chain_id,
                            'path': backup_path,
                            'data': backup_data,
                            'length': chain_length
                        })
                        print(f"   Backup {i}: ✓ Valid ({chain_length} blocks)")
                    else:
                        print(f"   Backup {i}: ✗ Corrupted at block {corrupt_idx}")
                except Exception as e:
                    print(f"   Backup {i}: ✗ Error reading: {e}")
            else:
                print(f"   Backup {i}: ✗ Not found")
        
        if not valid_chains:
            print("\n[FAILED] No valid backups found. Cannot recover.")
            print("         Manual intervention required!")
            return False
        
        # Step 2: Count which chain version appears most often
        print(f"\n[Step 2] Counting votes from {len(valid_chains)} valid backups...")
        
        chain_counts = Counter([c['id'] for c in valid_chains])
        most_common_hash, count = chain_counts.most_common(1)[0]
        
        total_nodes = len(BACKUP_PATHS)
        percentage = (count / total_nodes) * 100
        
        print(f"         Most common chain: {most_common_hash[:16]}...")
        print(f"         Agreement: {count}/{total_nodes} nodes ({percentage:.1f}%)")
        
        # Step 3: Check if we have 51% consensus
        consensus_threshold = total_nodes / 2  # More than 50%
        
        if count > consensus_threshold:
            print(f"\n[Step 3] ✓ 51% CONSENSUS REACHED!")
            
            # Find and restore the majority chain
            for chain_info in valid_chains:
                if chain_info['id'] == most_common_hash:
                    print(f"         Restoring from: {chain_info['path']}")
                    print(f"         Chain length: {chain_info['length']} blocks")
                    
                    # Write to main ledger
                    with open(LEDGER_FILE, 'w') as f:
                        json.dump(chain_info['data'], f, indent=2)
                    
                    # Reload the chain into memory
                    self.load_chain()
                    
                    print("\n[SUCCESS] Blockchain restored via 51% consensus!")
                    print("="*50)
                    return True
        else:
            print(f"\n[Step 3] ✗ NO CONSENSUS - Only {percentage:.1f}% agreement")
            print("         Need >50% for recovery")
            print("         Manual intervention required!")
            return False
        
        return False