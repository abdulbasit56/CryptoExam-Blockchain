
import socket
import threading
import time
import sys

HOST = 'localhost'
PORT = 9999

def server_func():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    print("Server listening...")
    conn, addr = s.accept()
    print(f"Server accepted {addr}")
    
    f = conn.makefile('rw', buffering=1, encoding='utf-8')
    f.write("HELLO\n")
    f.flush()
    print("Server sent HELLO. Waiting for response...")
    
    # Simulate waiting provided by the main script
    try:
        line = f.readline()
        print(f"Server read: {line}")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        conn.close()
        s.close()

def client_func():
    time.sleep(1)
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        c.connect((HOST, PORT))
        f = c.makefile('rw', buffering=1, encoding='utf-8')
        
        line = f.readline()
        print(f"Client received: {line.strip()}")
        
        print("Client sleeping (simulating exam)...")
        time.sleep(3) # Initial sleep
        
        # Write response
        f.write("FINISHED\n")
        f.flush()
        print("Client sent FINISHED")
        
    except Exception as e:
        print(f"Client error: {e}")
    finally:
        c.close()

t = threading.Thread(target=server_func)
t.start()
client_func()
t.join()
