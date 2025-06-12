from pwn import *
from warnings import filterwarnings
filterwarnings("ignore")
context.log_level = 'critical'
connection = remote('ipinfo.io', 80)
connection.send(f'GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\nConnection: close \r\n\r\n')
print(connection.recvall().decode().split('\r\n')[-1])
connection.close()