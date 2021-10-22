import socket
import os
import pyaes

port = 12345
s = socket.socket()
s.bind(('', port))
s.listen(5)

# genereaza o cheie random de 128 de biti
k = os.urandom(16)

kprime = b'\xf5\xe8Ya\x8b$\x18\xaf\xce\x91\xcd\xa9.\x9ba\xde'

aes = pyaes.AES(kprime)
encrypted_key = aes.encrypt(k)

print(bytes(encrypted_key))

while True:
    c, addr = s.accept()
    c.send(bytes(encrypted_key))
    print('Cheia criptata a fost trimisa')
    c.close()
