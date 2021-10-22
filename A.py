import socket
import pyaes
import time

portKM = 12345
portB = 12346
km = socket.socket()
b = socket.socket()

kprime = b'\xf5\xe8Ya\x8b$\x18\xaf\xce\x91\xcd\xa9.\x9ba\xde'
iv = "InitializationVe"

# conexiunea intre A si KM
km.connect(('127.0.0.1', portKM))
# primeste cheia criptata de la KM
encrypted_key = km.recv(1024)
km.close()

# decripteaza cheia K folosing K'
aes = pyaes.AES(kprime)
decrypted_k = bytes(aes.decrypt(list(encrypted_key)))

# conexiunea intre A si B
b.connect(('127.0.0.1', portB))

# modul de operare
enc_type = input("ECB sau CBC\n")

# trimite modul de operare la B
b.send(bytes(enc_type, 'utf-8'))
time.sleep(1)
# trimite cheia la B
b.send(bytes(encrypted_key))

# primeste mesajul sa inceapa comunicarea
print(b.recv(1024).decode())

# deschide fisierul cu textul
file = open("plaintext.txt", "r")
text = file.read()

info = [text[i:i+16] for i in range(0, len(text), 16)]
print(info)

if enc_type == "ECB":
    ecb = pyaes.AESModeOfOperationECB(decrypted_k)
    for plaintext in info:
        # completeaza textul in cazul in care nu are lungimea potrivita
        if len(plaintext) < 16:
            plaintext = plaintext.ljust(16)
        ciphertext = ecb.encrypt(plaintext)
        b.send(ciphertext)
    b.send('done'.encode())
elif enc_type == "CBC":
    cbc = pyaes.AESModeOfOperationCBC(decrypted_k, iv)
    for plaintext in info:
        if len(plaintext) < 16:
            plaintext = plaintext.ljust(16)
        ciphertext = cbc.encrypt(plaintext)
        b.send(ciphertext)
    b.send('done'.encode())

b.close()
