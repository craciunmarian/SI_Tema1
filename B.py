import socket
import pyaes

port = 12346
encoding = 'utf-8'
s = socket.socket()
s.bind(('', port))
s.listen(5)

kprime = b'\xf5\xe8Ya\x8b$\x18\xaf\xce\x91\xcd\xa9.\x9ba\xde'
iv = "InitializationVe"

while True:
    c, addr = s.accept()

    # Primeste modul de operare de la A
    enc_type = c.recv(1024).decode()
    print("Modul de operare: %s" % enc_type)

    # primeste cheia criptata de la A si o decripteaza
    encrypted_key = c.recv(1024)
    # decripteaza cheia K folosing K'
    aes = pyaes.AES(kprime)
    decrypted_k = bytes(aes.decrypt(list(encrypted_key)))

    c.send('Incepe comunicarea'.encode())

    ecb = pyaes.AESModeOfOperationECB(decrypted_k)
    cbc = pyaes.AESModeOfOperationCBC(decrypted_k, iv)

    text = ""

    while True:
        msg = c.recv(16)
        if msg == b'done' or msg == b' ':
            break
        if enc_type == "ECB":
            text += ecb.decrypt(msg).decode()
        elif enc_type == "CBC":
            text += cbc.decrypt(msg).decode()
        else:
            print("Invalid")
            break

    # afiseaza textul decriptat
    print(text)
    c.close()
