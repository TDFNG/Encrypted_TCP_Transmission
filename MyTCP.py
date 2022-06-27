import secrets
import socket
from threading import Thread
from time import sleep

import MyAES
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat


class Client:
    def __init__(self, port: int, ip: str):
        while 1:
            try:
                self.con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.con.settimeout(5)
                self.con.connect((ip, port))
                priv_k = ec.generate_private_key(ec.BrainpoolP512R1(), None)
                nonce_c = secrets.token_bytes(8)
                self.con.sendall(
                    nonce_c + priv_k.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
                spk = self.con.recv(276)
                self.con.settimeout(None)
                self.aes_k = HKDF(
                    algorithm=ec.hashes.SHA3_512(),
                    length=64,
                    salt=spk[:8],
                    info=nonce_c,
                ).derive(priv_k.exchange(ec.ECDH(), load_pem_public_key(spk[8:])))
                self.conl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.conl.connect((ip, port))
                self.conl.settimeout(5)
                Thread(target=self.check).start()
                break
            except:
                self.close()

    def send(self, data: bytes):
        self.con.sendall(MyAES.jiami(self.aes_k, data))

    def recv(self):
        return MyAES.jiemi(self.aes_k, self.con.recv(134217728))

    def close(self):
        try:
            self.con.close()
        except:
            pass
        try:
            self.conl.close()
        except:
            pass

    def check(self):
        try:
            while 1:
                self.conl.sendall(MyAES.jiami(self.aes_k, b'CHECK'))
                if MyAES.jiemi(self.aes_k, self.conl.recv(31)) != b'CHECKED':
                    raise ConnectionError
                sleep(1.5)
        except:
            self.close()


class Server:
    def __init__(self, port: int, ip=socket.gethostbyname(socket.gethostname())):
        while 1:
            try:
                self.base = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.base.bind((ip, port))
                self.base.listen(2)
                self.con, _ = self.base.accept()
                self.con.settimeout(5)
                priv_k = ec.generate_private_key(ec.BrainpoolP512R1(), None)
                nonce_s = secrets.token_bytes(8)
                spk = self.con.recv(276)
                self.aes_k = HKDF(
                    algorithm=ec.hashes.SHA3_512(),
                    length=64,
                    salt=nonce_s,
                    info=spk[:8],
                ).derive(priv_k.exchange(ec.ECDH(), load_pem_public_key(spk[8:])))
                self.con.sendall(
                    nonce_s + priv_k.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
                self.con.settimeout(None)
                self.base.settimeout(5)
                self.conl, _ = self.base.accept()
                self.base.settimeout(None)
                self.conl.settimeout(5)
                Thread(target=self.check).start()
                break
            except:
                self.close()

    def send(self, data: bytes):
        self.con.sendall(MyAES.jiami(self.aes_k, data))

    def recv(self):
        return MyAES.jiemi(self.aes_k, self.con.recv(134217728))

    def close(self):
        try:
            self.con.close()
        except:
            pass
        try:
            self.conl.close()
        except:
            pass
        try:
            self.base.close()
        except:
            pass

    def check(self):
        try:
            while 1:
                if MyAES.jiemi(self.aes_k, self.conl.recv(29)) != b'CHECK':
                    raise ConnectionError
                self.conl.sendall(MyAES.jiami(self.aes_k, b'CHECKED'))
                sleep(1.5)
        except:
            self.close()
