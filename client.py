import socket
import ssl
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from base64 import b64encode, b64decode


HOST = '192.168.137.207'
PORT = 8080
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))


def run():
    while True:
        data = str(input("메시지 : "))
        if data == "quit":
            break
        else:
            client_socket.sendall(data.encode())
            if data == "get_cert":
                get_cert()
            elif data == "help":
                data = client_socket.recv(1024)
                print(data.decode())
            else:
                data = client_socket.recv(1024)
                print(data.decode())


def get_cert():
    data = client_socket.recv(1024).decode()
    print(data)
    while True:
        data = str(input("메시지 : "))
        client_socket.sendall(data.encode())
        data = client_socket.recv(1024)
        if data.decode() == "END":
            print('Received', repr(data.decode()))
            break
        print('Received', repr(data.decode()))


def gen_key():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    with open("PrivKey.pem", "wb+") as f:
        f.write(private_key.export_key('PEM'))
    with open("PubKey.pem", "wb+") as f:
        f.write(public_key.export_key('PEM'))


if __name__ == "__main__":
    run()
