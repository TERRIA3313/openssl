import socket
import ssl
import random
import subprocess
from OpenSSL import crypto
from _thread import *
import os, re, datetime


def get_help():
    message = "Manual\n1. get_cert : Getting Your Cert\n0. quit : disconnect"
    client_socket.send(message.encode())


def get_cert_req():
    print("Start Getting Cert Mode")
    psec = crypto.PKey()
    psec.generate_key(crypto.TYPE_RSA, 2048)
    req = crypto.X509Req()
    subject = req.get_subject()
    try:
        client_socket.send("Start gertting Cert\ninput your Name".encode())
        print("Input Name")
        name = client_socket.recv(1024)
        if os.path.isdir("Cert/" + name.decode()):
            client_socket.send("Already exists name".encode())
            return
        else:
            os.makedirs("Cert/" + name.decode())

        subject.CN = name.decode()

        client_socket.send("input your Country".encode())
        print("Input Country")
        data = client_socket.recv(1024)
        subject.C = data.decode()

        client_socket.send("input your State".encode())
        print("Input State")
        data = client_socket.recv(1024)
        subject.ST = data.decode()

        client_socket.send("input your Office".encode())
        print("Input Office")
        data = client_socket.recv(1024)
        subject.O = data.decode()

        client_socket.send("input your e-mail".encode())
        print("Input e-mail")
        data = client_socket.recv(1024)
        p = re.compile("\w+@\w+[.]\w+")
        while not p.match(data.decode()):
            client_socket.send("Invalid format - ex)aa@bb.cc".encode())
            print("Input e-mail")
            data = client_socket.recv(1024)
        subject.emailAddress = data.decode()

        req.set_pubkey(psec)
        req.sign(psec, "sha256")
        with open("Cert/" + name.decode() + "/" + now + "-" + name.decode() + ".pem", "wb") as f:
            f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
        client_socket.send("END".encode())
        print("End Getting Cert Mode")
    except ConnectionResetError as e:
        print('Disconnected by ' + addr[0], ':', addr[1])


def get_cert():
    req = crypto.X509Req()


def threaded(client_socket, addr):
    print('Connected by :', addr[0], ':', addr[1])
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                print('Disconnected by ' + addr[0], ':', addr[1])
                break
            else:
                print('Received from ' + addr[0], ':', addr[1], "message : " + data.decode())
                if data.decode() == "get_cert":
                    get_cert_req()
                elif data.decode() == "help":
                    get_help()
                else:
                    client_socket.send("Not Found".encode())

        except ConnectionResetError as e:
            print('Disconnected by ' + addr[0], ':', addr[1])
            break
    client_socket.close()


HOST = '192.168.137.207'
PORT = 8080
datetime.timezone(datetime.timedelta(hours=9))
now = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((HOST, PORT))
server_socket.listen()

print('server start')
while True:
    print('wait')
    client_socket, addr = server_socket.accept()
    start_new_thread(threaded, (client_socket, addr))

server_socket.close()
