import socket
import ssl
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from base64 import b64encode, b64decode
import os
import socket
import ssl
import hashlib
import getpass


def set_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # openSSL 에서 TLS 를 사용할 것임을 선언
    context.load_verify_locations('CACert.pem')  # 서버의 인증서를 등록(자기 서명 인증서의 경우 등록하지 않으면 에러 발생)
    if os.path.isfile("Cert.pem") and os.path.isfile("Priv.pem"):
        context.load_cert_chain("Cert.pem", "Priv.pem")  # 사용자의 인증서 및 개인 키 등록
    return context


def sign_up(s):
    s.send("sign_up".encode())
    data = s.recv(1024).decode()
    print(data)
    data = s.recv(1024).decode()
    print(data)
    while True:
        s_data = str(input("메시지 : "))
        if s_data == "quit":
            s.sendall(s_data.encode())
            print("Cert Process Stopped")
            return
        s.sendall(s_data.encode())
        r_data = s.recv(1024)
        if r_data.decode() == "END":
            print('Received', repr(r_data.decode()))
            get_file(s, "Cert")
            get_file(s, "Priv")
            print("Sign up End")
            print("Restart Program")
            break
        print('Received', repr(r_data.decode()))


def sign_in(s):
    s.send("sign_in".encode())
    while True:
        data = s.recv(1024).decode()
        print(data)
        userID = input(" : ")
        s.send(userID.encode())
        data = s.recv(1024).decode()
        print(data)
        if data != "Not found":
            while True:
                userPW = getpass.getpass()
                hashPW = hashlib.sha256(userPW.encode()).hexdigest()
                s.send(hashPW.encode())
                data = s.recv(1024).decode()
                if data != "Wrong Password":
                    get_file(s, "Cert")
                    get_file(s, "Priv")
                    print("Sign in End")
                    print("Restart Program")
                    break
            break


def get_file(conn, filename):
    with open(filename + ".pem", 'wb') as f:
        try:
            r_data = conn.recv(1024)
            while r_data.decode() != "END":
                f.write(r_data)
                r_data = conn.recv(1024)
        except Exception as e:
            print(e)


def connection(context):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:  # TCP 소켓 생성
        with context.wrap_socket(sock, server_hostname='JeongJaeUk',
                                 do_handshake_on_connect=False) as s:  # TCP 소켓 위에 TLS 소켓 생성
            s.connect((HOST, PORT))  # 서버에 접속
            s.do_handshake()  # 핸드 셰이크 실행
            # 이하 프로그램 실행 코드
            while True:
                if not os.path.isfile("Cert.pem") and not os.path.isfile("Priv.pem"):  # 사용자의 Cert 및 개인키가 없을 때
                    while True:
                        sign_option = int(input("1. Sign up\n2. Sign in\n: "))
                        if sign_option == 1:
                            sign_up(s)
                            return True
                        elif sign_option == 2:
                            sign_in(s)
                            return True
                        else:
                            print("Wrong commands")
                s_data = input("Input message : ")
                if s_data == "quit" or s_data == "exit" or s_data == "end":
                    return False
                else:
                    s.sendall(s_data.encode('utf-8'))
                    r_data = s.recv(1024).decode('utf-8')
                    print(f'서버응답 : {r_data}')


def run():
    context = set_context()
    is_running = connection(context)
    return is_running


if __name__ == "__main__":
    HOST = '192.168.137.207'  # 서버 IP
    PORT = 8080  # 서버 Port
    running = True
    while running:
        running = run()
    print("Disconnect from Server : " + HOST + ":" + str(PORT))
