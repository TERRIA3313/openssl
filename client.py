import os
import socket
import ssl
import hashlib
import getpass
import datetime
import json
from OpenSSL import crypto


def set_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # openSSL 에서 TLS 를 사용할 것임을 선언
    context.load_verify_locations('CACert.pem')  # 서버의 인증서를 등록(자기 서명 인증서의 경우 등록하지 않으면 에러 발생)
    if os.path.isfile("Cert.pem") and os.path.isfile("Priv.pem"):
        context.load_cert_chain("Cert.pem", "Priv.pem")  # 사용자의 인증서 및 개인 키 등록
    return context


def clean():
    try:
        os.system("cls")
    except:
        os.system("clear")


def sign_up(s):
    clean()
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
    clean()
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


def get_now():
    now = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    return now


def send_message(s, user_cert, user_priv):
    clean()
    title = ""
    while True:
        title = input("Input Title : ")
        if len(title) == 0:
            print("Title cannot be empty.")
        elif len(title) > 20:
            print("Too Long! Please less then 20 letters")
        elif title == "exit":
            s.send("exit".encode())
            return
        else:
            break
    r_data = "Not Found"
    destination = ""
    while "Not" in r_data:
        destination = input("input receiver name : ")
        if destination == "exit":
            s.send("exit".encode())
            return
        s.send(destination.encode())
        r_data = s.recv(1024).decode()
        print(r_data)
    s.send("done".encode())
    name = s.recv(1024).decode()
    message_list = []
    while True:
        input_data = input()
        if input_data == "":
            break
        else:
            input_data += "\n"
            message_list.append(input_data)
    str_message = "".join(map(str, message_list))
    now = get_now()
    mail = {
        "title": title,
        "Sender": name,
        "Receiver": destination,
        "Message": str_message,
        "Timestamp": now,
        "isNew": True
    }
    json_mail = json.dumps(mail, indent=2)
    signed_mail = crypto.sign(user_priv, json_mail.encode(), "sha256")
    s.send(signed_mail)
    s.recv(1024)
    s.send(json_mail.encode())
    answer = s.recv(1024).decode()
    print(answer)


def read_mail(s):
    clean()
    title = s.recv(1024).decode()
    sender = s.recv(1024).decode()
    message = s.recv(2048).decode()
    timestamp = s.recv(1024).decode()
    print("%-10s : %s" % ("Title", title))
    print("%-10s : %s" % ("Sender", title))
    print("{0:-^20}\n{1}" .format("Message", message))
    print("%-10s : %s" % ("Timestamp", timestamp))
    os.system('pause')


def open_mailbox(s):
    clean()
    title_list_10 = []
    title_list = []
    title = s.recv(2048).decode()
    counter = 1
    while True:
        data = s.recv(2048).decode()
        if data == " ":
            title_list.append(title_list_10)
            break
        if counter == 11:
            title_list.append(title_list_10)
            title_list_10 = []
            counter = 1
        title_list_10.append(data)
        counter += 1

    page = 0
    while True:
        print(title)
        if len(title_list) > 1:
            for i in title_list[page]:
                print(i)
            end = "%7s" % " " + str(page + 1) + " > Next" if page == 0 else "Prev < " + str(page + 1) + " > Next"
            print(end)
            choose = input("input [<, >, exit, Number] : ")
            if choose == "<" and page != 0:
                page -= 1
                clean()
            elif choose == ">" and (page + 1) < len(title_list):
                page += 1
                clean()
            elif choose == "exit":
                s.send(choose.encode())
                break
            elif choose.isdecimal() and (page * 10) < int(choose) <= ((page + 1) * 10):
                s.send(choose.encode())
                read_mail(s)
                return False
            else:
                clean()
                print("Wrong Input")
        else:
            for i in title_list[page]:
                print(i)
            choose = input("input [exit, Number] : ")
            if choose == "exit":
                s.send(choose.encode())
                break
            elif choose.isdecimal() and 0 < int(choose) < 11:
                s.send(choose.encode())
                read_mail(s)
                return False
            else:
                clean()
                print("Wrong Input")
    clean()
    return True


def connection(context):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:  # TCP 소켓 생성
        with context.wrap_socket(sock, server_hostname='JeongJaeUk', do_handshake_on_connect=False) as s:  # TCP 소켓 위에 TLS 소켓 생성
            s.connect((HOST, PORT))  # 서버에 접속
            s.do_handshake()  # 핸드 셰이크 실행
            # 이하 프로그램 실행 코드
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
            else:
                with open("Cert.pem", "r") as file:
                    cert = file.read()
                    hash_cert = hashlib.sha256(cert.encode()).hexdigest()
                    s.sendall(hash_cert.encode())
                    r_data = s.recv(1024).decode()
                    if r_data == "Wrong Hash":
                        print("The Cert file is suspected of being corrupted.")
                        print("Please Remove your Cert and Priv File on your Folder")
                        return False
                with open("Priv.pem", "rb+") as file:
                    user_priv = crypto.load_privatekey(crypto.FILETYPE_PEM, file.read())
                with open("Cert.pem", "rb+") as file:
                    user_cert = crypto.load_certificate(crypto.FILETYPE_PEM, file.read())
            while True:
                s_data = input("Input message : ")
                if s_data == "quit" or s_data == "exit" or s_data == "end":
                    return False
                else:
                    s.sendall(s_data.encode())
                    if s_data == "send":
                        send_message(s, user_cert, user_priv)
                    elif s_data == "read":
                        while True:
                            result = open_mailbox(s)
                            if result:
                                break
                            else:
                                s.sendall("read".encode())
                    else:
                        r_data = s.recv(1024).decode()
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
