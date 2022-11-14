import socket, ssl, datetime, _thread, os, re
from OpenSSL import crypto


def get_help():
    message = "Manual\n1. get_cert : Getting Your Cert\n0. quit : disconnect"
    conn.send(message.encode())


def send_subject_message(subject):
    message = "input your " + subject
    conn.send(message.encode())
    print("Input " + subject + " Mode")
    data = conn.recv(1024)
    if data.decode() == "quit":
        return False
    else:
        return data.decode()


def get_cert_req():
    conn.send("Sign up Process Starting...".encode())
    print("Start Getting Cert Mode")
    req = crypto.X509Req()
    subject = req.get_subject()
    try:
        user_id = send_subject_message("id")
        print(user_id)
        if user_id:
            if os.path.isdir("Cert/" + user_id):
                conn.send("Already exists id".encode())
                return
        else:
            print("quit message from User")
            return

        data = send_subject_message("Contry")
        if data:
            subject.C = data
        else:
            print("quit message from User")
            return

        data = send_subject_message("State")
        if data:
            subject.ST = data
        else:
            print("quit message from User")
            return

        data = send_subject_message("Office")
        if data:
            subject.O = data
        else:
            print("quit message from User")
            return

        p = re.compile("\w+@\w+[.]\w+")
        data = send_subject_message("e-mail")
        if data:
            while not p.match(data):
                conn.send("Invalid format - ex)aa@bb.cc".encode())
                print("Input e-mail")
                data = conn.recv(1024).decode()
            subject.emailAddress = data
        else:
            print("quit message from User")
            return

        psec = crypto.PKey()
        psec.generate_key(crypto.TYPE_RSA, 2048)
        req.set_pubkey(psec)
        req.sign(psec, "sha256")
        filename = now + "-" + user_id
        os.makedirs("Cert/" + user_id)
        with open("Cert/" + user_id + "/Priv.pem", "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, psec))
        subject.CN = user_id
        get_cert(req, user_id, filename)
        conn.send("END".encode())
        trans_cert(conn, user_id, "Cert")
        conn.send("END".encode())
        trans_cert(conn, user_id, "Priv")
        conn.send("END".encode())
        print("End Getting Cert Mode")
    except ConnectionResetError as e:
        print('Disconnected by ' + addr[0], ':', addr[1])


def get_cert(req, user_id, filename):
    with open("serial_number.txt", "r") as f:
        number = int(f.read()) + 1

    with open("serial_number.txt", "w") as f:
        f.write(str(number))
    cert = crypto.X509()
    cert.set_serial_number(number)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_subject(req.get_subject())
    cert.set_issuer(CACert.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(CAPriv, "sha256")

    with open("Cert/" + user_id + "/Cert.pem", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))


def trans_cert(conn, user_id, filename):
    print(filename + " transmission Start")
    with open("Cert/" + user_id + "/" + filename + ".pem", 'rb') as f:
        try:
            data = f.read(1024)
            while data:
                conn.send(data)
                data = f.read(1024)
        except Exception as e:
            print(e)


def send_cert():
    while True:
        conn.send("input your ID".encode())
        user_id = conn.recv(1024).decode()
        if os.path.isdir("Cert/" + user_id):
            conn.send("input your Password".encode())
            user_pw = conn.recv(1024).decode()
            with open("Cert/" + user_id + "/password.txt", "r") as f:
                open_pw = f.read()
                if user_pw == open_pw:
                    conn.send("Transport Mode".encode())
                    trans_cert(conn, user_id, "Cert")
                    conn.send("END".encode())
                    trans_cert(conn, user_id, "Priv")
                    conn.send("END".encode())
                    break
                else:
                    conn.send("Wrong Password".encode())
        else:
            conn.send("Not Found".encode())


def tls_threaded(conn, addr):
    print('Connected by :', addr[0], ':', addr[1])
    if conn.getpeercert() is None:
        data = conn.recv(1024).decode()
        if data == "sign_up":
            get_cert_req()
        elif data == "sign_in":
            send_cert()
    else:
        peercert = conn.getpeercert()
        user_name = peercert['subject'][4][0][1]
    while True:
        try:
            data = conn.recv(1024).decode()
            if not data:
                print('Disconnected by ' + addr[0], ':', addr[1])
                break
            else:
                print('Received from ' + addr[0], ':', addr[1], data)
                if data == "help":
                    get_help()
                else:
                    conn.send("Not Found".encode())
                print("wait")
        except ConnectionResetError as e:
            print('Disconnected by ' + addr[0], ':', addr[1])
            break

    conn.close()


HOST = '192.168.137.207'
PORT = 8080

datetime.timezone(datetime.timedelta(hours=9))
now = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
with open("CAPriv.pem", "rb+") as f:
    CAPriv = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
with open("CACert.pem", "rb+") as f:
    CACert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.verify_mode = ssl.CERT_OPTIONAL
context.load_cert_chain('CACert.pem', 'CAPriv.pem')
context.load_verify_locations("CACert.pem")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((HOST, PORT))
sock.listen()
ssl_sock = context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
while True:
    print('wait')
    conn, addr = ssl_sock.accept()
    conn.do_handshake()
    _thread.start_new_thread(tls_threaded, (conn, addr))
