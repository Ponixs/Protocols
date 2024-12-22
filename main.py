import hashlib
import socket
import threading
import os

# Большое простое число N
N = int('EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775191B187DAE4ED191622857'
        '8409300BC3F62D76591F67D073224087A57B1CFF2D3B2AD4BFFC229287AAA41A82456F0AE8DB1D4070E52441E8CF83910'
        '870BF7BEB5E353B6742FA5A9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF', 16)

g = 2  # Генератор группы
k = 3  # Мультипликативный коэффициент


# Хэш функция
def hash_function(data):
    return hashlib.sha256(data).digest()


# Класс клиент
class Client:
    def __init__(self, I, P):
        self.I = I  # Имя пользователя
        self.P = P  # Пароль
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect_to_server(self):
        self.client_socket.connect(('localhost', 9999))

        self.a = int.from_bytes(os.urandom(16), 'big')
        self.A = pow(g, self.a, N)

        print(f"Client: A = {hex(self.A)}")

        self.client_socket.send(self.I.encode())
        s = self.client_socket.recv(1024).decode()
        B = int(self.client_socket.recv(1024).decode(), 16)

        print(f"Client: B = {hex(B)}")

        u = int.from_bytes(hash_function(str(self.A).encode() + str(B).encode()), 'big')
        x = int.from_bytes(hash_function((s + self.P).encode()), 'big')
        S = pow(B - k * pow(g, x, N), self.a + u * x, N)
        K = hash_function(str(S).encode())

        print(f"Client: K = {K.hex()}")

        self.client_socket.send(hex(self.A).encode())  # Send A as hex
        self.client_socket.send(hash_function((self.I + s + K.hex()).encode()).hex().encode())

        server_response = self.client_socket.recv(1024).decode()
        if server_response == hash_function((str(self.A) + K.hex()).encode()).hex():
            print("Client: Authentication successful!")
        else:
            print("Client: Authentication failed!")
        self.client_socket.close()


# Класс сервер
class Server:
    def __init__(self, I, P):
        self.I = I  # Имя пользователя
        self.P = P  # Пароль
        self.s = os.urandom(16).hex()
        self.v = pow(g, int.from_bytes(hash_function((self.s + P).encode()), 'big'), N)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', 9999))
        self.server_socket.listen(1)

    def start(self):
        print("Server started and waiting for connections")
        conn, addr = self.server_socket.accept()
        print(f"Connected to {addr}")
        self.handle_client(conn)

    def handle_client(self, conn):
        I = conn.recv(1024).decode()

        b = int.from_bytes(os.urandom(16), 'big')
        B = (k * self.v + pow(g, b, N)) % N

        print(f"Server: B = {hex(B)}")

        conn.send(self.s.encode())
        conn.send(hex(B).encode())  # Send B as hex

        A = int(conn.recv(1024).decode(), 16)  # Read A as hex
        u = int.from_bytes(hash_function(str(A).encode() + str(B).encode()), 'big')

        S = pow(A * pow(self.v, u, N), b, N)
        K = hash_function(str(S).encode())

        print(f"Server: K = {K.hex()}")

        client_response = conn.recv(1024).decode()
        if client_response == hash_function((I + self.s + K.hex()).encode()).hex():
            conn.send(hash_function((str(A) + K.hex()).encode()).hex().encode())
            print("Server: Authentication successful!")
        else:
            conn.send("Server: Authentication failed!".encode())
            print("Server: Authentication failed!")

        conn.close()


# Создание и запуск сервера
server = Server(I="user", P="secure_password")
server_thread = threading.Thread(target=server.start)
server_thread.start()

# Создание и подключение клиента
client = Client(I="user", P="secure_password")
client.connect_to_server()
