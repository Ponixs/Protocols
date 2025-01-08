import socket
import threading
import hashlib
import random
import sys

# Общее большое простое число и генератор
N = 0xE48985B3  # Пример простого числа (для реальной реализации используйте большее простое число)
g = 2  # Генератор

def H(data):
    """Хеш-функция SHA-256"""
    return int(hashlib.sha256(data).hexdigest(), 16)

class PAKEProtocol:
    def __init__(self, role, password=None, host='localhost', port=12345):
        self.role = role  # 'server' или 'client'
        self.password = password.encode() if password else None
        self.host = host
        self.port = port
        self.password_hash = None
        self.private = None
        self.public = None
        self.peer_public = None
        self.shared_key = None

    def start(self):
        if self.role == 'server':
            self.server_start()
        elif self.role == 'client':
            self.client_start()
        else:
            print("Недопустимая роль. Выберите 'server' или 'client'.")

    def server_start(self):
        # Создаем сокет и слушаем подключения
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((self.host, self.port))
        server_sock.listen(1)
        print('Сервер запущен и ожидает подключения...')

        conn, addr = server_sock.accept()
        print(f'Подключен клиент: {addr}')

        try:
            # Получаем хеш пароля от клиента (регистрация)
            data = conn.recv(1024)
            self.password_hash = int(data.decode())
            print('Получен хеш пароля от клиента.', self.password_hash)

            # Получаем публичное значение A от клиента
            data = conn.recv(1024)
            self.peer_public = int(data.decode())
            print('Получено публичное значение A от клиента.', self.peer_public)

            # Генерируем секретное и публичное значения сервера
            self.private = random.randint(1, N - 1)
            self.public = pow(g, self.private, N)

            # Отправляем публичное значение B клиенту
            conn.sendall(str(self.public).encode())
            print('Отправлено публичное значение B клиенту.')

            # Вычисляем общий ключ
            temp = pow(self.peer_public, self.private, N)
            self.shared_key = (temp * self.password_hash) % N
            print(f'Сервер вычислил общий ключ: {self.shared_key}')
        finally:
            # Закрываем соединение
            conn.close()
            server_sock.close()

    def client_start(self):
        # Создаем сокет и подключаемся к серверу
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect((self.host, self.port))
        print('Подключен к серверу.')

        try:
            # Вычисляем хеш пароля и отправляем серверу (регистрация)
            self.password_hash = H(self.password)
            client_sock.sendall(str(self.password_hash).encode())
            print('Отправлен хеш пароля серверу.', self.password_hash)

            # Генерируем секретное и публичное значения клиента
            self.private = random.randint(1, N - 1)
            self.public = pow(g, self.private, N)

            # Отправляем публичное значение A серверу
            client_sock.sendall(str(self.public).encode())
            print('Отправлено публичное значение A серверу.', self.public)

            # Получаем публичное значение B от сервера
            data = client_sock.recv(1024)
            self.peer_public = int(data.decode())
            print('Получено публичное значение B от сервера.')

            # Вычисляем общий ключ
            temp = pow(self.peer_public, self.private, N)
            self.shared_key = (temp * self.password_hash) % N
            print(f'Клиент вычислил общий ключ: {self.shared_key}')
        finally:
            # Закрываем соединение
            client_sock.close()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Использование: python pake.py [server|client] [password]")
        sys.exit(1)

    role = sys.argv[1]

    if role == 'server':
        pake = PAKEProtocol(role='server')
        pake.start()
    elif role == 'client':
        if len(sys.argv) < 3:
            print("Для клиента необходимо указать пароль.")
            print("Использование: python pake.py client [password]")
            sys.exit(1)
        password = sys.argv[2]
        pake = PAKEProtocol(role='client', password=password)
        pake.start()
    else:
        print("Недопустимая роль. Выберите 'server' или 'client'.")
