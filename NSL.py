import socket
import threading
import sys
import argparse
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Функции для клиента
def client_program():
    # Загрузка открытого ключа сервера
    with open('server_public_key.pem', 'rb') as key_file:
        server_public_key = serialization.load_pem_public_key(key_file.read())

    # Создание сокета и подключение к серверу или атакующему
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Подключаемся к атакующему вместо сервера для демонстрации атаки
    client_socket.connect(('localhost', 65431))

    # Сгенерировать случайное число N_A
    N_A = os.urandom(16)

    # Шаг 1: Отправить {N_A, A} серверу
    message1 = N_A + b'ClientA'
    encrypted_message1 = server_public_key.encrypt(
        message1,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    client_socket.sendall(encrypted_message1)

    # Шаг 2: Получить {N_A, N_B} от сервера
    encrypted_message2 = client_socket.recv(1024)
    if not encrypted_message2:
        print("Нет ответа от сервера.")
        client_socket.close()
        return

    # Загрузка собственного закрытого ключа
    with open('client_private_key.pem', 'rb') as key_file:
        client_private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    decrypted_message2 = client_private_key.decrypt(
        encrypted_message2,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    received_N_A = decrypted_message2[:16]
    N_B = decrypted_message2[16:]

    # Проверка N_A
    if received_N_A == N_A:
        print("N_A совпадает, продолжаем аутентификацию.")

        # Шаг 3: Отправить {N_B} серверу
        encrypted_message3 = server_public_key.encrypt(
            N_B,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        client_socket.sendall(encrypted_message3)
    else:
        print("Ошибка проверки N_A!")

    client_socket.close()

# Функции для сервера
def server_program():
    # Загрузка собственного закрытого ключа
    with open('server_private_key.pem', 'rb') as key_file:
        server_private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    # Загрузка открытого ключа клиента
    with open('client_public_key.pem', 'rb') as key_file:
        client_public_key = serialization.load_pem_public_key(key_file.read())

    # Создание сокета и ожидание подключения
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen()

    print("Сервер ожидает подключения клиента...")
    conn, addr = server_socket.accept()
    print(f"Подключен клиент {addr}")

    # Шаг 1: Получить {N_A, A} от клиента
    encrypted_message1 = conn.recv(1024)
    if not encrypted_message1:
        print("Нет данных от клиента.")
        conn.close()
        server_socket.close()
        return

    decrypted_message1 = server_private_key.decrypt(
        encrypted_message1,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    N_A = decrypted_message1[:16]
    client_id = decrypted_message1[16:]

    # Генерировать случайное число N_B
    N_B = os.urandom(16)

    # Шаг 2: Отправить {N_A, N_B} клиенту
    message2 = N_A + N_B
    encrypted_message2 = client_public_key.encrypt(
        message2,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    conn.sendall(encrypted_message2)

    # Шаг 3: Получить {N_B} от клиента
    encrypted_message3 = conn.recv(1024)
    if not encrypted_message3:
        print("Нет ответа от клиента.")
        conn.close()
        server_socket.close()
        return

    decrypted_message3 = server_private_key.decrypt(
        encrypted_message3,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    received_N_B = decrypted_message3

    # Проверка N_B
    if received_N_B == N_B:
        print("Аутентификация успешна!")
    else:
        print("Ошибка аутентификации!")

    conn.close()
    server_socket.close()

# Функции для атакующего
def attacker_program():
    # Создание сокета для подключения клиента к атакующему
    attacker_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    attacker_client_socket.bind(('localhost', 65431))
    attacker_client_socket.listen()

    print("Атакующий ожидает подключения клиента...")
    client_conn, client_addr = attacker_client_socket.accept()
    print(f"Клиент подключен к атакующему {client_addr}")

    # Создание сокета для подключения атакующего к серверу
    attacker_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    attacker_server_socket.connect(('localhost', 65432))
    print("Атакующий подключен к серверу")

    def handle_client(client_socket, server_socket):
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            # Здесь можно изменить данные перед пересылкой на сервер
            print("Атакующий перехватил данные от клиента и отправил на сервер.")
            server_socket.sendall(data)

    def handle_server(server_socket, client_socket):
        while True:
            data = server_socket.recv(1024)
            if not data:
                break
            # Здесь можно изменить данные перед пересылкой клиенту
            print("Атакующий перехватил данные от сервера и отправил клиенту.")
            client_socket.sendall(data)

    # Запуск потоков для пересылки данных
    client_thread = threading.Thread(target=handle_client, args=(client_conn, attacker_server_socket))
    server_thread = threading.Thread(target=handle_server, args=(attacker_server_socket, client_conn))
    client_thread.start()
    server_thread.start()

    client_thread.join()
    server_thread.join()

    attacker_client_socket.close()
    attacker_server_socket.close()

# Основная функция для запуска программ в зависимости от аргументов командной строки
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NSL Protocol Simulation with MITM Attack")
    parser.add_argument('role', choices=['client', 'server', 'attacker'], help="Role to play: client, server, or attacker")

    args = parser.parse_args()

    if args.role == 'client':
        client_program()
    elif args.role == 'server':
        server_program()
    elif args.role == 'attacker':
        attacker_program()
