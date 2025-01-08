import socket
import threading
import sys
import argparse
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Генерация RSA-ключей (один раз)
def generate_keys():
    # Генерация ключей для клиента
    client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_public_key = client_private_key.public_key()

    # Сохранение закрытого ключа клиента
    with open('client_private_key.pem', 'wb') as f:
        f.write(client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Сохранение открытого ключа клиента
    with open('client_public_key.pem', 'wb') as f:
        f.write(client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Генерация ключей для сервера
    server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_public_key = server_private_key.public_key()

    # Сохранение закрытого ключа сервера
    with open('server_private_key.pem', 'wb') as f:
        f.write(server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Сохранение открытого ключа сервера
    with open('server_public_key.pem', 'wb') as f:
        f.write(server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Генерация ключей для атакующего
    attacker_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_public_key = attacker_private_key.public_key()

    # Сохранение закрытого ключа атакующего
    with open('attacker_private_key.pem', 'wb') as f:
        f.write(attacker_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Сохранение открытого ключа атакующего
    with open('attacker_public_key.pem', 'wb') as f:
        f.write(attacker_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Ключи сгенерированы и сохранены.")

# Функции для клиента
def client_program():
    # Загрузка открытого ключа атакующего (используется вместо server_public_key)
    with open('attacker_public_key.pem', 'rb') as key_file:
        attacker_public_key = serialization.load_pem_public_key(key_file.read())

    # Загрузка собственного закрытого ключа
    with open('client_private_key.pem', 'rb') as key_file:
        client_private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    # Создание сокета и подключение к атакующему
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65431))  # Подключение к атакующему

    # Сгенерировать случайное число N_A
    N_A = os.urandom(16)
    print(f"[Клиент] Сгенерировано N_A: {N_A.hex()}")

    # Шаг 1: Отправить {N_A, A} атакующему вместо сервера
    message1 = N_A + b'ClientA'
    print(f"[Клиент] Исходное сообщение для сервера: {message1.hex()}")

    encrypted_message1 = attacker_public_key.encrypt(
        message1,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"[Клиент] Зашифрованное сообщение для сервера (атакующий): {encrypted_message1.hex()}")
    client_socket.sendall(encrypted_message1)

    # Шаг 2: Получить {N_A, N_B} от атакующего (подмененный атакующим)
    encrypted_message2 = client_socket.recv(4096)
    if not encrypted_message2:
        print("[Клиент] Нет ответа от атакующего.")
        client_socket.close()
        return

    print(f"[Клиент] Получено зашифрованное сообщение от сервера (посредником): {encrypted_message2.hex()}")

    decrypted_message2 = client_private_key.decrypt(
        encrypted_message2,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    received_N_A = decrypted_message2[:16]
    N_B = decrypted_message2[16:]
    print(f"[Клиент] Расшифрованное сообщение от сервера: N_A={received_N_A.hex()}, N_B={N_B.hex()}")

    # Проверка N_A
    if received_N_A == N_A:
        print("[Клиент] Проверка N_A прошла успешно. Отправляем N_B серверу.")
        # Шаг 3: Отправить {N_B} атакующему вместо сервера
        encrypted_message3 = attacker_public_key.encrypt(
            N_B,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"[Клиент] Зашифрованное N_B для сервера (атакующий): {encrypted_message3.hex()}")
        client_socket.sendall(encrypted_message3)
    else:
        print("[Клиент] Ошибка проверки N_A! Аутентификация завершена с ошибкой!")

    client_socket.close()

# Функции для сервера
def server_program():
    # Загрузка собственного закрытого ключа
    with open('server_private_key.pem', 'rb') as key_file:
        server_private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    # Загрузка открытого ключа атакующего (для ответа через атакующего)
    with open('attacker_public_key.pem', 'rb') as key_file:
        attacker_public_key = serialization.load_pem_public_key(key_file.read())

    # Создание сокета и ожидание подключения
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen()

    print("[Сервер] Ожидание подключения атакующего...")
    conn, addr = server_socket.accept()
    print(f"[Сервер] Подключен атакующий {addr}")

    # Шаг 1: Получить {N_A, A} от клиента через атакующего
    encrypted_message1 = conn.recv(4096)
    if not encrypted_message1:
        print("[Сервер] Нет данных от атакующего.")
        conn.close()
        server_socket.close()
        return

    print(f"[Сервер] Получено зашифрованное сообщение от клиента через атакующего: {encrypted_message1.hex()}")

    # Расшифровать сообщение
    decrypted_message1 = server_private_key.decrypt(
        encrypted_message1,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    N_A = decrypted_message1[:16]
    client_id = decrypted_message1[16:]
    print(f"[Сервер] Расшифрованное сообщение: N_A_attacker={N_A.hex()}, ClientID={client_id.decode()}")

    # Генерировать случайное число N_B
    N_B = os.urandom(16)
    print(f"[Сервер] Сгенерировано N_B: {N_B.hex()}")

    # Создать сообщение {N_A, N_B} и зашифровать с использованием открытого ключа атакующего
    message2 = N_A + N_B
    print(f"[Сервер] Исходное сообщение для клиента: {message2.hex()}")

    encrypted_message2 = attacker_public_key.encrypt(
        message2,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"[Сервер] Зашифрованное сообщение для клиента через атакующего: {encrypted_message2.hex()}")
    conn.sendall(encrypted_message2)

    # Шаг 3: Получить {N_B} от клиента через атакующего
    encrypted_message3 = conn.recv(4096)
    if not encrypted_message3:
        print("[Сервер] Нет ответа от атакующего.")
        conn.close()
        server_socket.close()
        return

    print(f"[Сервер] Получено зашифрованное N_B от клиента через атакующего: {encrypted_message3.hex()}")

    decrypted_message3 = server_private_key.decrypt(
        encrypted_message3,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    received_N_B = decrypted_message3
    print(f"[Сервер] Расшифрованное значение N_B: {received_N_B.hex()}")

    # Проверка N_B
    if received_N_B == N_B:
        print("[Сервер] Аутентификация успешна!")
    else:
        print("[Сервер] Ошибка аутентификации!")

    conn.close()
    server_socket.close()

# Функции для атакующего
def attacker_program():
    import socket
    import threading
    import sys
    import argparse
    import os
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    # Загрузка собственных ключей
    with open('attacker_private_key.pem', 'rb') as key_file:
        attacker_private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    with open('attacker_public_key.pem', 'rb') as key_file:
        attacker_public_key = serialization.load_pem_public_key(key_file.read())

    # Загрузка открытого ключа сервера (для отправки серверу)
    with open('server_public_key.pem', 'rb') as key_file:
        server_public_key = serialization.load_pem_public_key(key_file.read())

    # Загрузка открытого ключа клиента (для отправки клиенту)
    with open('client_public_key.pem', 'rb') as key_file:
        client_public_key = serialization.load_pem_public_key(key_file.read())

    # Создание сокета для подключения клиента к атакующему
    attacker_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    attacker_client_socket.bind(('localhost', 65431))
    attacker_client_socket.listen()

    print("[Атакующий] Ожидание подключения клиента...")
    client_conn, client_addr = attacker_client_socket.accept()
    print(f"[Атакующий] Клиент подключен: {client_addr}")

    # Создание сокета для подключения атакующего к серверу
    attacker_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        attacker_server_socket.connect(('localhost', 65432))
        print("[Атакующий] Подключен к серверу.")
    except Exception as e:
        print(f"[Атакующий] Не удалось подключиться к серверу: {e}")
        client_conn.close()
        attacker_client_socket.close()
        return

    # Сохранение оригинальных и атакующих значений
    original_N_A_client = None  # N_A, сгенерированное клиентом
    attacker_N_A = None         # N_A, сгенерированное атакующим
    original_N_B_server = None  # N_B, сгенерированное сервером
    attacker_N_B = None         # N_B, сгенерированное атакующим

    # Функция для обработки сообщений от клиента к серверу
    def handle_client_to_server():
        nonlocal original_N_A_client, attacker_N_A
        while True:
            data = client_conn.recv(4096)
            if not data:
                break
            print(f"[Атакующий] Перехвачено сообщение от клиента: {data.hex()}")

            # Расшифровать сообщение с помощью закрытого ключа атакующего
            try:
                decrypted_message = attacker_private_key.decrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                original_N_A_client = decrypted_message[:16]
                client_id = decrypted_message[16:]
                print(f"[Атакующий] Расшифрованное сообщение от клиента: N_A_client={original_N_A_client.hex()}, ClientID={client_id.decode()}")
            except Exception as e:
                print(f"[Атакующий] Ошибка при расшифровке сообщения от клиента: {e}")
                break

            # Генерация своего N_A для сервера
            attacker_N_A = os.urandom(16)
            print(f"[Атакующий] Сгенерировано собственной N_A для сервера: {attacker_N_A.hex()}")

            # Создание сообщения {attacker_N_A, ClientID} для сервера
            substituted_message = attacker_N_A + client_id
            print(f"[Атакующий] Подмененное сообщение для сервера: {substituted_message.hex()}")

            # Шифрование сообщения для сервера
            encrypted_substituted = server_public_key.encrypt(
                substituted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"[Атакующий] Зашифрованное подмененное сообщение для сервера: {encrypted_substituted.hex()}")
            attacker_server_socket.sendall(encrypted_substituted)

    # Функция для обработки сообщений от сервера к клиенту
    def handle_server_to_client():
        nonlocal original_N_B_server, attacker_N_B
        while True:
            data = attacker_server_socket.recv(4096)
            if not data:
                break
            print(f"[Атакующий] Перехвачено сообщение от сервера: {data.hex()}")

            # Расшифровать сообщение с помощью закрытого ключа атакующего
            try:
                decrypted_message = attacker_private_key.decrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                received_N_A = decrypted_message[:16]
                original_N_B_server = decrypted_message[16:]
                print(f"[Атакующий] Расшифрованное сообщение от сервера: N_A_attacker={received_N_A.hex()}, N_B_server={original_N_B_server.hex()}")
            except Exception as e:
                print(f"[Атакующий] Ошибка при расшифровке сообщения от сервера: {e}")
                break

            # Проверка, что N_A_attacker совпадает с атакующим N_A
            if received_N_A != attacker_N_A:
                print("[Атакующий] Полученный N_A соответствует не сгенерированному атакующим N_A. Пропуск сообщения.")
                continue

            # Генерация своего N_B для клиента
            attacker_N_B = os.urandom(16)
            print(f"[Атакующий] Сгенерировано собственной N_B для клиента: {attacker_N_B.hex()}")

            # Создание сообщения {original_N_A_client, attacker_N_B} для клиента
            substituted_message = original_N_A_client + attacker_N_B
            print(f"[Атакующий] Подмененное сообщение для клиента: {substituted_message.hex()}")

            # Шифрование сообщения для клиента
            encrypted_message = client_public_key.encrypt(
                substituted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"[Атакующий] Зашифрованное сообщение для клиента: {encrypted_message.hex()}")
            client_conn.sendall(encrypted_message)

    # Функция для обработки сообщений от клиента (после получения N_B) к серверу
    def handle_client_response_to_server():
        nonlocal original_N_B_server, attacker_N_A
        while True:
            data = client_conn.recv(4096)
            if not data:
                break
            print(f"[Атакующий] Перехвачено сообщение от клиента (N_B): {data.hex()}")

            # Расшифровать сообщение с помощью закрытого ключа атакующего
            try:
                decrypted_message = attacker_private_key.decrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                received_N_B_client = decrypted_message
                print(f"[Атакующий] Расшифрованное сообщение от клиента (N_B): {received_N_B_client.hex()}")
            except Exception as e:
                print(f"[Атакующий] Ошибка при расшифровке сообщения от клиента (N_B): {e}")
                break

            # Создание сообщения {received_N_B_client} для сервера
            substituted_message = original_N_B_server
            print(f"[Атакующий] Подмененное сообщение для сервера: {substituted_message.hex()}")

            # Шифрование сообщения для сервера
            encrypted_substituted = server_public_key.encrypt(
                substituted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"[Атакующий] Зашифрованное подмененное сообщение для сервера: {encrypted_substituted.hex()}")
            attacker_server_socket.sendall(encrypted_substituted)

    # Запуск потоков для пересылки данных
    thread_client_to_server = threading.Thread(target=handle_client_to_server)
    thread_server_to_client = threading.Thread(target=handle_server_to_client)
    thread_client_response_to_server = threading.Thread(target=handle_client_response_to_server)

    thread_client_to_server.start()
    thread_server_to_client.start()
    thread_client_response_to_server.start()

    thread_client_to_server.join()
    thread_server_to_client.join()
    thread_client_response_to_server.join()

    attacker_client_socket.close()
    attacker_server_socket.close()

# Основная функция для запуска программ в зависимости от аргументов командной строки
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NSL Protocol Simulation with MITM Attack")
    parser.add_argument('role', choices=['client', 'server', 'attacker', 'generate_keys'], help="Role to play: client, server, attacker, or generate_keys")

    args = parser.parse_args()

    if args.role == 'generate_keys':
        generate_keys()
    elif args.role == 'client':
        client_program()
    elif args.role == 'server':
        server_program()
    elif args.role == 'attacker':
        attacker_program()