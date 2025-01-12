import random
import sympy
import time

class Prover:
    def __init__(self, n, s, t):
        """
        Участник Проверяющий (Prover).
        n: модуль (публичный)
        s: секретный ключ (приватный)
        t: количество раундов
        """
        self.n = n
        self.s = s
        self.t = t
        self.r = []
        self.x = []

    def generate_commitment(self):
        print("\n[Prover] Генерация подтверждений:")
        self.r = [random.randint(1, self.n - 1) for _ in range(self.t)]
        for i, ri in enumerate(self.r, 1):
            print(f"  Раунд {i}: r = {ri}")
        self.x = [pow(ri, 2, self.n) for ri in self.r]
        for i, xi in enumerate(self.x, 1):
            print(f"  Раунд {i}: x = r^2 mod n = {xi}")
        return self.x

    def generate_response(self, e):
        print("\n[Prover] Генерация ответов на вызовы:")
        y = []
        for i in range(self.t):
            y_i = (self.r[i] * pow(self.s, e[i], self.n)) % self.n
            y.append(y_i)
            print(f"  Раунд {i+1}: y = r * s^e mod n = {self.r[i]} * {self.s}^{e[i]} mod {self.n} = {y_i}")
        return y

class Verifier:
    def __init__(self, n, v, t):
        """
        Участник Проверяющий (Verifier).
        n: модуль (публичный)
        v: публичный ключ (v = s^2 mod n)
        t: количество раундов
        """
        self.n = n
        self.v = v
        self.t = t
        self.e = []

    def send_challenge(self):
        self.e = [random.randint(0, 1) for _ in range(self.t)]
        print("\n[Verifier] Отправка вызовов (challenges):")
        for i, ei in enumerate(self.e, 1):
            print(f"  Раунд {i}: e = {ei}")
        return self.e

    def verify(self, x, y):
        print("\n[Verifier] Проверка ответов:")
        for i in range(self.t):
            left = pow(y[i], 2, self.n)
            right = (x[i] * pow(self.v, self.e[i], self.n)) % self.n
            print(f"  Раунд {i+1}:")
            print(f"    y^2 mod n = {y[i]}^2 mod {self.n} = {left}")
            print(f"    x * v^e mod n = {x[i]} * {self.v}^{self.e[i]} mod {self.n} = {right}")
            if left != right:
                print(f"    Результат: Неудача в раунде {i+1}")
                return False
            else:
                print(f"    Результат: Успех в раунде {i+1}")
        return True

def calculate_false_identification_probability(t):
    return 0.5 ** t

def main():
    print("=== Инициализация протокола Feige-Fiat-Shamir ===")
    # Генерация двух больших простых чисел p и q
    p = sympy.randprime(2**10, 2**11)
    q = sympy.randprime(2**10, 2**11)
    n = p * q
    print(f"p = {p}, q = {q}")
    print(f"n = p * q = {n}")

    # Секретный ключ (приватный)
    s = random.randint(1, n - 1)
    print(f"Секретный ключ s = {s}")
    # Публичный ключ
    v = pow(s, 2, n)
    print(f"Публичный ключ v = s^2 mod n = {v}")

    # Количество раундов (параметр)
    t = 1
    print(f"Количество раундов t = {t}")

    prover = Prover(n, s, t)
    verifier = Verifier(n, v, t)

    # Измерение времени выполнения протокола
    start_time = time.perf_counter()

    # Этапы протокола
    x = prover.generate_commitment()
    e = verifier.send_challenge()
    y = prover.generate_response(e)
    result = verifier.verify(x, y)

    end_time = time.perf_counter()

    print("\n=== Результаты аутентификации ===")
    print("Аутентификация честного пользователя:", "Успех" if result else "Неудача")

    # Попытка ложной аутентификации
    print("\n=== Попытка ложной аутентификации ===")
    fake_s = random.randint(1, n - 1)
    print(f"Сгенерирован поддельный секретный ключ fake_s = {fake_s}")
    fake_prover = Prover(n, fake_s, t)
    x_fake = fake_prover.generate_commitment()
    e_fake = verifier.send_challenge()
    y_fake = fake_prover.generate_response(e_fake)
    result_fake = verifier.verify(x_fake, y_fake)

    print("\nРезультаты попытки ложной аутентификации:", "Успех" if result_fake else "Неудача")

    # Расчет вероятности ложной идентификации
    prob = calculate_false_identification_probability(t)
    print(f"\nВероятность ложной идентификации при {t} раундах: {prob}")

    # Оценка производительности
    elapsed_time = end_time - start_time
    print(f"Время выполнения протокола: {elapsed_time:.6f} секунд")

if __name__ == "__main__":
    main()

