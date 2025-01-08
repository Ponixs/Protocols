import random

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
        self.r = [random.randint(1, self.n - 1) for _ in range(self.t)]
        self.x = [pow(ri, 2, self.n) for ri in self.r]
        return self.x

    def generate_response(self, e):
        y = []
        for i in range(self.t):
            y_i = (self.r[i] * pow(self.s, e[i], self.n)) % self.n
            y.append(y_i)
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
        return self.e

    def verify(self, x, y):
        for i in range(self.t):
            left = pow(y[i], 2, self.n)
            right = (x[i] * pow(self.v, self.e[i], self.n)) % self.n
            if left != right:
                return False
        return True

def calculate_false_identification_probability(t):
    return 0.5 ** t

def main():
    import sympy

    # Генерация двух больших простых чисел p и q
    p = sympy.randprime(2**10, 2**11)
    q = sympy.randprime(2**10, 2**11)
    n = p * q

    # Секретный ключ (приватный)
    s = random.randint(1, n - 1)
    # Публичный ключ
    v = pow(s, 2, n)

    # Количество раундов (параметр)
    t = 1  # Вы можете изменить это значение

    prover = Prover(n, s, t)
    verifier = Verifier(n, v, t)

    # Этап 1: Проверяющий генерирует подтверждение
    x = prover.generate_commitment()
    # Этап 2: Проверяющий отправляет вызов
    e = verifier.send_challenge()
    # Этап 3: Проверяющий генерирует ответ
    y = prover.generate_response(e)
    # Этап 4: Проверяющий проверяет ответ
    result = verifier.verify(x, y)

    print("Аутентификация честного пользователя:", "Успех" if result else "Неудача")

    # Попытка ложной аутентификации
    fake_s = random.randint(1, n - 1)
    fake_prover = Prover(n, fake_s, t)
    x_fake = fake_prover.generate_commitment()
    e_fake = verifier.send_challenge()
    y_fake = fake_prover.generate_response(e_fake)
    result_fake = verifier.verify(x_fake, y_fake)

    print("Попытка ложной аутентификации:", "Успех" if result_fake else "Неудача")

    # Расчет вероятности ложной идентификации
    prob = calculate_false_identification_probability(t)
    print(f"Вероятность ложной идентификации при {t} раундах: {prob}")

if __name__ == "__main__":
    main()
