def extended_gcd(a, b):
    """Расширенный алгоритм Евклида: возвращает (gcd, x, y) такие, что a*x + b*y = gcd"""
    if b == 0:
        return a, 1, 0
    else:
        gcd, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y


def check_modular_inverse(a, n):
    gcd, x, y = extended_gcd(a, n)
    print(f"НОД({a}, {n}) = {gcd}")
    print(f"Коэффициенты Безу: x = {x}, y = {y}")
    print(f"Проверка: {a}*({x}) + {n}*({y}) = {a*x + n*y}")

    if gcd == 1:
        inverse = x % n
        print(f"\nЧисла {a} и {n} взаимно просты.")
        print(f"Уравнение Безу: {a} * ({x}) + {n} * ({y}) = 1 mod {n}")
        print(f"Обратный элемент {a} по модулю {n}: {inverse}")
    else:
        print(f"\nЧисла {a} и {n} не взаимно просты, обратного элемента не существует.")


# Пример использования
check_modular_inverse(4, 2)
