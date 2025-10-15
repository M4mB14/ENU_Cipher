import random
import math

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def is_prime(n):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True

def generate_prime(start=100, end=300):
    while True:
        num = random.randint(start, end)
        if is_prime(num):
            return num

def mod_inverse(e, phi):
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y
    g, x, y = egcd(e, phi)
    if g != 1:
        raise Exception('Обратного элемента не существует')
    return x % phi

def mod_pow(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def generate_keys():
    print("\nГенерация ключей...")
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()

    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = mod_inverse(e, phi)

    print(f"\n--- Сгенерированные ключи ---")
    print(f"p = {p}, q = {q}")
    print(f"n = {n}")
    print(f"φ(n) = {phi}")
    print(f"Открытый ключ en = {e},{n}")
    print(f"Закрытый ключ dn = {d},{n}\n")

# ---------- Шифрование / Дешифровка ----------

def encrypt(message, e, n):
    cipher_nums = [mod_pow(ord(ch), e, n) for ch in message]
    cipher_hex = ''.join([format(num, 'x').zfill(8) for num in cipher_nums])
    return cipher_hex

def decrypt(cipher_hex, d, n):
    cipher_nums = [int(cipher_hex[i:i+8], 16) for i in range(0, len(cipher_hex), 8)]
    decrypted = ''.join([chr(mod_pow(num, d, n)) for num in cipher_nums])
    return decrypted

# ---------- Основное меню ----------

def main():
    print("=== RSA Консольная программа ===")
    print("Реализация алгоритма RSA без библиотек.\n")

    while True:
        print("Выберите действие:")
        print("1 - Сгенерировать ключи")
        print("2 - Зашифровать сообщение (по en)")
        print("3 - Расшифровать сообщение (по dn)")
        print("4 - Выход")

        choice = input("\nВаш выбор: ").strip()

        if choice == '1':
            generate_keys()

        elif choice == '2':
            try:
                key_input = input("Введите открытый ключ :  ").strip()
                e, n = map(int, key_input.split(','))
                message = input("Введите сообщение: ")
                cipher_hex = encrypt(message, e, n)
                print(f"\nЗашифрованное сообщение (hex): {cipher_hex}\n")
            except Exception as ex:
                print("Ошибка при шифровании:", ex)

        elif choice == '3':
            try:
                key_input = input("Введите закрытый ключ :  ").strip()
                d, n = map(int, key_input.split(','))
                cipher_hex = input("Введите hex-сообщение для расшифровки: ").strip()
                decrypted = decrypt(cipher_hex, d, n)
                print(f"\nРасшифрованное сообщение: {decrypted}\n")
            except Exception as ex:
                print("Ошибка при расшифровке:", ex)

        elif choice == '4':
            print("Выход из программы.")
            break

        else:
            print("Неверный выбор, попробуйте снова.\n")


if __name__ == "__main__":
    main()
