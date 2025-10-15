from rsa import generate_keys, encrypt, decrypt, mod_pow
from hash_func import parse_plaintext_to_bits, compress256, FIXED_IV_BITS, chunk_bits
import sys


def hash_message(message: str) -> str:
    """Вычисление хэша сообщения (256 бит в бинарном виде)"""
    bits = parse_plaintext_to_bits(message)
    blocks = list(chunk_bits(bits, 256))
    if len(blocks) == 0:
        blocks = ['0' * 256]
    if len(blocks[-1]) < 256:
        blocks[-1] = blocks[-1].ljust(256, '0')
    state = FIXED_IV_BITS
    for blk in blocks:
        state = compress256(state, blk)
    return state


def sign_message():
    print("\n=== Подпись сообщения ===")
    M = input("Введите сообщение (M): ").strip()
    # Хэшируем сообщение
    H_M = hash_message(M)
    H_int = int(H_M, 2)
    print(f"\nХэш сообщения (H(M)) = {format(H_int, '064x')}")

    # Генерируем ключи RSA
    print("\nГенерация RSA ключей...")
    from rsa import generate_prime, gcd, mod_inverse
    import random, math

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

    print(f"\nОткрытый ключ: {e},{n}")
    print(f"Закрытый ключ: {d},{n}")

    # Подпись: Q = (H(M))^d mod n
    Q = mod_pow(H_int, d, n)
    print(f"\nПодпись (Q) = {Q}\n")

    print("=== Результат ===")
    print(f"M = {M}")
    print(f"Q = {Q}")
    print(f"Открытый ключ (для проверки): {e},{n}")
    print(f"Закрытый ключ (для подписи): {d},{n}")
    print("============================\n")


def verify_signature():
    print("\n=== Проверка подписи ===")
    M = input("Введите сообщение (M): ").strip()
    Q = int(input("Введите подпись (Q): ").strip())
    e, n = map(int, input("Введите открытый ключ (e,n): ").split(','))

    # Вычисляем хэш сообщения
    H_M = hash_message(M)
    H_int = int(H_M, 2)

    # Проверяем подпись: H(M) == (Q^e mod n)
    decrypted_hash = mod_pow(Q, e, n)

    print(f"\nВычисленный хэш (H(M)) = {H_int}")
    print(f"Расшифрованная подпись (Q^e mod n) = {decrypted_hash}")

    if H_int == decrypted_hash:
        print("\n✅ Подпись ВЕРНА — сообщение не изменено.")
    else:
        print("\n❌ Подпись НЕВЕРНА — сообщение подделано или неверный ключ.")


def main():
    print("=== Консольное приложение ЭЦП ===")

    while True:
        print("\nВыберите действие:")
        print("1 - Подписать сообщение")
        print("2 - Проверить подпись")
        print("3 - Выход")

        choice = input("Ваш выбор: ").strip()

        if choice == '1':
            sign_message()
        elif choice == '2':
            verify_signature()
        elif choice == '3':
            print("Выход из программы.")
            sys.exit(0)
        else:
            print("Неверный выбор, попробуйте снова.")


if __name__ == "__main__":
    main()
