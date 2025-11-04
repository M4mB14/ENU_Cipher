import sys
from rsa import encrypt, decrypt
from hash_func import parse_plaintext_to_bits, compress256, FIXED_IV_BITS, chunk_bits


def hash_message(message: str) -> str:
    """
    Возвращает хеш сообщения в виде hex-строки (как в вашем примере).
    Внутри — возвращаем бинарное состояние (256 бит) и преобразуем в hex.
    """
    bits = parse_plaintext_to_bits(message)
    blocks = list(chunk_bits(bits, 256))
    if len(blocks) == 0:
        blocks = ['0' * 256]
    if len(blocks[-1]) < 256:
        blocks[-1] = blocks[-1].ljust(256, '0')
    state = FIXED_IV_BITS
    for blk in blocks:
        state = compress256(state, blk)
    H_int = int(state, 2)
    H_hex = format(H_int, '064x')
    return H_hex


def sign_with_private_hash_as_text(d, n, message):
    H_hex = hash_message(message)
    Q_hex = encrypt(H_hex, d, n)
    return H_hex, Q_hex

def verify_signature_with_public_hash_as_text(e, n, message, Q_hex):
    expected_hash = hash_message(message)
    try:
        decrypted = decrypt(Q_hex, e, n)
    except Exception as ex:
        raise RuntimeError(f"Ошибка при расшифровке подписи: {ex}")

    is_valid = (expected_hash.lower() == decrypted.lower())
    return is_valid, expected_hash, decrypted

# -------------------- Консольное меню --------------------

def main_menu():
    print("=== RSA ЭЦП (подпись: шифрование хеша закрытым ключом как текста) ===")
    keys = None

    while True:
        print("\nВыберите действие:")
        print("1 - Подписать сообщение (использует последние сгенерированные ключи или попросит ввести dn,n)")
        print("2 - Проверить подпись (введите public key en,n и Q hex)")
        print("3 - Выход")
        choice = input("Ваш выбор: ").strip()

        if choice == '1':
            message = input("Введите сообщение (M): ").strip()
            d, n = map(int, input("Введите закрытый ключ (d,n): ").split(','))

            H_hex, Q_hex = sign_with_private_hash_as_text(d, n, message)
            print("\n--- Подпись создана ---")
            print(f"H(M) (hex) = {H_hex}")
            print(f"Q (signature, hex) = {Q_hex}")

        elif choice == '2':
            message = input("Введите сообщение (M): ").strip()
            Q_hex = input("Введите подпись Q (hex): ").strip()
            e_n_input = input("Введите открытый ключ (e,n) через запятую: ").strip()
            try:
                e, n = map(int, e_n_input.split(','))
            except Exception:
                print("Неверный формат ключа, ожидалось 'e,n' (целые).")
                continue
            try:
                valid, expected_hash, decrypted_hash = verify_signature_with_public_hash_as_text(e, n, message, Q_hex)
            except RuntimeError as ex:
                print(str(ex))
                continue

            print(f"\nВычисленный H(M) = {expected_hash}")
            print(f"Дешифрованное из Q = {decrypted_hash}")
            if valid:
                print("\n Подпись ВЕРНА — хеш совпадает.")
            else:
                print("\n Подпись НЕВЕРНА — хеш не совпадает.")

        elif choice == '3':
            print("Выход.")
            sys.exit(0)
        else:
            print("Неверный выбор, попробуйте снова.")

if __name__ == "__main__":
    main_menu()
