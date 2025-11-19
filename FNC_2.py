from cipher_function import (
    generate_key,
    bits_to_hex,
    hex_to_bits,
    bits_to_text,
    text_to_bits,
    fnc_encrypt_cbc,
    fnc_encrypt_ecb,
    fnc_decrypt_cbc,
    fnc_decrypt_ecb
)


# --- Консольное меню ---
def main():
    while True:
        print("\nМеню:")
        print("1 - Зашифровать")
        print("2 - Расшифровать")
        print("3 - Выход")
        choice = input("Ваш выбор: ")

        if choice == "1":
            key_bits = generate_key(256)
            key_hex = bits_to_hex(key_bits)
            print(f"\nСгенерирован ключ (512 бит = {len(key_hex) * 4} бит в HEX):\n{key_hex}\n")

            mode = input("Выберите режим (ECB/CBC): ").strip().upper()
            if mode not in ["ECB", "CBC"]:
                print("Ошибка: допустимые режимы — ECB или CBC.")
                continue

            plaintext = input("Введите открытый текст: ")
            bits = text_to_bits(plaintext)

            if mode == "ECB":
                cipher_bits = fnc_encrypt_ecb(bits, key_bits)
                iv_hex = None
            else:
                iv_bits = generate_key(512)
                iv_hex = bits_to_hex(iv_bits)
                cipher_bits = fnc_encrypt_cbc(bits, key_bits, iv_bits)

            cipher_hex = bits_to_hex(cipher_bits)
            print("\nЗашифрованный текст (HEX):")
            print(cipher_hex)
            if iv_hex:
                print("\nIV (HEX):")
                print(iv_hex)

        elif choice == "2":
            key_hex = input("Введите ключ (в HEX): ").strip()
            try:
                key_bits = hex_to_bits(key_hex)
            except ValueError:
                print("Ошибка: некорректный HEX ключ.")
                continue

            if len(key_bits) != 256:
                print("Ошибка: ключ должен быть 512 бит (128 HEX-символов).")
                continue

            mode = input("Введите режим (ECB/CBC): ").strip().upper()
            if mode not in ["ECB", "CBC"]:
                print("Ошибка: допустимые режимы — ECB или CBC.")
                continue

            cipher_hex = input("Введите шифртекст (в HEX): ").strip()
            try:
                cipher_bits = hex_to_bits(cipher_hex)
            except ValueError:
                print("Ошибка: некорректный HEX шифртекст.")
                continue

            if mode == "CBC":
                iv_hex = input("Введите IV (в HEX): ").strip()
                try:
                    iv_bits = hex_to_bits(iv_hex)
                except ValueError:
                    print("Ошибка: некорректный IV.")
                    continue
                if len(iv_bits) != 512:
                    print("Ошибка: IV должен быть 512 бит.")
                    continue
                plain_bits = fnc_decrypt_cbc(cipher_bits, key_bits, iv_bits)
            else:
                plain_bits = fnc_decrypt_ecb(cipher_bits, key_bits)

            print("\nРасшифрованный текст:")
            print(bits_to_text(plain_bits))

        elif choice == "3":
            print("Выход.")
            break
        else:
            print("Неверный выбор.")

if __name__ == "__main__":
    main()
