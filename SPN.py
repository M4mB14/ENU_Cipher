from  cipher_function import (
    generate_key,
    generate_iv,
    generate_round_keys,
    bits_to_hex,
    bits_to_text,
    ecb_decrypt,
    ecb_encrypt,
    cbc_encrypt,
    cbc_decrypt,
    detect_and_convert_to_bits,
    pkcs7_pad,
    pkcs7_unpad,
    hex_to_bits)


def main():
    while True:
        print("\nМеню:")
        print("1 - Зашифровать")
        print("2 - Расшифровать")
        print("3 - Выход")

        choice = input("Ваш выбор: ")

        if choice in ["1", "2"]:
            print("\nВыберите режим:")
            print("1 - ECB")
            print("2 - CBC")
            mode = input("Режим: ")

            key_256 = generate_key(256)
            key_hex = bits_to_hex(key_256)
            round_keys = generate_round_keys(key_256, 10)

            if choice == "1":
                plaintext = input("\nВведите открытый текст: ")
                bits = detect_and_convert_to_bits(plaintext)
                bits = pkcs7_pad(bits, 512)

                if mode == "1":
                    cipher_bits = ecb_encrypt(bits, round_keys)
                    print("\nРежим: ECB")
                else:
                    iv = generate_iv(128)
                    iv_hex = bits_to_hex(iv)
                    print(f"\nРежим: CBC\nIV (HEX): {iv_hex}")
                    cipher_bits = cbc_encrypt(bits, round_keys, iv)

                cipher_hex = bits_to_hex(cipher_bits)
                print(f"\nКлюч (HEX): {key_hex}")
                print("\nЗашифрованный текст (HEX):")
                print(cipher_hex)

            elif choice == "2":
                key_hex = input("\nВведите ключ (HEX): ")
                key_bits = hex_to_bits(key_hex)
                round_keys = generate_round_keys(key_bits, 10)

                cipher_hex = input("Введите зашифрованный текст (HEX): ")
                cipher_bits = hex_to_bits(cipher_hex)

                if mode == "1":
                    decrypted_bits = ecb_decrypt(cipher_bits, round_keys)
                    print("\nРежим: ECB")
                else:
                    iv_hex = input("Введите IV (HEX): ")
                    iv_bits = hex_to_bits(iv_hex)
                    decrypted_bits = cbc_decrypt(cipher_bits, round_keys, iv_bits)
                    print("\nРежим: CBC")

                unpadded_bits = pkcs7_unpad(decrypted_bits)
                decrypted_text = bits_to_text(unpadded_bits)
                print("\nРасшифрованный текст:")
                print(decrypted_text.strip('\x00'))

        elif choice == "3":
            print("Выход.")
            break
        else:
            print("Неверный выбор.")

if __name__ == "__main__":
    main()
