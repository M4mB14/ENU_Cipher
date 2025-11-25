import sys
from cipher_function import (
    bits_to_hex, 
    hex_to_bits, 
    bits_to_text, 
    text_to_bits,
    generate_key,
    init_registers,
    Flow_encrypt_decrypt
)


def a5_process(text: str, key_bits: str) -> str:
    plaintext_bits = text_to_bits(text)
    R1, R2, R3 = init_registers(key_bits)
    ks = Flow_encrypt_decrypt(R1, R2, R3, len(plaintext_bits))
    cipher_bits = ''.join(str(int(b) ^ int(k)) for b, k in zip(plaintext_bits, ks))
    return cipher_bits

def main():
    while True:
        print("\nВыберите действие:")
        print("1 - Зашифровать")
        print("2 - Расшифровать")
        print("3 - Выход")
        choice = input("Ваш выбор: ").strip()

        if choice == "1":
            key_bits = generate_key(256)
            key_hex = bits_to_hex(key_bits)
            print(f"Сгенерированный ключ (hex): {key_hex}")

            text = input("Введите текст для шифрования: ")
            cipher_bits = a5_process(text, key_bits)
            cipher_hex = bits_to_hex(cipher_bits)
            print(f"Шифртекст (hex): {cipher_hex}")

        elif choice == "2":
            key_hex = input("Введите ключ (hex): ").strip()
            cipher_hex = input("Введите шифртекст (hex): ").strip()

            key_bits = hex_to_bits(key_hex).zfill(256)
            cipher_bits = hex_to_bits(cipher_hex)
            n_bits = len(cipher_bits)
            R1, R2, R3 = init_registers(key_bits)
            ks = Flow_encrypt_decrypt(R1, R2, R3, n_bits)
            plaintext_bits = ''.join(str(int(c) ^ int(k)) for c, k in zip(cipher_bits, ks))
            plaintext = bits_to_text(plaintext_bits)
            print(f"Расшифрованный текст: {plaintext}")

        elif choice == "3":
            print("Выход.")
            sys.exit(0)
        else:
            print("Неверный выбор, попробуйте снова.")

if __name__ == "__main__":
    main()
