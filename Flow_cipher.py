import random
import sys

def detect_key_format(key_str: str) -> str:
    key_str = key_str.strip()
    if all(c in '01' for c in key_str):  # только 0 и 1
        return "binary"
    elif key_str.isdigit():  # десятичное число
        return "decimal"
    elif key_str.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in key_str):
        return "hex"
    else:
        return "text"

def to_binary(key_str: str) -> str:
    fmt = detect_key_format(key_str)
    if fmt == "binary":
        return key_str
    elif fmt == "decimal":
        return bin(int(key_str))[2:]
    elif fmt == "hex":
        return bin(int(key_str, 16))[2:]
    else:  # текст
        return ''.join(format(ord(ch), '08b') for ch in key_str)

def generate_taps(length: int, num_taps: int = 3) -> list:
    positions = list(range(length))
    return random.sample(positions, min(num_taps, length))

def stream_encrypt(plaintext: str, key: str, taps: list) -> str:
    cipher = []
    key_bits = list(key)

    for bit in plaintext:
        xor_val = 0
        for pos in taps:
            xor_val ^= int(key_bits[pos])
        
        key_bit = xor_val

        cipher_bit = str(int(bit) ^ key_bit)
        cipher.append(cipher_bit)

        key_bits = [str(key_bit)] + key_bits[:-1]

    return ''.join(cipher)

def stream_decrypt(ciphertext: str, key: str, taps: list) -> str:
    return stream_encrypt(ciphertext, key, taps)

def text_to_bits(text: str) -> str:
    return ''.join(format(ord(ch), '08b') for ch in text)

def bits_to_text(bits: str) -> str:
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def main():
    while True:
        print("\nВыберите действие:")
        print("1 - Зашифровать")
        print("2 - Расшифровать")
        print("3 - Выход")

        choice = input("Ваш выбор: ").strip()
        
        if choice == "1":
            key_str = input("Введите ключ (текст, число, hex или двоичный): ")
            key_bin = to_binary(key_str)

            taps = generate_taps(len(key_bin))
            print(f"Опорные позиции (taps): {taps}")

            text = input("Введите текст для шифрования: ")
            plaintext = text_to_bits(text)

            cipher = stream_encrypt(plaintext, key_bin, taps)
            print("Зашифрованные биты:", cipher)
            print("Шифротекст (в hex):", hex(int(cipher, 2))[2:])

        elif choice == "2":
            key_str = input("Введите ключ (текст, число, hex или двоичный): ")
            key_bin = to_binary(key_str)

            taps_str = input("Введите опорные позиции (через запятую): ")
            taps = list(map(int, taps_str.split(",")))

            cipher = input("Введите шифротекст (в битах): ").strip()

            decrypted_bits = stream_decrypt(cipher, key_bin, taps)
            decrypted_text = bits_to_text(decrypted_bits)

            print("Расшифрованные биты:", decrypted_bits)
            print("Расшифрованный текст:", decrypted_text)

        elif choice == "3":
            print("Выход из программы.")
            sys.exit(0)
        else:
            print("Неверный ввод, попробуйте снова.")

if __name__ == "__main__":
    main()
