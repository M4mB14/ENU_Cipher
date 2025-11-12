from cipher_function import (
    generate_key,
    generate_round_keys,
    pkcs7_pad,
    pkcs7_unpad,
    bits_to_hex,
    hex_to_bits,
    bits_to_text,
    text_to_bits,
    feistel_encrypt_block,
    feistel_decrypt_block,
    xor_bits
)


# --- Шифрование одного блока ---
def encrypt_block(block_bits, round_keys):
    return feistel_encrypt_block(block_bits, round_keys)

# --- Основные функции ECB ---
def encrypt_ecb(plaintext_bits, key_bits):
    round_keys = generate_round_keys(key_bits, num_rounds=10, round_key_size=256)
    padded = pkcs7_pad(plaintext_bits, 512)
    ciphertext_bits = ''
    for i in range(0, len(padded), 512):
        block = padded[i:i + 512]
        ciphertext_bits += encrypt_block(block, round_keys)
    return ciphertext_bits

def decrypt_ecb(ciphertext_bits, key_bits):
    round_keys = generate_round_keys(key_bits, num_rounds=10, round_key_size=256)
    plain_padded = ''
    for i in range(0, len(ciphertext_bits), 512):
        block = ciphertext_bits[i:i + 512]
        if len(block) < 512:
            block = block.ljust(512, '0')
        plain_padded += feistel_decrypt_block(block, round_keys)
    return pkcs7_unpad(plain_padded)

# --- CBC режим ---
def encrypt_cbc(plaintext_bits, key_bits, iv_bits):
    round_keys = generate_round_keys(key_bits, num_rounds=10, round_key_size=256)
    padded = pkcs7_pad(plaintext_bits, 512)
    ciphertext_bits = ''
    prev_block = iv_bits
    for i in range(0, len(padded), 512):
        block = padded[i:i + 512]
        xored = xor_bits(block, prev_block)
        enc_block = encrypt_block(xored, round_keys)
        ciphertext_bits += enc_block
        prev_block = enc_block
    return ciphertext_bits

def decrypt_cbc(ciphertext_bits, key_bits, iv_bits):
    round_keys = generate_round_keys(key_bits, num_rounds=10, round_key_size=256)
    plain_padded = ''
    prev_block = iv_bits
    for i in range(0, len(ciphertext_bits), 512):
        block = ciphertext_bits[i:i + 512]
        if len(block) < 512:
            block = block.ljust(512, '0')
        dec_block = feistel_decrypt_block(block, round_keys)
        plain_padded += xor_bits(dec_block, prev_block)
        prev_block = block
    return pkcs7_unpad(plain_padded)

# --- Консольное меню ---
def main():
    while True:
        print("\nМеню:")
        print("1 - Зашифровать")
        print("2 - Расшифровать")
        print("3 - Выход")
        choice = input("Ваш выбор: ")

        if choice == "1":
            key_bits = generate_key(512)
            key_hex = bits_to_hex(key_bits)
            print(f"\nСгенерирован ключ (512 бит = {len(key_hex) * 4} бит в HEX):\n{key_hex}\n")

            mode = input("Выберите режим (ECB/CBC): ").strip().upper()
            if mode not in ["ECB", "CBC"]:
                print("Ошибка: допустимые режимы — ECB или CBC.")
                continue

            plaintext = input("Введите открытый текст: ")
            bits = text_to_bits(plaintext)

            if mode == "ECB":
                cipher_bits = encrypt_ecb(bits, key_bits)
                iv_hex = None
            else:
                iv_bits = generate_key(512)
                iv_hex = bits_to_hex(iv_bits)
                cipher_bits = encrypt_cbc(bits, key_bits, iv_bits)

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

            if len(key_bits) != 512:
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
                plain_bits = decrypt_cbc(cipher_bits, key_bits, iv_bits)
            else:
                plain_bits = decrypt_ecb(cipher_bits, key_bits)

            print("\nРасшифрованный текст:")
            print(bits_to_text(plain_bits))

        elif choice == "3":
            print("Выход.")
            break
        else:
            print("Неверный выбор.")

if __name__ == "__main__":
    main()
