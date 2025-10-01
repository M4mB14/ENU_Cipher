def to_bits(x, width=8):
    return format(x, f'0{width}b')

def from_bits(bstr):
    return int(bstr, 2)

# --- S-box ---
SBOX = {
    "00": "10",
    "01": "00",
    "10": "11",
    "11": "01"
}

def sbox_substitution(bits4):
    pairs = [bits4[0:2], bits4[2:4]]
    out = []
    for p in pairs:
        out.append(SBOX[p])
    return ''.join(out)

def permutation(bits4):
    return bits4[1] + bits4[0] + bits4[3] + bits4[2]

def f_function(L4, K4):
    xor_res = format(int(L4, 2) ^ int(K4, 2), '04b')
    s_out = sbox_substitution(xor_res)
    return permutation(s_out)

def feistel_round_apply(L4, R4, K4):
    f_out = f_function(L4, K4)
    new_L = format(int(f_out, 2) ^ int(R4, 2), '04b')
    new_R = L4
    return new_L, new_R

def feistel_round_unapply(L_cur, R_cur, K4):
    prev_L = R_cur
    f_out = f_function(prev_L, K4)
    prev_R = format(int(f_out, 2) ^ int(L_cur, 2), '04b')
    return prev_L, prev_R

def encrypt_half(byte8_bits, subkeys):
    L, R = byte8_bits[:4], byte8_bits[4:]
    for k in subkeys:
        L, R = feistel_round_apply(L, R, k)
    return L + R

def decrypt_half(byte8_bits, subkeys):
    L, R = byte8_bits[:4], byte8_bits[4:]
    for k in reversed(subkeys):
        L, R = feistel_round_unapply(L, R, k)
    return L + R

def encrypt_16bit_block(block16_int, key_bits_str):
    block_bits = to_bits(block16_int, 16)
    left8, right8 = block_bits[:8], block_bits[8:]
    subkeys = [key_bits_str[i:i+4] for i in range(0, len(key_bits_str), 4)]
    enc_left = encrypt_half(left8, subkeys)
    enc_right = encrypt_half(right8, subkeys)
    return enc_left + enc_right

def decrypt_16bit_block(cipher16_bits_str, key_bits_str):
    left8, right8 = cipher16_bits_str[:8], cipher16_bits_str[8:]
    subkeys = [key_bits_str[i:i+4] for i in range(0, len(key_bits_str), 4)]
    dec_right = decrypt_half(right8, subkeys)
    dec_left = decrypt_half(left8, subkeys)
    return dec_left + dec_right

def detect_and_convert_to_bits(user_input):
    if all(ch in '01' for ch in user_input):
        return user_input
    if user_input.isdigit():
        val = int(user_input)
        return format(val, 'b')
    bits = ''.join(format(ord(c), '08b') for c in user_input)
    return bits

def bits_to_text(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            continue
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def pad_bits(bits, block_size=16):
    if len(bits) % block_size != 0:
        bits += '0' * (block_size - len(bits) % block_size)
    return bits

def main():
    while True:
        print("\nМеню:")
        print("1 - Зашифровать")
        print("2 - Расшифровать")
        print("3 - Выход")
        choice = input("Ваш выбор: ")

        if choice == "1":
            key = input("Введите ключ (12 бит, строка из 0 и 1): ")
            if len(key) != 12 or not all(c in '01' for c in key):
                print("Ключ должен быть длиной 12 бит (только 0/1).")
                continue
            plaintext = input("Введите открытый текст (бинарный, десятичный или обычный): ")
            bits = detect_and_convert_to_bits(plaintext)
            bits = pad_bits(bits, 16)

            cipher_bits = ""
            for i in range(0, len(bits), 16):
                block = bits[i:i+16]
                block_int = int(block, 2)
                enc_block = encrypt_16bit_block(block_int, key)
                cipher_bits += enc_block

            print("Зашифрованный текст (биты):", cipher_bits)

        elif choice == "2":
            key = input("Введите ключ (12 бит, строка из 0 и 1): ")
            if len(key) != 12 or not all(c in '01' for c in key):
                print("Ключ должен быть длиной 12 бит (только 0/1).")
                continue
            cipher_bits = input("Введите шифртекст (в битах): ")
            if not all(c in '01' for c in cipher_bits):
                print("Шифртекст должен быть в двоичном виде.")
                continue
            cipher_bits = pad_bits(cipher_bits, 16)

            plain_bits = ""
            for i in range(0, len(cipher_bits), 16):
                block = cipher_bits[i:i+16]
                dec_block = decrypt_16bit_block(block, key)
                plain_bits += dec_block

            print("Расшифрованные биты:", plain_bits)
            print("Как текст:", bits_to_text(plain_bits))

        elif choice == "3":
            print("Выход.")
            break
        else:
            print("Неверный выбор.")

if __name__ == "__main__":
    main()
