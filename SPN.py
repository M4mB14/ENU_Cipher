def to_bits(x, width=8):
    return format(x, f'0{width}b')

def from_bits(bstr):
    return int(bstr, 2)

SBOX = {
    "00": "10",
    "01": "00",
    "10": "11",
    "11": "01"
}

def sbox_substitution(bits4):
    pairs = [bits4[0:2], bits4[2:4]]
    out_pairs = []
    for p in pairs:
        out_pairs.append(SBOX[p])
    return ''.join(out_pairs)

def permutation(bits4):
    return bits4[1] + bits4[0] + bits4[3] + bits4[2]

def round_encrypt(bits4, key4, last_round=False):
    xor_res = format(int(bits4, 2) ^ int(key4, 2), '04b')
    s_out = sbox_substitution(xor_res)
    if last_round:
        return s_out
    return permutation(s_out)

def spn_encrypt_block(P_bits, K_bits):
    P1, P2 = P_bits[:4], P_bits[4:]
    K1, K2 = K_bits[:4], K_bits[4:]

    C1 = round_encrypt(P1, K1, last_round=False)
    C2 = round_encrypt(C1, K2, last_round=True)
    C3 = round_encrypt(P2, K1, last_round=False)
    C4 = round_encrypt(C3, K2, last_round=True)

    return C2 + C4

def spn_decrypt_block(C_bits, K_bits):
    return spn_encrypt_block(C_bits, K_bits)

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

def pad_bits(bits, block_size=8):
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
            key = input("Введите ключ (8 бит, строка из 0 и 1): ")
            if len(key) != 8 or not all(c in '01' for c in key):
                print("Ключ должен быть длиной 8 бит (только 0/1).")
                continue
            plaintext = input("Введите открытый текст (бинарный, десятичный или обычный): ")
            bits = detect_and_convert_to_bits(plaintext)
            bits = pad_bits(bits, 8)

            cipher_bits = ""
            for i in range(0, len(bits), 8):
                block = bits[i:i+8]
                enc_block = spn_encrypt_block(block, key)
                cipher_bits += enc_block

            print("Зашифрованный текст (биты):", cipher_bits)

        elif choice == "2":
            key = input("Введите ключ (8 бит, строка из 0 и 1): ")
            if len(key) != 8 or not all(c in '01' for c in key):
                print("Ключ должен быть длиной 8 бит (только 0/1).")
                continue
            cipher_bits = input("Введите шифртекст (в битах): ")
            if not all(c in '01' for c in cipher_bits):
                print("Шифртекст должен быть в двоичном виде.")
                continue
            cipher_bits = pad_bits(cipher_bits, 8)

            plain_bits = ""
            for i in range(0, len(cipher_bits), 8):
                block = cipher_bits[i:i+8]
                dec_block = spn_decrypt_block(block, key)
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
