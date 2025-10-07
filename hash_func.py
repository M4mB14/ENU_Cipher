from typing import Tuple
import sys
import re

def to_bits_int(x: int, width: int) -> str:
    return format(x, f'0{width}b')

def from_bits(bstr: str) -> int:
    return int(bstr, 2)

def bytes_to_bits(b: bytes) -> str:
    return ''.join(format(byte, '08b') for byte in b)

def chunk_bits(bitstr: str, n: int):
    for i in range(0, len(bitstr), n):
        yield bitstr[i:i+n]

SBOX = {
    "00": "10",
    "01": "00",
    "10": "11",
    "11": "01"
}

def sbox_substitution(bits4: str) -> str:
    pairs = [bits4[0:2], bits4[2:4]]
    out_pairs = [SBOX[p] for p in pairs]
    return ''.join(out_pairs)

def permutation(bits4: str) -> str:
    return bits4[1] + bits4[0] + bits4[3] + bits4[2]

def round_encrypt(bits4: str, key4: str, last_round: bool=False) -> str:
    xor_res = format(int(bits4,2) ^ int(key4,2), '04b')
    s_out = sbox_substitution(xor_res)
    if last_round:
        return s_out
    return permutation(s_out)

def spn_encrypt_8bit(P: int, K: int) -> int:
    p_bits = format(P, '08b')
    k_bits = format(K, '08b')
    P1, P2 = p_bits[:4], p_bits[4:]
    K1, K2 = k_bits[:4], k_bits[4:]
    C1 = round_encrypt(P1, K1, last_round=False)
    C2 = round_encrypt(C1, K2, last_round=True)
    C3 = round_encrypt(P2, K1, last_round=False)
    C4 = round_encrypt(C3, K2, last_round=True)
    ciphertext_bits = C2 + C4
    return int(ciphertext_bits, 2)

def compress32(state32: str, block32: str, verbose: bool=False) -> str:
    assert len(state32) == 32 and len(block32) == 32
    out_bytes = []
    for i, (s_chunk, b_chunk) in enumerate(zip(chunk_bits(state32, 8), chunk_bits(block32, 8))):
        s_int = int(s_chunk, 2)
        b_int = int(b_chunk, 2)
        out_int = spn_encrypt_8bit(s_int, b_int)
        out_bytes.append(format(out_int, '08b'))
    tmp = ''.join(out_bytes)
    new_state_int = int(tmp, 2) ^ int(state32, 2) ^ int(block32, 2)
    new_state = format(new_state_int, '032b')
    return new_state

def parse_plaintext_to_bits(s: str) -> str:
    s = s.strip()
    if re.fullmatch(r'[01]+', s):
        return s
    if s.lower().startswith('0x'):
        hexpart = s[2:]
        if len(hexpart) == 0:
            return ''
        if len(hexpart) % 2 != 0:
            hexpart = '0' + hexpart
        b = bytes.fromhex(hexpart)
        return bytes_to_bits(b)
    if re.fullmatch(r'[0-9a-fA-F]+', s) and re.search(r'[a-fA-F]', s):
        hexpart = s
        if len(hexpart) % 2 != 0:
            hexpart = '0' + hexpart
        b = bytes.fromhex(hexpart)
        return bytes_to_bits(b)
    if re.fullmatch(r'\d+', s):
        val = int(s, 10)
        return format(val, 'b') if val != 0 else '0'
    b = s.encode('utf-8')
    return bytes_to_bits(b)

# === Фиксированный IV ===
FIXED_IV = "11110000010101010000111111000000"  # 32 бита

def run_interactive():
    print("=== Hashervon (интерактивное хэширование) ===")
    print(f"Фиксированный IV: {FIXED_IV} (0x{format(int(FIXED_IV,2),'08x')})")

    while True:
        print("\nВыберите действие:")
        print(" 1 - Захэшировать текст")
        print(" 2 - Выйти")
        choice = input("Введите 1/2: ").strip()

        if choice == '1':
            plain_in = input("Введите открытый текст (текст / DEC / 0xHEX / бинарно): ")
            bits = parse_plaintext_to_bits(plain_in)
            if bits == '':
                print("Пустой ввод — ничего хешировать.")
                continue
            blocks = list(chunk_bits(bits, 32))
            if len(blocks) == 0:
                blocks = ['0'*32]
            if len(blocks[-1]) < 32:
                blocks[-1] = blocks[-1].ljust(32, '0')
            print(f"Исходные биты (len={len(bits)}): {bits}")
            print(f"Количество 32-бит блоков: {len(blocks)}")

            state = FIXED_IV
            for idx, blk in enumerate(blocks, start=1):
                print(f"\n--- Блок {idx}/{len(blocks)} ---")
                print(f" block = {blk} (0x{format(int(blk,2),'08x')})")
                print(f" state = {state} (0x{format(int(state,2),'08x')})")
                state = compress32(state, blk, verbose=True)
                print(f" new state = {state} (0x{format(int(state,2),'08x')})")

            print("\n=== Хэширование завершено ===")
            print(f"IV (фиксированный): {FIXED_IV}  (0x{format(int(FIXED_IV,2),'08x')})")
            print(f"Final hash (bin):  {state}")
            print(f"Final hash (hex):  0x{format(int(state,2),'08x')}")

        elif choice == '2':
            print("Выход. Пока.")
            sys.exit(0)
        else:
            print("Неправильный выбор, введите 1 или 2.")

if __name__ == '__main__':
    try:
        run_interactive()
    except KeyboardInterrupt:
        print("\nПрервано пользователем. Выход.")
        sys.exit(0)
