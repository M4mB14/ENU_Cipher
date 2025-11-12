import random

SBOX_HEX = {
    0x0: 0x8, 0x1: 0x3, 0x2: 0x7, 0x3: 0x0,
    0x4: 0x1, 0x5: 0xA, 0x6: 0x5, 0x7: 0xF,
    0x8: 0x2, 0x9: 0x4, 0xA: 0xD, 0xB: 0x6,
    0xC: 0x9, 0xD: 0xB, 0xE: 0xC, 0xF: 0xE
}
INV_SBOX_HEX = {v: k for k, v in SBOX_HEX.items()}

DEFAULT_PBOX_MAP_16 = {
    1: 12, 2: 3, 3: 9, 4: 14,
    5: 1, 6: 7, 7: 15, 8: 4,
    9: 10, 10: 16, 11: 8, 12: 2,
    13: 13, 14: 6, 15: 11, 16: 5
}

def generate_key(bits=256):
    return ''.join(random.choice('01') for _ in range(bits))

def generate_iv(bits=128):
    return ''.join(random.choice('01') for _ in range(bits))

def bits_to_hex(bits):
    return hex(int(bits, 2))[2:].upper().zfill(len(bits) // 4)

def hex_to_bits(hex_str):
    return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)

def bits_to_text(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def detect_and_convert_to_bits(user_input):
    if all(ch in '01' for ch in user_input):
        return user_input
    if all(ch in '0123456789ABCDEFabcdef' for ch in user_input):
        return hex_to_bits(user_input)
    return ''.join(format(ord(c), '08b') for c in user_input)

def sbox_substitution_4bit(bits, inverse=False):
    out_bits = ""
    table = INV_SBOX_HEX if inverse else SBOX_HEX
    for i in range(0, len(bits), 4):
        nibble = bits[i:i + 4]
        if len(nibble) < 4:
            nibble = nibble.ljust(4, '0')
        val = int(nibble, 2)
        sub_val = table[val]
        out_bits += format(sub_val, '04b')
    return out_bits

def make_identity_pbox_map(n_bits):
    return {i + 1: i + 1 for i in range(n_bits)}

def pbox_permutation(bits, inverse=False, pbox_map=None, chunk_size=16):
    if pbox_map is None:
        if chunk_size == 16:
            table = {k: v for k, v in DEFAULT_PBOX_MAP_16.items()}
        else:
            table = make_identity_pbox_map(chunk_size)
    else:
        table = {v: k for k, v in pbox_map.items()} if inverse else pbox_map
    out_bits = ""
    for i in range(0, len(bits), chunk_size):
        block = bits[i:i + chunk_size]
        if len(block) < chunk_size:
            block = block.ljust(chunk_size, '0')
        permuted = ['0'] * chunk_size
        for src, dest in table.items():
            if 1 <= src <= len(block) and 1 <= dest <= chunk_size:
                permuted[dest - 1] = block[src - 1]
        out_bits += ''.join(permuted)
    return out_bits

def xor_bits(bits1, bits2):
    return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))

def split_into_blocks(bin_text, block_size=512):
    return [bin_text[i:i + block_size] for i in range(0, len(bin_text), block_size)]

def pkcs7_pad(bits, block_size_bits=512):
    if block_size_bits % 8 != 0:
        raise ValueError("block_size_bits must be multiple of 8")
    byte_len = len(bits) // 8
    block_size_bytes = block_size_bits // 8
    padding_len = block_size_bytes - (byte_len % block_size_bytes)
    if padding_len == 0:
        padding_len = block_size_bytes
    padding_byte = format(padding_len, '08b')
    padded_bits = bits + padding_byte * padding_len
    return padded_bits

def pkcs7_unpad(bits):
    if len(bits) % 8 != 0:
        return bits
    last_byte = bits[-8:]
    pad_val = int(last_byte, 2)
    if pad_val <= 0 or pad_val > (len(bits) // 8):
        return bits
    return bits[:-(pad_val * 8)]

def generate_round_keys(key_bits, num_rounds=10, round_key_size=128):
    if len(key_bits) < 2:
        raise ValueError("key_bits too short")
    half = len(key_bits) // 2
    K1, K2 = key_bits[:half], key_bits[half:]
    seed = int(K1, 2) ^ int(K2, 2)
    round_keys = []
    a = 1664525
    c = 1013904223
    m = 2 ** 32
    for i in range(num_rounds):
        seed = (a * (seed + i) + c) % m
        key_bits_n = ""
        local_seed = seed
        words = (round_key_size + 31) // 32
        for _ in range(words):
            local_seed = (a * local_seed + c) % m
            key_bits_n += format(local_seed, '032b')
        key_bits_n = key_bits_n[:round_key_size]
        round_keys.append(key_bits_n)
    return round_keys

# --- Функция F ---
def f_function(right_half, round_key):
    mixed = xor_bits(right_half, round_key)
    substituted = sbox_substitution_4bit(mixed)
    permuted = pbox_permutation(substituted)
    return permuted

# --- Один раунд сети Фейстеля ---
def feistel_round(L, R, round_key):
    new_L = R
    f_out = f_function(R, round_key)
    new_R = xor_bits(L, f_out)
    return new_L, new_R

# --- Обратный раунд ---
def feistel_round_unapply(L_cur, R_cur, round_key):
    prev_R = L_cur
    f_out = f_function(prev_R, round_key)
    prev_L = xor_bits(R_cur, f_out)
    return prev_L, prev_R

# --- Шифрование блока (512 бит) ---
def feistel_encrypt_block(block_bits, round_keys):
    L, R = block_bits[:256], block_bits[256:]
    for k in round_keys:
        L, R = feistel_round(L, R, k)
    return L + R

# --- Расшифрование блока ---
def feistel_decrypt_block(block_bits, round_keys):
    L, R = block_bits[:256], block_bits[256:]
    for k in reversed(round_keys):
        L, R = feistel_round_unapply(L, R, k)
    return L + R

def spn_encrypt_block(plaintext_bits, round_keys, round_key_size=128, pbox_map=None):
    chunk = round_key_size
    blocks = [plaintext_bits[i:i + chunk] for i in range(0, len(plaintext_bits), chunk)]
    for round_key in round_keys:
        new_blocks = []
        for block in blocks:
            if len(block) < chunk:
                block = block.ljust(chunk, '0')
            xor_out = xor_bits(block, round_key[:len(block)])
            sbox_out = sbox_substitution_4bit(xor_out)
            pbox_out = pbox_permutation(sbox_out, inverse=False, pbox_map=pbox_map, chunk_size=len(block))
            new_blocks.append(pbox_out)
        blocks = new_blocks
    return ''.join(blocks)

def spn_decrypt_block(cipher_bits, round_keys, round_key_size=128, pbox_map=None):
    chunk = round_key_size
    blocks = [cipher_bits[i:i + chunk] for i in range(0, len(cipher_bits), chunk)]
    for round_key in reversed(round_keys):
        new_blocks = []
        for block in blocks:
            if len(block) < chunk:
                block = block.ljust(chunk, '0')
            pbox_inv = pbox_permutation(block, inverse=True, pbox_map=pbox_map, chunk_size=len(block))
            sbox_inv = sbox_substitution_4bit(pbox_inv, inverse=True)
            xor_out = xor_bits(sbox_inv, round_key[:len(block)])
            new_blocks.append(xor_out)
        blocks = new_blocks
    return ''.join(blocks)

def ecb_encrypt(plaintext_bits, round_keys, block_size_bits=512, round_key_size=128, pbox_map=None):
    blocks = split_into_blocks(plaintext_bits, block_size_bits)
    ciphertext = ""
    for block in blocks:
        if len(block) < block_size_bits:
            block = block.ljust(block_size_bits, '0')
        ciphertext += spn_encrypt_block(block, round_keys, round_key_size=round_key_size, pbox_map=pbox_map)
    return ciphertext

def ecb_decrypt(cipher_bits, round_keys, block_size_bits=512, round_key_size=128, pbox_map=None):
    blocks = split_into_blocks(cipher_bits, block_size_bits)
    plaintext = ""
    for block in blocks:
        if len(block) < block_size_bits:
            block = block.ljust(block_size_bits, '0')
        plaintext += spn_decrypt_block(block, round_keys, round_key_size=round_key_size, pbox_map=pbox_map)
    return plaintext

def cbc_encrypt(plaintext_bits, round_keys, iv, block_size_bits=512, round_key_size=128, pbox_map=None):
    blocks = split_into_blocks(plaintext_bits, block_size_bits)
    prev = iv.zfill(block_size_bits)
    ciphertext = ""
    for block in blocks:
        if len(block) < block_size_bits:
            block = block.ljust(block_size_bits, '0')
        xored = xor_bits(block, prev)
        encrypted = spn_encrypt_block(xored, round_keys, round_key_size=round_key_size, pbox_map=pbox_map)
        ciphertext += encrypted
        prev = encrypted
    return ciphertext

def cbc_decrypt(cipher_bits, round_keys, iv, block_size_bits=512, round_key_size=128, pbox_map=None):
    blocks = split_into_blocks(cipher_bits, block_size_bits)
    prev = iv.zfill(block_size_bits)
    plaintext = ""
    for block in blocks:
        if len(block) < block_size_bits:
            block = block.ljust(block_size_bits, '0')
        decrypted = spn_decrypt_block(block, round_keys, round_key_size=round_key_size, pbox_map=pbox_map)
        xored = xor_bits(decrypted, prev)
        plaintext += xored
        prev = block
    return plaintext
