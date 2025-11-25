import random


####################################
####        Constants           ####
####################################

R1_LEN, R2_LEN, R3_LEN = 19, 22, 23
R1_TAPS = [13, 16, 17, 18]
R2_TAPS = [20, 21]
R3_TAPS = [7, 20, 21, 22]
R1_SYNC, R2_SYNC, R3_SYNC = 8, 10, 10
FN = "1100101010110010101011"

####################################
####          Boxes             ####
####################################

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

####################################
####       Generators           ####
####################################

def generate_key(bits=256):
    return ''.join(random.choice('01') for _ in range(bits))

def generate_iv(bits=128):
    return ''.join(random.choice('01') for _ in range(bits))

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

def aes_key_expansion(key_bits, num_rounds=10, round_key_size=128):
    if len(key_bits) not in (128, 192, 256):
        raise ValueError("AES key must be 128, 192, or 256 bits")

    key = [int(key_bits[i:i+8], 2) for i in range(0, len(key_bits), 8)]

    key_size_bits = len(key_bits)
    Nk = key_size_bits // 32      
    Nb = 4                      
    Nr = {128: 10, 192: 12, 256: 14}[key_size_bits]

    if num_rounds != Nr:
        raise ValueError(f"For AES-{key_size_bits}, num_rounds must be {Nr}")

    Rcon = [
        0x00000000,
        0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000,
        0x1B000000, 0x36000000
    ]

    sbox = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    ]


    w = []
    for i in range(Nk):
        word = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3]
        w.append(word)


    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]

        if i % Nk == 0:
            temp = ((temp << 8) & 0xFFFFFFFF) | (temp >> 24)

            temp = (
                (sbox[(temp >> 24) & 0xFF] << 24) |
                (sbox[(temp >> 16) & 0xFF] << 16) |
                (sbox[(temp >> 8) & 0xFF] << 8) |
                (sbox[temp & 0xFF])
            )

            temp ^= Rcon[i // Nk]
        elif Nk > 6 and (i % Nk == 4):  
            temp = (
                (sbox[(temp >> 24) & 0xFF] << 24) |
                (sbox[(temp >> 16) & 0xFF] << 16) |
                (sbox[(temp >> 8) & 0xFF] << 8) |
                (sbox[temp & 0xFF])
            )

        w.append((w[i - Nk] ^ temp) & 0xFFFFFFFF)

    round_keys = []

    for r in range(Nr + 1):
        aes_key = ""
        for i in range(Nb):  
            aes_key += format(w[r * Nb + i], '032b')

        if len(aes_key) < round_key_size:
            repeats = round_key_size // len(aes_key) + 1
            aes_key = (aes_key * repeats)[:round_key_size]
        else:
            aes_key = aes_key[:round_key_size]

        round_keys.append(aes_key)

    return round_keys
    

####################################
####        Utility             ####
####################################

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

def xor_bits(bits1, bits2):
    return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))

def split_into_blocks(bin_text, block_size=512):
    return [bin_text[i:i + block_size] for i in range(0, len(bin_text), block_size)]

####################################
####         Box uses           ####
####################################

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

####################################
####         Padding            ####
####################################

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


####################################
####       Festel Util          ####
####################################

def f_function(right_half, round_key):
    mixed = xor_bits(right_half, round_key)
    substituted = sbox_substitution_4bit(mixed)
    permuted = pbox_permutation(substituted)
    return permuted

def feistel_encrypt_block(block_bits, round_keys):
    L, R = block_bits[:256], block_bits[256:]
    for k in round_keys:
        f_out = f_function(R, k)
        L, R = R, xor_bits(L, f_out)
    return L + R

def feistel_decrypt_block(block_bits, round_keys):
    L, R = block_bits[:256], block_bits[256:]
    for k in reversed(round_keys):
        f_out = f_function(L, k)
        L, R = xor_bits(R, f_out), L
    return L + R

####################################
####        SPN Util            ####
####################################

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

####################################
####    flow_cipher Util        ####
####################################

def lfsr_shift(reg: list, taps: list) -> None:
    new_bit = 0
    for t in taps:
        new_bit ^= reg[t]
    reg.insert(0, new_bit)
    reg.pop()

def majority(a: int, b: int, c: int) -> int:
    return (a & b) | (a & c) | (b & c)

def init_registers(key_bits: str):
    R1 = [0] * R1_LEN
    R2 = [0] * R2_LEN
    R3 = [0] * R3_LEN

    for bit in key_bits:
        b = int(bit)
        R1[0] ^= b
        R2[0] ^= b
        R3[0] ^= b
        lfsr_shift(R1, R1_TAPS)
        lfsr_shift(R2, R2_TAPS)
        lfsr_shift(R3, R3_TAPS)

    for bit in FN:
        b = int(bit)
        R1[0] ^= b
        R2[0] ^= b
        R3[0] ^= b
        lfsr_shift(R1, R1_TAPS)
        lfsr_shift(R2, R2_TAPS)
        lfsr_shift(R3, R3_TAPS)

    for _ in range(100):
        m = majority(R1[R1_SYNC], R2[R2_SYNC], R3[R3_SYNC])
        if R1[R1_SYNC] == m:
            lfsr_shift(R1, R1_TAPS)
        if R2[R2_SYNC] == m:
            lfsr_shift(R2, R2_TAPS)
        if R3[R3_SYNC] == m:
            lfsr_shift(R3, R3_TAPS)

    return R1, R2, R3

def Flow_encrypt_decrypt(R1, R2, R3, n_bits: int):
    stream = []
    for _ in range(n_bits):
        m = majority(R1[R1_SYNC], R2[R2_SYNC], R3[R3_SYNC])
        if R1[R1_SYNC] == m:
            lfsr_shift(R1, R1_TAPS)
        if R2[R2_SYNC] == m:
            lfsr_shift(R2, R2_TAPS)
        if R3[R3_SYNC] == m:
            lfsr_shift(R3, R3_TAPS)

        ks_bit = R1[0] ^ R2[0] ^ R3[0]
        stream.append(ks_bit)
    return ''.join(str(b) for b in stream)

####################################
####        SPN mode's          ####
####################################

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

####################################
####        FNC mode's          ####
####################################

def fnc_encrypt_ecb(plaintext_bits, key_bits):
    round_keys = aes_key_expansion(key_bits, num_rounds=14, round_key_size=256)
    padded = pkcs7_pad(plaintext_bits, 512)
    ciphertext_bits = ''
    for i in range(0, len(padded), 512):
        block = padded[i:i + 512]
        ciphertext_bits += feistel_encrypt_block(block, round_keys)
    return ciphertext_bits

def fnc_decrypt_ecb(ciphertext_bits, key_bits):
    round_keys = aes_key_expansion(key_bits, num_rounds=14, round_key_size=256)
    plain_padded = ''
    for i in range(0, len(ciphertext_bits), 512):
        block = ciphertext_bits[i:i + 512]
        if len(block) < 512:
            block = block.ljust(512, '0')
        plain_padded += feistel_decrypt_block(block, round_keys)
    return pkcs7_unpad(plain_padded)

def fnc_encrypt_cbc(plaintext_bits, key_bits, iv_bits):
    round_keys = aes_key_expansion(key_bits, num_rounds=14, round_key_size=256)
    padded = pkcs7_pad(plaintext_bits, 512)
    ciphertext_bits = ''
    prev_block = iv_bits
    for i in range(0, len(padded), 512):
        block = padded[i:i + 512]
        xored = xor_bits(block, prev_block)
        enc_block = feistel_encrypt_block(xored, round_keys)
        ciphertext_bits += enc_block
        prev_block = enc_block
    return ciphertext_bits

def fnc_decrypt_cbc(ciphertext_bits, key_bits, iv_bits):
    round_keys = aes_key_expansion(key_bits, num_rounds=14, round_key_size=256)
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