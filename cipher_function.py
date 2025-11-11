import random


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


def detect_and_convert_to_bits(user_input):
    if all(ch in '01' for ch in user_input):
        return user_input
    if all(ch in '0123456789ABCDEFabcdef' for ch in user_input):
        return hex_to_bits(user_input)
    return ''.join(format(ord(c), '08b') for c in user_input)


SBOX_HEX = {
    0x0: 0x8, 0x1: 0x3, 0x2: 0x7, 0x3: 0x0,
    0x4: 0x1, 0x5: 0xA, 0x6: 0x5, 0x7: 0xF,
    0x8: 0x2, 0x9: 0x4, 0xA: 0xD, 0xB: 0x6,
    0xC: 0x9, 0xD: 0xB, 0xE: 0xC, 0xF: 0xE
}

INV_SBOX_HEX = {v: k for k, v in SBOX_HEX.items()}


def sbox_substitution_4bit(bits, inverse=False):
    out_bits = ""
    table = INV_SBOX_HEX if inverse else SBOX_HEX
    for i in range(0, len(bits), 4):
        nibble = bits[i:i + 4]
        val = int(nibble, 2)
        sub_val = table[val]
        out_bits += format(sub_val, '04b')
    return out_bits


PBOX_MAP = {
    1: 12, 2: 3, 3: 9, 4: 14,
    5: 1, 6: 7, 7: 15, 8: 4,
    9: 10, 10: 16, 11: 8, 12: 2,
    13: 13, 14: 6, 15: 11, 16: 5
}

INV_PBOX_MAP = {v: k for k, v in PBOX_MAP.items()}


def pbox_permutation(bits, inverse=False):
    out_bits = ""
    table = INV_PBOX_MAP if inverse else PBOX_MAP
    for i in range(0, len(bits), 16):
        block = bits[i:i + 16]
        if len(block) < 16:
            block = block.ljust(16, '0')
        permuted = ['0'] * 16
        for src, dest in table.items():
            if src <= len(block):
                permuted[dest - 1] = block[src - 1]
        out_bits += ''.join(permuted)
    return out_bits


def xor_bits(bits1, bits2):
    return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))


def split_into_blocks(bin_text, block_size=512):
    return [bin_text[i:i + block_size] for i in range(0, len(bin_text), block_size)]


def pkcs7_pad(bits, block_size_bits=512):
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


def generate_round_keys(key_bits, num_rounds=10):
    K1, K2 = key_bits[:128], key_bits[128:]
    seed = int(K1, 2) ^ int(K2, 2)
    round_keys = []
    a = 1664525
    c = 1013904223
    m = 2 ** 32
    for i in range(num_rounds):
        seed = (a * (seed + i) + c) % m
        key_bits_128 = ""
        local_seed = seed
        for _ in range(128 // 32):
            local_seed = (a * local_seed + c) % m
            key_bits_128 += format(local_seed, '032b')
        round_keys.append(key_bits_128)
    return round_keys


def encrypt_block(plaintext_bits, round_keys):
    blocks = [plaintext_bits[i:i + 128] for i in range(0, len(plaintext_bits), 128)]
    for round_key in round_keys:
        new_blocks = []
        for block in blocks:
            xor_out = xor_bits(block, round_key)
            sbox_out = sbox_substitution_4bit(xor_out)
            pbox_out = pbox_permutation(sbox_out)
            new_blocks.append(pbox_out)
        blocks = new_blocks
    return ''.join(blocks)


def decrypt_block(cipher_bits, round_keys):
    blocks = [cipher_bits[i:i + 128] for i in range(0, len(cipher_bits), 128)]
    for round_key in reversed(round_keys):
        new_blocks = []
        for block in blocks:
            pbox_inv = pbox_permutation(block, inverse=True)
            sbox_inv = sbox_substitution_4bit(pbox_inv, inverse=True)
            xor_out = xor_bits(sbox_inv, round_key)
            new_blocks.append(xor_out)
        blocks = new_blocks
    return ''.join(blocks)


def ecb_encrypt(plaintext_bits, round_keys):
    blocks = split_into_blocks(plaintext_bits, 512)
    ciphertext = ""
    for block in blocks:
        ciphertext += encrypt_block(block, round_keys)
    return ciphertext


def ecb_decrypt(cipher_bits, round_keys):
    blocks = split_into_blocks(cipher_bits, 512)
    plaintext = ""
    for block in blocks:
        plaintext += decrypt_block(block, round_keys)
    return plaintext


def cbc_encrypt(plaintext_bits, round_keys, iv):
    blocks = split_into_blocks(plaintext_bits, 512)
    prev = iv.zfill(512)
    ciphertext = ""
    for block in blocks:
        xored = xor_bits(block, prev)
        encrypted = encrypt_block(xored, round_keys)
        ciphertext += encrypted
        prev = encrypted
    return ciphertext


def cbc_decrypt(cipher_bits, round_keys, iv):
    blocks = split_into_blocks(cipher_bits, 512)
    prev = iv.zfill(512)
    plaintext = ""
    for block in blocks:
        decrypted = decrypt_block(block, round_keys)
        xored = xor_bits(decrypted, prev)
        plaintext += xored
        prev = block
    return plaintext
