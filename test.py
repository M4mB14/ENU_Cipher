from cipher_function import generate_round_keys,pkcs7_pad
from FNC_2 import feistel_round

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

# --- Шифрование блока (512 бит) ---
def feistel_encrypt_block(block_bits, round_keys):
    print(len(block_bits))
    print((round_keys))
    L, R = block_bits[:256], block_bits[256:]
    for k in round_keys:
        L, R = feistel_round(L, R, k)
    # финальный swap (для чётного количества раундов можно убрать, но лучше всегда)
    return R + L

#print(text_to_bits("Hello"))
print(feistel_encrypt_block('',''))