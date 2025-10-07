import sys
import importlib.util
from pathlib import Path
import binascii
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

HASH_MODULE_PATH = "D:\Study\Cods\Kriptology\hash_func.py"
spec = importlib.util.spec_from_file_location("hash_func_user", HASH_MODULE_PATH)
hash_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hash_mod)


def compute_hash_bytes_from_input_string(s: str) -> bytes:
    bits = hash_mod.parse_plaintext_to_bits(s)
    if bits == '':
        bits = '0'
    blocks = [bits[i:i+32] for i in range(0, len(bits), 32)]
    if len(blocks) == 0:
        blocks = ['0' * 32]
    if len(blocks[-1]) < 32:
        blocks[-1] = blocks[-1].ljust(32, '0')
    state = hash_mod.FIXED_IV
    for blk in blocks:
        state = hash_mod.compress32(state, blk, verbose=False)
    state_int = int(state, 2)
    return state_int.to_bytes(4, 'big') 

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

private_key, public_key = generate_rsa_keys()

def pem_public_key():
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def pem_private_key():
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def sign_message(msg_str: str) -> bytes:
    h_bytes = compute_hash_bytes_from_input_string(msg_str)
    signature = private_key.sign(
        h_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def verify_message(msg_str: str, signature: bytes) -> bool:
    h_bytes = compute_hash_bytes_from_input_string(msg_str)
    try:
        public_key.verify(
            signature,
            h_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
    
def to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def from_hex(s: str) -> bytes:
    return binascii.unhexlify(s.strip())

def run_interactive():
    print("=== Утилита ЭЦП (используется твой hash_func) ===")
    print("Публичный ключ (PEM), поделись им с проверяющей стороной:")
    print(pem_public_key().decode())
    while True:
        print("\nВыберите действие:")
        print(" 1 - Подписать документ (ввод сообщения -> получаем подпись)")
        print(" 2 - Проверить подпись (ввод сообщения + подпись -> проверка)")
        print(" 3 - Выйти")
        choice = input("Введите 1/2/3: ").strip()
        if choice == '1':
            msg = input("Введите сообщение (любой формат: текст / DEC / 0xHEX / бинарно):\n")
            h_bytes = compute_hash_bytes_from_input_string(msg)
            print(f"Хеш (32 бита) в hex: {to_hex(h_bytes)}")
            sig = sign_message(msg)
            print("Подпись (hex):")
            print(to_hex(sig))
            print("\nПодпись сгенерирована.")
        elif choice == '2':
            msg = input("Введите сообщение для проверки:\n")
            sig_hex = input("Введите подпись (hex):\n").strip()
            try:
                sig = from_hex(sig_hex)
            except Exception:
                print("Ошибка: подпись должна быть в hex-формате (только 0-9a-f).")
                continue
            ok = verify_message(msg, sig)
            if ok:
                print("Проверка пройдена — подпись корректна.")
            else:
                print("Проверка НЕ пройдена — подпись не соответствует сообщению.")
        elif choice == '3':
            print("Выход.")
            break
        else:
            print("Неправильный выбор. Введите 1, 2 или 3.")

if __name__ == '__main__':
    try:
        run_interactive()
    except KeyboardInterrupt:
        print("\nПрервано пользователем. Выход.")
        sys.exit(0)
