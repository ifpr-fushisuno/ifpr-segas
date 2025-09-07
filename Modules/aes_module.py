import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


# --- Funções básicas AES ---
def encrypt_aes(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def decrypt_aes(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()


# --- Header (32 bytes) ---
def defHeader(iv):
    IDENT = b'ED'
    VERSION = bytes([0x01])
    ALGO = bytes([0x01])  # AES
    MODE = bytes([0x01])  # CBC
    RESERVED = bytes(11)

    header = bytearray()
    header += IDENT + VERSION + ALGO + MODE + iv + RESERVED

    if len(header) != 32:
        raise ValueError(f"Tamanho incorreto do cabeçalho: {len(header)}")

    return bytes(header)


# --- Criptografar arquivo ---
def encriptFile(nameFile, key):
    input_filepath = f'./arquivos/{nameFile}'
    output_filepath = f'./arquivos_encript/{nameFile}.enc'

    try:
        os.makedirs('./arquivos_encript', exist_ok=True)
        with open(input_filepath, 'rb') as f:
            originBinFile = f.read()

        iv = os.urandom(16)
        enc = encrypt_aes(key, iv, originBinFile)

        with open(output_filepath, 'wb') as f:
            f.write(defHeader(iv) + enc)

        print(f"Arquivo criptografado: {output_filepath}")
    except Exception as e:
        print(f"Erro ao criptografar {nameFile}: {e}")


# --- Descriptografar arquivo ---
def decriptFile(nameFile, key):
    input_filepath = f'./arquivos_encript/{nameFile}'
    output_filepath = f'./arquivos_decript/{nameFile[:-4]}'

    try:
        os.makedirs('./arquivos_decript', exist_ok=True)
        with open(input_filepath, 'rb') as f:
            header_bytes = f.read(32)
            iv = header_bytes[5:21]
            ciphertext_content = f.read()

        plaintext = decrypt_aes(key, iv, ciphertext_content)
        with open(output_filepath, 'wb') as f_out:
            f_out.write(plaintext)

        print(f"Arquivo descriptografado: {output_filepath}")
    except Exception as e:
        print(f"Erro ao descriptografar {nameFile}: {e}")
