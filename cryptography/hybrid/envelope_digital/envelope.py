import os, time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from Modules.aes_module import *

# --- Geração de chaves RSA ---
def generatePublicAndPrivateKey():
    private_path = "./rsa_keys/private_key.pem"
    public_path = "./rsa_keys/public_key.pem"

    if os.path.exists(private_path) or os.path.exists(public_path):
        print("As chaves já existem. Não serão recriadas.")
        return
    
    private_key = rsa.generate_private_key(
                                        public_exponent=65537,
                                        key_size=3072,
                                        backend=default_backend(), )
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(), )
    
    with open('./rsa_keys/private_key.pem', 'xb') as private_file:
        private_file.write(private_bytes)

    public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo, )

    with open('./rsa_keys/public_key.pem', 'xb') as public_file:
        public_file.write(public_bytes)

# --- Geração de chave AES ---
def generateKeyAes(key_size_bits: int = 128) -> bytes:
    if key_size_bits not in [128, 192, 256]:
        raise ValueError("Tamanho inválido. Use 128, 192 ou 256 bits.")
    return os.urandom(key_size_bits // 8)

# --- Utilidades ---
def clear_screen(): 
    os.system('cls' if os.name == 'nt' else 'clear')
def loading_bar(msg, segundos=3):
    print(f"{'-'*8} {msg} {'-'*8}")
    for _ in range(segundos*2):
        time.sleep(0.5); print('.', end='', flush=True)
    print()

# --- Criptografia RSA ---
def encrypt_rsa(public_key, key_aes):
    padding_config = padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None, )
    ciphertext = public_key.encrypt(
                    plaintext=key_aes,
                    padding=padding_config, )
    
    return ciphertext

# --- Decriptografar RSA ---
def decrypt_rsa(private_key, key_aes):
    padding_config = padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None, )
    ciphertext = private_key.decrypt(
                    ciphertext=key_aes,
                    padding=padding_config, )
    
    return ciphertext

# --- Carregar chave publica ---
def load_public_key_from_input():
    key_input = input("Digite o caminho da chave pública ou cole o PEM:\n>> ").strip()
    if os.path.exists(key_input):
        with open(key_input, "rb") as f: key_bytes = f.read()
    else: key_bytes = key_input.encode()
    return serialization.load_pem_public_key(key_bytes)

# --- Carregar chave privada ---
def load_private_key_from_input():
    key_input = input("Digite o caminho da chave privada ou cole o PEM:\n>> ").strip()
    if os.path.exists(key_input):
        with open(key_input, "rb") as f: key_bytes = f.read()
    else: key_bytes = key_input.encode()
    return serialization.load_pem_private_key(key_bytes, password=None)

# --- Envelope Digital ---
def doEnvelopDigital(public_key, filename):
    # Gerar chave simétrica (AES) e IV
    key_aes = generateKeyAes()

    # Criptografa o arquivo com AES
    encriptFile(filename, key_aes)
    encrypted_filename = f'./arquivos_encript/{filename}.enc'

    # Cifra a chave AES com RSA
    cipherrsa = encrypt_rsa(public_key, key_aes)

    return {
        "encrypted_file": encrypted_filename,
        "key_encrypted": cipherrsa
    }

# --- Descriptografar envelope digital ---
def decryptEnvelope(private_key, envelope_dict):
    # Descriptografa a chave AES com RSA
    key_aes = decrypt_rsa(private_key, envelope_dict["key_encrypted"])

    # Descriptografa o arquivo com AES
    encrypted_filepath = envelope_dict["encrypted_file"]
    filename = os.path.basename(encrypted_filepath)
    decriptFile(filename, key_aes)

    # Retorna o caminho do arquivo descriptografado
    output_filepath = f'./arquivos_decript/{filename[:-4]}'
    return output_filepath

def init():
    clear_screen()
    print("=" * 55)
    print(f"{' '*15}ENVELOPE DIGITAL (DEMO)")
    print("=" * 55)

    is_file = input("Digite: 0 - Para arquivo | 1 - Para texto\n>> ") == '0'

    if not is_file:
        plaintext = input("Texto a criptografar:\n>> ")
        filename = f"msg_{os.urandom(5).hex()}.txt"
        with open(f"./arquivos/{filename}", 'x', encoding='utf-8') as f:
            f.write(plaintext)
    else:
        filename = input("Nome do arquivo em ./arquivos:\n>> ").strip()

    loading_bar("Gerando Chaves RSA")
    generatePublicAndPrivateKey()
    public_key = load_public_key_from_input()

    envelope = doEnvelopDigital(public_key, filename)

    print("\n--- Resultado ---")
    print("Arquivo criptografado (AES):", envelope["encrypted_file"])
    print("Chave AES cifrada (RSA):", envelope["key_encrypted"].hex())

# --- Função de teste para descriptografia ---
def decrypt_init():
    private_key = load_private_key_from_input()

    import binascii
    encrypted_file = input("Digite o caminho do arquivo criptografado:\n>> ").strip()
    key_encrypted_hex = input("Digite a chave AES cifrada (RSA) em HEX:\n>> ").strip()

    envelope_dict = {
        "encrypted_file": encrypted_file,
        "key_encrypted": binascii.unhexlify(key_encrypted_hex)
    }

    output_filepath = decryptEnvelope(private_key, envelope_dict)

    print("\n--- Arquivo descriptografado ---")
    print(f"Caminho do arquivo: {output_filepath}")



if __name__ == "__main__":
    os.makedirs('./arquivos', exist_ok=True)
    os.makedirs('./rsa_keys', exist_ok=True)
    choice = input("Deseja 0 - Criar Envelope | 1 - Decifrar Envelope\n>> ")
    if choice == "0":
        init()
    elif choice == "1":
        decrypt_init()
