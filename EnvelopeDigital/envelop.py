import os, time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from Modules.aes_module import encrypt_aes, decrypt_aes

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
    key_input = input("Digite o caminho da chave pública ou cole o PEM:\n>> ").strip()
    if os.path.exists(key_input):
        with open(key_input, "rb") as f: key_bytes = f.read()
    else: key_bytes = key_input.encode()
    return serialization.load_pem_private_key(key_bytes, password=None)

# --- Envelope Digital ---
def doEnvelopDigital(public_key, plaintext):
    # Gerar chave simétrica (AES) e IV
    key_aes = generateKeyAes()
    iv = os.urandom(16)

    # Cifra o conteúdo com AES
    ciphertext = encrypt_aes(key_aes, iv, plaintext)

    # Cifra a chave AES com RSA
    cipherrsa = encrypt_rsa(public_key, key_aes)

    return {
        "ciphertext": ciphertext,
        "key_encrypted": cipherrsa,
        "iv": iv
    }

# --- Descriptografar envelope digital ---
def decryptEnvelope(private_key, envelope_dict):
    # Descriptografa a chave AES com a chave RSA
    key_aes = decrypt_rsa(private_key, envelope_dict["key_encrypted"])

    #Descriptografa o conteúdo com AES
    plaintext = decrypt_aes(key_aes, envelope_dict["iv"], envelope_dict["ciphertext"])
    return plaintext

def init():
    clear_screen()
    print("=" * 55)
    print(f"{' '*15}ENVELOPE DIGITAL (DEMO)")
    print("=" * 55)

    is_file = input("Digite: 0 - Para arquivo | 1 - Para texto\n>> ") == '0'
    plaintext = (
        input("Nome do arquivo em ./arquivos:\n>> ")
        if is_file else input("Texto a criptografar:\n>> ")
    )

    if not is_file:
        filename = f"msg_{os.urandom(5).hex()}.txt"
        with open(f"./arquivos/{filename}", 'x', encoding='utf-8') as f:
            f.write(plaintext)
        plaintext = filename

    loading_bar("Gerando Chaves RSA")
    generatePublicAndPrivateKey()
    public_key = load_public_key_from_input()

    with open(f"./arquivos/{plaintext}", 'rb') as f:
        plaintextBin = f.read()

    envelope = doEnvelopDigital(public_key, plaintextBin)

    print("\n--- Resultado ---")
    print("Chave AES cifrada (RSA):", envelope["key_encrypted"].hex())
    print("IV:", envelope["iv"].hex())
    print("Ciphertext (AES):", envelope["ciphertext"].hex())

# --- Função de teste para descriptografia ---
def decrypt_init():
    private_key = load_private_key_from_input()

    import binascii
    ciphertext_hex = input("Digite o ciphertext (AES) em HEX:\n>> ").strip()
    key_encrypted_hex = input("Digite a chave AES cifrada (RSA) em HEX:\n>> ").strip()
    iv_hex = input("Digite o IV (AES) em HEX:\n>> ").strip()

    envelope_dict = {
        "ciphertext": binascii.unhexlify(ciphertext_hex),
        "key_encrypted": binascii.unhexlify(key_encrypted_hex),
        "iv": binascii.unhexlify(iv_hex)
    }

    plaintext = decryptEnvelope(private_key, envelope_dict)

    print("\n--- Texto descriptografado ---")
    try:
        print(plaintext.decode(errors='ignore'))
    except Exception:
        print(plaintext)



if __name__ == "__main__":
    os.makedirs('./arquivos', exist_ok=True)
    os.makedirs('./rsa_keys', exist_ok=True)
    choice = input("Deseja 0 - Criar Envelope | 1 - Decifrar Envelope\n>> ")
    if choice == "0":
        init()
    elif choice == "1":
        decrypt_init()
