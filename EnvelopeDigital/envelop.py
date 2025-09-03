import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

#GENERATE
def generatePublicAndPrivateKey():
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
def generateKeyAes(key_size_bits: int = 128) -> bytes:
    if key_size_bits not in [128, 192, 256]:
        raise ValueError("Tamanho inválido. Use 128, 192 ou 256 bits.")
    
    return os.urandom(key_size_bits // 8)


#SCREEN
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
def loading_bar(mensagem: str, segundos: int = 3):
    print(f"{'-'*8} {mensagem} {'-'*8}", end='', flush=True)
    print()
    for _ in range(segundos * 2):  # 0.5s * 2 = 1s por ponto
        time.sleep(0.5)
        print('.', end='', flush=True)
    print()  # quebra de linha no fim


#AES
def encrypt_aes(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Criptografa o texto usando AES no modo CBC.

    :param key: Chave de criptografia de 16, 24 ou 32 bytes.
    :param iv: Vetor de inicialização de 16 bytes.
    :param plaintext: Texto em claro a ser criptografado.
    :return: Texto cifrado.
    """
    # Criação do cifrador AES no modo CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    # Criando o objeto de criptografia
    encryptor = cipher.encryptor()

    # Preenchimento do texto em claro para ajustar ao tamanho do bloco
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Criptografando o texto em claro
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext
def decrypt_aes(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Descriptografa o texto cifrado usando AES no modo CBC.

    :param key: Chave de criptografia de 16, 24 ou 32 bytes.
    :param iv: Vetor de inicialização de 16 bytes.
    :param ciphertext: Texto cifrado a ser descriptografado.
    :return: Texto em claro.
    """
    # Criação do cifrador AES no modo CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    # Criando o objeto de descriptografia
    decryptor = cipher.decryptor()

    # Descriptografando o texto cifrado
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remoção do preenchimento
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


#RSA
def encrypt_rsa(public_key, key_aes):
    padding_config = padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None, )
    ciphertext = public_key.encrypt(
                    plaintext=key_aes,
                    padding=padding_config, )
    
    return ciphertext
def doEnvelopDigital(public_key, plaintext):
    #Gerar Chave Simetrica

    key_aes = generateKeyAes()
    iv = generateKeyAes()

    #Cifro com a chave Kaes -> chave sessão
    ciphertext = encrypt_aes(key_aes, iv, plaintext)

    #Cifro a chave simetrica, com a chave assimetrica publica do destino
    cipherrsa = encrypt_rsa(public_key, key_aes)

    #Enviar os dados cifrados, e a chave
    return {ciphertext, cipherrsa}


#Init
def init():
    clear_screen()
    print("=" * 55)
    print(f"{' '*15}ENVELOPE DIGITAL (DEMO)")
    print("=" * 55)
    print()

    text_or_file = 0 if input("Digite: 0 - Para arquivo\t1 - Para texto direto\n>> ") == '0' else 1
    print('-' * 40)
    print()


    plaintext = (
        input("Informe o nome do arquivo (deve estar em './arquivos/'):\n>> ")
        if text_or_file == 0
        else input("Digite o texto a ser criptografado:\n>> ")
    )

    if text_or_file != 0:
        filename = f"msg_{os.urandom(5).hex()}.txt"
        try:
            with open(f"./arquivos/{filename}", 'x', encoding='utf-8') as f:
                f.write(plaintext)
            print(f"\nTexto salvo automaticamente em ./arquivos")
        except FileNotFoundError:
            print(f"\nArquivo já existe. Tente novamente.")
            exit(1)
        
        plaintext = filename


    print()
    loading_bar("Gerando Chave Pública e Privada", segundos=3)


    generatePublicAndPrivateKey()

    print(f"{'-'*8} ✅ Concluído, chaves salvas em: ./rsa_keys {'-'*8}")
    print()

    publicKeyRsaInput = input("Digite sua chave publica:\n>> ")
    cript_file, cript_key = doEnvelopDigital(publicKeyRsaInput, plaintext)

    print(cript_key)





os.makedirs('./arquivos', exist_ok=True)
os.makedirs('./rsa_keys', exist_ok=True)

init()
