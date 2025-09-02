from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

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

def defHeader(iv):
    # Define campos
    IDENT       = b'ED'                 # 2 bytes
    VERSION     = bytes([0x01])         # 1 byte
    ALGO        = bytes([0x01])         # 1 byte (AES)
    MODE        = bytes([0x01])         # 1 byte (CBC)
    IV          = iv     # 16 bytes: 0x00..0x0F
    RESERVED    = bytes(11)             # 11 bytes de 0x00

    # Monta o header (32 bytes)
    header = bytearray()
    header += IDENT
    header += VERSION
    header += ALGO
    header += MODE
    header += IV
    header += RESERVED

    if len(header) != 32:
            raise ValueError(f"Erro ao montar cabeçalho: tamanho incorreto. Esperado 32, obtido {len(header)}")

    return bytes(header) # Retorna como bytes imutáveis

def encriptFile(nameFile, key):
    input_filepath = f'./arquivos/{nameFile}'
    output_filename = f'{nameFile}.enc'
    output_filepath = f'./arquivos_encript/{output_filename}'

    try:
        os.makedirs('./arquivos_encript', exist_ok=True)

        with open(input_filepath, 'rb') as f:
            originBinFile = f.read()

        iv = os.urandom(16) 
        enc = encrypt_aes(key, iv, originBinFile)

        with open(output_filepath, 'wb') as f:
            header = defHeader(iv)
            complete = header + enc
            f.write(complete)

        print(f"\n✅ Arquivo '{nameFile}' criptografado com sucesso para '{output_filepath}'.")

    except FileNotFoundError:
        print(f"\n❌ Erro: O arquivo de entrada '{input_filepath}' não foi encontrado.")
    except ValueError as e:
        print(f"\n❌ Erro durante a criptografia: {e}")
    except Exception as e:
        print(f"\n❌ Ocorreu um erro inesperado durante a criptografia de '{nameFile}': {e}")


def decriptFile(nameFile, key):
    input_filepath = f'./arquivos_encript/{nameFile}'

    basename = nameFile[0:len(nameFile)-4]
    output_filepath = f'./arquivos_decript/{basename}'

    print(basename)
    try:
        os.makedirs('./arquivos_decript', exist_ok=True)

        with open(input_filepath, 'rb') as f:
            header_bytes = f.read(32)

            if len(header_bytes) < 32:
                raise ValueError("Arquivo cifrado é muito pequeno para conter o cabeçalho completo.")

            ident      = header_bytes[0:2]        # 2 bytes
            version    = header_bytes[2]          # 1 byte
            algo       = header_bytes[3]          # 1 byte
            mode       = header_bytes[4]          # 1 byte
            iv         = header_bytes[5:21]       # 16 bytes
            reserved   = header_bytes[21:32]      # 11 bytes

            if ident.decode() != 'ED':
                raise ValueError(f"Identificador inválido no cabeçalho")
            if version != 1:
                raise ValueError(f"Versão inválida no cabeçalho")
            if algo != 1:
                raise ValueError(f"Algoritmo inválido no cabeçalho")
            if mode != 1:
                raise ValueError(f"Modo inválido no cabeçalho")

            if len(iv) != 16:
                 raise ValueError(f"Tamanho do IV incorreto no cabeçalho: Esperado 16, obtido {len(iv)}")

            ciphertext_content = f.read()

            if not ciphertext_content:
                print("⚠️ Aviso: O arquivo cifrado não contém conteúdo após o cabeçalho. O arquivo descriptografado será vazio.")

            decrypted_plaintext = decrypt_aes(key, iv, ciphertext_content)
            
            with open(output_filepath, 'wb') as f_out:
                f_out.write(decrypted_plaintext)

        print(f"\n✅ Arquivo '{nameFile}' descriptografado com sucesso para '{output_filepath}'.")

    except FileNotFoundError:
        print(f"\n❌ Erro: O arquivo cifrado '{input_filepath}' não foi encontrado. Certifique-se de que o arquivo .enc está em './arquivos_encript/'.")
    except ValueError as e:
        print(f"\n❌ Erro de validação ou estrutura do arquivo cifrado: {e}")
    except Exception as e:
        print(f"\n❌ Ocorreu um erro inesperado durante a descriptografia de '{nameFile}': {e}")

def generate_metadata_file(original_filename: str, key: bytes):
    """
    Gera um arquivo de metadados (.meta) para verificação de integridade.
    O arquivo .meta contém um cabeçalho (com IV) e um bloco de hash (últimos 16 bytes do ciphertext).
    """
    original_filepath = f'./arquivos/{original_filename}'
    meta_filename = f'{original_filename}.meta'
    meta_filepath = f'./meta/{meta_filename}'

    try:
        os.makedirs('./meta', exist_ok=True)

        with open(original_filepath, 'rb') as f:
            original_content = f.read()

        if not original_content:
            print(f"⚠️ Aviso: O arquivo original '{original_filepath}' está vazio. A tag de integridade será baseada em conteúdo vazio.")

        iv_meta = os.urandom(16)
        
        ciphertext_for_tag = encrypt_aes(key, iv_meta, original_content)
        
        if len(ciphertext_for_tag) < 16:
            raise ValueError("Erro ao gerar tag: ciphertext resultante é menor que 16 bytes.")
            
        tag_bloco = ciphertext_for_tag[-16:] # Pega os últimos 16 bytes

        header_meta = defHeader(iv_meta)

        metadata_content = header_meta + tag_bloco

        if len(metadata_content) != 48:
            raise ValueError(f"Erro ao montar metadados: tamanho incorreto. Esperado 48, obtido {len(metadata_content)}")

        with open(meta_filepath, 'wb') as f_meta:
            f_meta.write(metadata_content)

        print(f"\n✅ Arquivo de metadados '{meta_filename}' gerado com sucesso em '{meta_filepath}'.")
        print(f"   IV usado para tag: {iv_meta.hex()}")
        print(f"   Tag (últimos 16 bytes do cipher): {tag_bloco.hex()}")

    except FileNotFoundError:
        print(f"\n❌ Erro: O arquivo original '{original_filepath}' não foi encontrado para gerar metadados.")
    except ValueError as e:
        print(f"\n❌ Erro durante a geração do arquivo de metadados: {e}")
    except Exception as e:
        print(f"\n❌ Ocorreu um erro inesperado durante a geração de metadados para '{original_filename}': {e}")

def verify_integrity(original_filename: str, key: bytes):
    """
    Verifica a integridade de um arquivo original comparando sua tag calculada
    com a tag armazenada em seu arquivo .meta correspondente.
    """
    original_filepath = f'./arquivos/{original_filename}'
    meta_filename = f'{original_filename}.meta'
    meta_filepath = f'./meta/{meta_filename}'

    try:
        with open(meta_filepath, 'rb') as f_meta:
            meta_content = f_meta.read()

        if len(meta_content) != 48:
            raise ValueError(f"Arquivo de metadados '{meta_filename}' tem tamanho incorreto. Esperado 48 bytes, obtido {len(meta_content)}.")

        header_bytes_meta = meta_content[:32]
        stored_tag_bloco = meta_content[32:]

        ident_meta       = header_bytes_meta[0:2]
        version_meta     = header_bytes_meta[2]
        algo_meta        = header_bytes_meta[3]
        mode_meta        = header_bytes_meta[4]
        stored_iv_meta   = header_bytes_meta[5:21]

        if ident_meta.decode('utf-8', errors='ignore') != 'ED':
            raise ValueError("Identificador inválido no cabeçalho do arquivo .meta.")
        if version_meta != 0x01:
            raise ValueError("Versão inválida no cabeçalho do arquivo .meta.")
        if algo_meta != 0x01: 
            raise ValueError("Algo inválido no cabeçalho do arquivo .meta.")
        if mode_meta != 0x01:
            raise ValueError("Modo infálido no cabeçalho do arquivo .meta.")
        if len(stored_iv_meta) != 16:
            raise ValueError("Tamanho do IV incorreto no cabeçalho do arquivo .meta.")

        with open(original_filepath, 'rb') as f_orig:
            original_content = f_orig.read()
        
        # Criptografa o conteúdo original com o IV do arquivo .meta para recalcular a tag
        recalculated_ciphertext = encrypt_aes(key, stored_iv_meta, original_content)
        
        if len(recalculated_ciphertext) < 16:
            raise ValueError("Erro ao recalcular tag: ciphertext resultante é menor que 16 bytes.")
            
        calculated_tag_bloco = recalculated_ciphertext[-16:]

        print(f"\n--- Verificação de Integridade para '{original_filename}' ---")
        print(f"   IV lido do .meta: {stored_iv_meta.hex()}")
        print(f"   Tag armazenada no .meta: {stored_tag_bloco.hex()}")
        print(f"   Tag calculada do arquivo: {calculated_tag_bloco.hex()}")

        if stored_tag_bloco == calculated_tag_bloco:
            print(f"✅ INTEGRIDADE VERIFICADA: O arquivo '{original_filename}' não foi alterado.")
        else:
            print(f"❌ FALHA NA INTEGRIDADE: O arquivo '{original_filename}' foi alterado ou o arquivo .meta não corresponde.")

    except FileNotFoundError:
        print(f"\n❌ Erro: Arquivo original '{original_filepath}' ou arquivo de metadados '{meta_filepath}' não encontrado.")
    except ValueError as e:
        print(f"\n❌ Erro durante a verificação de integridade: {e}")
    except Exception as e:
        print(f"\n❌ Ocorreu um erro inesperado durante a verificação de integridade para '{original_filename}': {e}")
     
os.makedirs('./arquivos', exist_ok=True)
os.makedirs('./arquivos_encript', exist_ok=True)
os.makedirs('./arquivos_decript', exist_ok=True)
os.makedirs('./meta', exist_ok=True)

key = b'\xe1\x18\x89\xae\x98\xf7\x94\xf4+\x9bL\x89\xe0\x08W\xf8'

nameFile_input = input("Informe o nome do arquivo.\nPara criptografar: 'nome_original.txt' (deve estar em './arquivos/')\nPara descriptografar: 'nome_cifrado.enc' (deve estar em './arquivos_encript/')\nNome do arquivo: ")

op = -1
while op not in [0, 1, 2, 3]:
    try:
        op = int(input("Qual operação ? 0 (Criptografar)\t1 (Descriptografar)\t2 (Gerar Arquivo de Metadados)\t 3 (Verificar Integridade)\nEscolha: "))
        if op not in [0, 1, 2, 3]:
            print("❌ Opção inválida. Por favor, digite 0 para Criptografar, 1 para Descriptografar, 2 para Gerar Arquivo de Metadados ou 3 para Verificar Integridade.")
    except ValueError:
        print("❌ Entrada inválida. Por favor, digite um número (0, 1, 2 ou 3).")

print("\n--- Iniciando Operação ---")
if op == 0:
    encriptFile(nameFile_input, key)
elif op == 1:
    decriptFile(nameFile_input, key)
elif op == 2:
    generate_metadata_file(nameFile_input, key)
elif op == 3:
    verify_integrity(nameFile_input, key)
print("--- Operação Concluída ---\n")
