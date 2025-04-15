import tools
import os
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM, AESCCM

def Algo1(data, key):
    f = Fernet(key)
    with open("raw_data/store_in_me.enc", "wb") as target_file:
        secret_data = f.encrypt(data)
        target_file.write(secret_data)

def Algo1_extented(filename, key1, key2):
    f = MultiFernet([Fernet(key1), Fernet(key2)])
    source_filename = 'files/' + filename
    target_filename = 'encrypted/' + filename

    raw = b''  # Use bytes to handle binary data
    with open(source_filename, 'rb') as file:
        raw = file.read()  # Read the entire content at once

    secret_data = f.encrypt(raw)
    with open(target_filename, 'wb') as target_file:
        target_file.write(secret_data)

def Algo2(filename, key, nonce):
    aad = b"authenticated but unencrypted data"
    chacha = ChaCha20Poly1305(key)
    source_filename = 'files/' + filename
    target_filename = 'encrypted/' + filename

    with open(source_filename, 'rb') as file:
        raw = file.read()

    secret_data = chacha.encrypt(nonce, raw, aad)
    with open(target_filename, 'wb') as target_file:
        target_file.write(secret_data)

def Algo3(filename, key, nonce):
    aad = b"authenticated but unencrypted data"
    aesgcm = AESGCM(key)
    source_filename = 'files/' + filename
    target_filename = 'encrypted/' + filename

    with open(source_filename, 'rb') as file:
        raw = file.read()

    secret_data = aesgcm.encrypt(nonce, raw, aad)
    with open(target_filename, 'wb') as target_file:
        target_file.write(secret_data)

def Algo4(filename, key, nonce):
    aad = b"authenticated but unencrypted data"
    aesccm = AESCCM(key)
    source_filename = 'files/' + filename
    target_filename = 'encrypted/' + filename

    with open(source_filename, 'rb') as file:
        raw = file.read()

    secret_data = aesccm.encrypt(nonce, raw, aad)
    with open(target_filename, 'wb') as target_file:
        target_file.write(secret_data)

def encrypter():
    # Ensure the necessary directories exist
    os.makedirs('key', exist_ok=True)
    os.makedirs('encrypted', exist_ok=True)
    os.makedirs('raw_data', exist_ok=True)

    tools.empty_folder('key')
    tools.empty_folder('encrypted')

    key_1 = Fernet.generate_key()
    key_1_1 = Fernet.generate_key()
    key_1_2 = Fernet.generate_key()
    key_2 = ChaCha20Poly1305.generate_key()
    key_3 = AESGCM.generate_key(bit_length=128)
    key_4 = AESCCM.generate_key(bit_length=128)

    nonce13 = os.urandom(13)
    nonce12 = os.urandom(12)

    files = sorted(tools.list_dir('files'))
    for index, filename in enumerate(files):
        if index % 4 == 0:
            Algo1_extented(filename, key_1_1, key_1_2)
        elif index % 4 == 1:
            Algo2(filename, key_2, nonce12)
        elif index % 4 == 2:
            Algo3(filename, key_3, nonce12)
        else:
            Algo4(filename, key_4, nonce13)

    secret_information = b":::::".join([key_1_1.hex().encode(), key_1_2.hex().encode(), key_2.hex().encode(), key_3.hex().encode(), key_4.hex().encode(), nonce12.hex().encode(), nonce13.hex().encode()])
    Algo1(secret_information, key_1)

    with open("./key/Taale_Ki_Chabhi.pem", "wb") as public_key:
        public_key.write(key_1)

    tools.empty_folder('files')  # Make sure files are encrypted before clearing