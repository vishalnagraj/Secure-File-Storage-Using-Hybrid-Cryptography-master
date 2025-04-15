import tools
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM, AESCCM

def Algo1(key):
    f = Fernet(key)
    with open("raw_data/store_in_me.enc", "rb") as target_file:
        secret_data = target_file.read()
    data = f.decrypt(secret_data)
    return data

def Algo1_extented(filename, key1, key2):
    f = MultiFernet([Fernet(key1), Fernet(key2)])
    with open(f'encrypted/{filename}', 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    with open(f'files/{filename}', 'wb') as target_file:
        target_file.write(decrypted_data)

def Algo2(filename, key, nonce):
    aad = b"authenticated but unencrypted data"
    chacha = ChaCha20Poly1305(key)
    with open(f'encrypted/{filename}', 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = chacha.decrypt(nonce, encrypted_data, aad)
    with open(f'files/{filename}', 'wb') as target_file:
        target_file.write(decrypted_data)

def Algo3(filename, key, nonce):
    aad = b"authenticated but unencrypted data"
    aesgcm = AESGCM(key)
    with open(f'encrypted/{filename}', 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = aesgcm.decrypt(nonce, encrypted_data, aad)
    with open(f'files/{filename}', 'wb') as target_file:
        target_file.write(decrypted_data)

def Algo4(filename, key, nonce):
    aad = b"authenticated but unencrypted data"
    aesccm = AESCCM(key)
    with open(f'encrypted/{filename}', 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = aesccm.decrypt(nonce, encrypted_data, aad)
    with open(f'files/{filename}', 'wb') as target_file:
        target_file.write(decrypted_data)

def decrypter():
    tools.empty_folder('files')

    # Read the key
    key_files = tools.list_dir('key')
    if not key_files:
        print("Error: No key file found in the 'key' folder.")
        return

    key_path = f'./key/{key_files[0]}'
    with open(key_path, "rb") as public_key:
        key_1 = public_key.read()

    # Decrypt secret information
    secret_information = Algo1(key_1)

    try:
        list_information = secret_information.decode('utf-8').split(':::::')
    except UnicodeDecodeError:
        print("Error: Decryption failed due to an invalid key or corrupted data.")
        return

    # Assign keys and nonces (already in bytes, no need to encode again)
    try:
        key_1_1 = bytes.fromhex(list_information[0])
        key_1_2 = bytes.fromhex(list_information[1])
        key_2 = bytes.fromhex(list_information[2])
        key_3 = bytes.fromhex(list_information[3])
        key_4 = bytes.fromhex(list_information[4])
        nonce12 = bytes.fromhex(list_information[5])
        nonce13 = bytes.fromhex(list_information[6])
    except IndexError:
        print("Error: Decrypted data is incomplete or corrupted.")
        return
    except ValueError:
        print("Error: Invalid hexadecimal string format in decrypted data.")
        return

    # Decrypt files using the respective algorithms
    files = sorted(tools.list_dir('encrypted'))
    for index, filename in enumerate(files):
        if index % 4 == 0:
            Algo1_extented(filename, key_1_1, key_1_2)
        elif index % 4 == 1:
            Algo2(filename, key_2, nonce12)
        elif index % 4 == 2:
            Algo3(filename, key_3, nonce12)
        else:
            Algo4(filename, key_4, nonce13)