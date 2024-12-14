from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hashlib import sha256
import os
import secrets

def dh_key_exchange():
    private_key = secrets.randbelow(2**16)
    public_key = pow(5, private_key, 97) # (g=5, p=97)
    return private_key, public_key

def derive_shared_secret(private_key, public_key):
    return pow(public_key, private_key, 97)  

def hash_key(shared_secret):
    return sha256(str(shared_secret).encode()).digest()

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key[:16]), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext.encode()) + encryptor.finalize()

def aes_decrypt(key, ciphertext):
    iv, ct = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key[:16]), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def onion_routing_simulation(num_relays, message):
    print(f"Pas 1: Alice crea un circuit segur amb {num_relays} relays")

    private_keys = []
    public_keys = []
    shared_secrets = []
    hashed_keys = []

    private_key_a, public_key_a = dh_key_exchange()

    for i in range(num_relays):
        private_key, public_key = dh_key_exchange()
        private_keys.append(private_key)
        public_keys.append(public_key)
        
        shared_secret = derive_shared_secret(private_key_a, public_key)
        shared_secrets.append(shared_secret)
        hashed_keys.append(hash_key(shared_secret))
        
        print(f"Relay {i + 1}: Secret compartit: {shared_secret}")

    print("\nPas 2: Alice encripta el missatge a través de les capes")
    encrypted_message = message
    for key in reversed(hashed_keys):
        encrypted_message = aes_encrypt(key, encrypted_message).hex()

    print(f"Missatge encriptat final: {encrypted_message}")

    print("\nPas 3: Desencriptar el missatge a cada relay")
    decrypted_message = encrypted_message
    for i, key in enumerate(hashed_keys):
        decrypted_message = aes_decrypt(key, bytes.fromhex(decrypted_message)).decode()
        print(f"Relay {i + 1} desencriptat: {decrypted_message}")

    print("\nMissatge final desencriptat per Alice:", decrypted_message)

# --- Simulació ---
num_relays = int(input("Introdueix el nombre de relays (ORs): "))
message = input("Introdueix el missatge que vols enviar: ")
onion_routing_simulation(num_relays, message)
