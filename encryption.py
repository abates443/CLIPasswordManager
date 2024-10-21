from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from hashlib import sha256
import base64, string, random


# Generating a randomized password
def generate_secure_password(length=12):
    # Populates the available pool of characters with all letters, digits, and punctuation.
    char_pool = string.ascii_letters + string.digits + string.punctuation
    # From the character pool, randomly select 12 characters and concatenate them into the password.
    password = ''.join(random.choice(char_pool) for _ in range(length))
    return password


# Deriving Encryption Key function
def derive_key(master_password):
    salt = b'H\x1d\tMg\xc9\xe3\xec\xbeU\xee\x03\xec\x18\xf1U'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


# Generate SHA256 hash for auth table
def gen_hash(master_password):
    return sha256(master_password.encode('utf-8')).hexdigest()


# Using key to encrypt/decrypt a password
def encrypt_password(password, key):
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password


def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password
