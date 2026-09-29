import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =========================================================
# ENCRYPTION KEY SETTINGS
# =========================================================

KEY_FOLDER = "keys"
KEY_FILE = os.path.join(KEY_FOLDER, "encryption.key")


# =========================================================
# CREATE AES-256 KEY
# =========================================================

def create_key():
    """
    Creates a 256-bit AES encryption key if one
    does not already exist.
    """

    os.makedirs(KEY_FOLDER, exist_ok=True)

    if os.path.exists(KEY_FILE):
        return

    key = AESGCM.generate_key(bit_length=256)

    with open(KEY_FILE, "wb") as file:
        file.write(key)

    print("Encryption key created successfully.")


# =========================================================
# LOAD AES-256 KEY
# =========================================================

def load_key():
    """
    Loads the existing AES-256 encryption key.
    """

    create_key()

    with open(KEY_FILE, "rb") as file:
        key = file.read()

    if len(key) != 32:
        raise ValueError(
            "Invalid encryption key. "
            "AES-256 requires a 32-byte key."
        )

    return key


# =========================================================
# ENCRYPT DATA
# =========================================================

def encrypt_data(data):
    """
    Encrypts plaintext using AES-256-GCM.

    Returns:
        Base64 encoded encrypted data.
    """

    if data is None:
        return None

    data = str(data)

    key = load_key()

    aes = AESGCM(key)

    # GCM recommends a 12-byte nonce.
    nonce = os.urandom(12)

    plaintext = data.encode("utf-8")

    encrypted_data = aes.encrypt(
        nonce,
        plaintext,
        None
    )

    # Store nonce together with encrypted data.
    combined = nonce + encrypted_data

    encoded = base64.urlsafe_b64encode(
        combined
    )

    return encoded.decode("utf-8")


# =========================================================
# DECRYPT DATA
# =========================================================

def decrypt_data(encrypted_data):
    """
    Decrypts AES-256-GCM encrypted data.
    """

    if encrypted_data is None:
        return None

    key = load_key()

    try:

        combined = base64.urlsafe_b64decode(
            encrypted_data.encode("utf-8")
        )

        nonce = combined[:12]

        ciphertext = combined[12:]

        aes = AESGCM(key)

        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            None
        )

        return plaintext.decode("utf-8")

    except Exception:

        raise ValueError(
            "Unable to decrypt data. "
            "The encryption key or encrypted data "
            "may be invalid."
        )


# =========================================================
# TEST ENCRYPTION
# =========================================================

if __name__ == "__main__":

    print("Testing AES-256-GCM encryption...")

    original_text = "Patient has diabetes and requires regular monitoring."

    encrypted_text = encrypt_data(original_text)

    print("\nOriginal:")
    print(original_text)

    print("\nEncrypted:")
    print(encrypted_text)

    decrypted_text = decrypt_data(encrypted_text)

    print("\nDecrypted:")
    print(decrypted_text)

    if decrypted_text == original_text:
        print("\nAES-256-GCM test successful.")
    else:
        print("\nAES-256-GCM test failed.")