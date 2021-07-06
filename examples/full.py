import os

from pysecube import (Wrapper,
                      Crypter,
                      ALGORITHM_AES,
                      FEEDBACK_CTR,
                      MODE_ENCRYPT,
                      MODE_DECRYPT)

AES_KEY_ID = 10
AES_KEY_BYTES = os.urandom(32) # Generate a 32 byte AES key
AES_CTR_NONCE = os.urandom(16) # Generate a 16 byte AES CTR nonce

SECUBE_PIN = b"test"

secube_wrapper = Wrapper(SECUBE_PIN)
secube_wrapper.crypto_set_time_now()

# Set up sample AES Key
if secube_wrapper.key_exists(AES_KEY_ID):
    secube_wrapper.delete_key(AES_KEY_ID)
secube_wrapper.add_key(AES_KEY_ID, b"SampleAESKey", AES_KEY_BYTES, 300)

plaintext = b"AAAABBBBCCCCDDDD"

print("Plaintext: 0x{}".format(plaintext.hex()))

# SHA256
digest = secube_wrapper.sha256(plaintext)
print("Digest: 0x{}".format(digest.hex()))

# Encrypt with AES256-CTR
encrypter = Crypter(secube_wrapper, ALGORITHM_AES, FEEDBACK_CTR | MODE_ENCRYPT, AES_KEY_ID, AES_CTR_NONCE)
ciphertext = encrypter.update(plaintext)
print("Ciphertext: 0x{}".format(ciphertext.hex()))
encrypter.close()

# Decrypt with AES256-CTR
decrypter = Crypter(secube_wrapper, ALGORITHM_AES, FEEDBACK_CTR | MODE_DECRYPT, AES_KEY_ID, AES_CTR_NONCE)
new_plaintext = decrypter.update(ciphertext)
print("New Plaintext: 0x{}".format(new_plaintext.hex()))
decrypter.close()

secube_wrapper.delete_key(AES_KEY_ID)
secube_wrapper.destroy()
