import logging

# Using same cryptography module as Paramiko
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

from pysecube import (Wrapper,
                      PySEcubeException,
                      ALGORITHM_AES,
                      FEEDBACK_CTR,
                      MODE_ENCRYPT,
                      MODE_DECRYPT)

# Set logger to INFO, this can be ommitted to produce no logs
logging.basicConfig()
logging.getLogger("pysecube").setLevel(logging.DEBUG)

# Use key with ID 10 stored in the SEcube device
AES_KEY_ID = 10
AES_KEY_BYTES = b"\x01\x02\x03\x04\x05\x06\x07\x08" + \
                b"\x01\x02\x03\x04\x05\x06\x07\x08" + \
                b"\x01\x02\x03\x04\x05\x06\x07\x08" + \
                b"\x01\x02\x03\x04\x05\x06\x07\x08" # 32 byte AES key
CTR_NONCE     = b"\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8" + \
                b"\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8" # 16 byte CTR nonce


def test_encrypt_decrypt(plaintext, encrypter, decrypter):
    print(f"Encrypter: {type(encrypter)}")
    print(f"Decrypter: {type(decrypter)}")

    enc_out = encrypter.update(plaintext)
    print(f"[1] SEcube ENC output length: {len(enc_out)}")
    print(f"[1] SEcube ENC output HEX: 0x{enc_out.hex()}")

    dec_out = decrypter.update(enc_out)
    print(f"[1] Output length: {len(dec_out)}")
    print(f"[1] Output HEX 0x{dec_out.hex()}")
    print(f"[1] Output text: {dec_out.decode()}")
    assert(dec_out == plaintext)

    enc_out = encrypter.update(plaintext)
    print(f"[2] SEcube ENC output length: {len(enc_out)}")
    print(f"[2] SEcube ENC output HEX: 0x{enc_out.hex()}")

    dec_out = decrypter.update(enc_out)
    print(f"[2] Output length: {len(dec_out)}")
    print(f"[2] Output HEX 0x{dec_out.hex()}")
    print(f"[2] Output text: {dec_out.decode()}")
    assert(dec_out == plaintext)

def test_large_encrypt_decrypt(encrypter, decrypter):
    print(f"Encrypter: {type(encrypter)}")
    print(f"Decrypter: {type(decrypter)}")

    plaintext = b"A" * 64000

    enc_out = encrypter.update(plaintext)
    dec_out = decrypter.update(enc_out)
    assert(dec_out == plaintext)

def main() -> int:
    print("PySEcube Sample")

    secube_wrapper = None

    try:
        # Create new wrapper instance, this will do a couple of things:
        # 1. Load DLL (Shared objects can be used but haven't been implemented
        #              into the wrapper yet)
        # 2. Setup boiler plate (i.e. Setup argument/return types of functions)
        # 3. Create L0 library handle
        # 4. Check that 1 or more SEcube devices are connected, if not,
        #    an Exception is raised
        # 5. Create L1 library handle
        # 6. If the pin is specified (Either as bytes or a List of integers),
        #    a login is attempted as ACCESS_MODE_USER with the given pin
        secube_wrapper = Wrapper(b"test")

        # Delete key if already exists
        if secube_wrapper.key_exists(AES_KEY_ID):
            secube_wrapper.delete_key(AES_KEY_ID)
        
        # Add key (only for testing; hence the 1 minute valid time)
        # Will be deleted at the end of the test
        secube_wrapper.add_key(AES_KEY_ID, b"AESTestKey", AES_KEY_BYTES, 60)

        # Once the function exits the __del__ function of the wrapper is called,
        #   performing the following:
        # 1. If the wrapper is logged in, the wrapper will logout
        # 2. Destroy L1 library handle
        # 3. Destroy L0 library handle

        # Set the crypto time to now, this is equivalent to executing
        #   L1CryptoSetTime(time(0)), from the C++ host libraries
        secube_wrapper.crypto_set_time_now()

        # Plaintext to Encrypt as bytes
        plaintext = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"
        print(f"Plaintext length: {len(plaintext)}")
        print(f"Plaintext HEX: 0x{plaintext.hex()}")
        print(f"Plaintext text: {plaintext.decode()}")

        # openssl_enc_out = openssl_enc_engine.update(plaintext)
        # print(f"OpenSSL ENC output length: {len(openssl_enc_out)}")
        # print(f"OpenSSL ENC output HEX: 0x{openssl_enc_out.hex()}")

        # Create OpenSSL cipher engine
        openssl_engine = Cipher(algorithm = algorithms.AES(AES_KEY_BYTES),
                                mode = modes.CTR(CTR_NONCE),
                                backend = default_backend()) # OpenSSL backend

        # 1. Encrypt w. SEcube and decrypt w. SEcube
        print("> ENC. SEcube - DEC. SEcube <")

        # Create PySEcube encryptor and decryptor
        encrypter = secube_wrapper.get_crypter(
            ALGORITHM_AES, MODE_ENCRYPT | FEEDBACK_CTR, AES_KEY_ID, iv=CTR_NONCE
        )
        decrypter = secube_wrapper.get_crypter(
            ALGORITHM_AES, MODE_DECRYPT | FEEDBACK_CTR, AES_KEY_ID, iv=CTR_NONCE
        )
        test_encrypt_decrypt(plaintext, encrypter, decrypter)
        test_large_encrypt_decrypt(encrypter, decrypter)

        # 2. Encrypt w. OpenSSL and decrypt w. SEcube
        print("> ENC. OpenSSL - DEC. SEcube <")
        encrypter = openssl_engine.encryptor()
        decrypter = secube_wrapper.get_crypter(
            ALGORITHM_AES, MODE_DECRYPT | FEEDBACK_CTR, AES_KEY_ID, iv=CTR_NONCE
        )
        test_encrypt_decrypt(plaintext, encrypter, decrypter)
        test_large_encrypt_decrypt(encrypter, decrypter)
        
        # 3. Encrypt w. SEcube and decrypt w. OpenSSL
        print("> ENC. SEcube - DEC. OpenSSL <")
        encrypter = secube_wrapper.get_crypter(
            ALGORITHM_AES, MODE_ENCRYPT | FEEDBACK_CTR, AES_KEY_ID, iv=CTR_NONCE
        )
        decrypter = openssl_engine.decryptor()
        test_encrypt_decrypt(plaintext, encrypter, decrypter)
        test_large_encrypt_decrypt(encrypter, decrypter)

        # Remove the test key
        secube_wrapper.delete_key(AES_KEY_ID)

    except PySEcubeException as e:
        print(e)
        return 1
    return 0

if __name__ == "__main__":
    exit(main())
