import logging

# Using same cryptography module as Paramiko
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

from pysecube.common import MODE_ENCRYPT
from pysecube import (Wrapper,
                      PySEcubeException,
                      ALGORITHM_AES,
                      FEEDBACK_CTR)

# Set logger to INFO, this can be ommitted to produce no logs
logging.basicConfig()
logging.getLogger("pysecube").setLevel(logging.INFO)

# Use key with ID 10 stored in the SEcube device
AES_KEY_ID = 10
AES_KEY_BYTES = b"\x01\x02\x03\x04\x05\x06\x07\x08" + \
                b"\x01\x02\x03\x04\x05\x06\x07\x08" + \
                b"\x01\x02\x03\x04\x05\x06\x07\x08" + \
                b"\x01\x02\x03\x04\x05\x06\x07\x08" # 32 byte AES key
CTR_NONCE     = b"\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8" + \
                b"\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8" # 16 byte CTR nonce

def main() -> int:
    print("PySEcube Sample")

    secube_wrapper = None

    cipher = Cipher(algorithm = algorithms.AES(AES_KEY_BYTES),
                    mode = modes.CTR(CTR_NONCE),
                    backend = default_backend()) # OpenSSL backend
    enc_engine = cipher.encryptor()
    dec_engine = cipher.decryptor()

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
        plaintext = b"AAAABBBBCCCCDDDD"
        print(f"Plaintext length: {len(plaintext)}")
        print(f"Plaintext HEX: 0x{plaintext.hex()}")
        print(f"Plaintext text: {plaintext.decode()}")

        # Encryption of the plaintext is performed using following arguments:
        # 1. algorithm: Algorithm to be used for encryption
        # 2. mode:      Algorithm mode to be used for encryption
        # 3. key_id:    Key ID stored on the SEcube device
        # 4. data_in:   The plaintext to encrypt
        secube_enc_out = secube_wrapper.crypt(ALGORITHM_AES, FEEDBACK_CTR,
                                              AES_KEY_ID, plaintext,
                                              CTR_NONCE)

        print(f"SEcube ENC output length: {len(secube_enc_out)}")
        print(f"SEcube ENC output HEX: 0x{secube_enc_out.hex()}")

        openssl_enc_out = enc_engine.update(plaintext)
        print(f"OpenSSL ENC output length: {len(openssl_enc_out)}")
        print(f"OpenSSL ENC output HEX: 0x{openssl_enc_out.hex()}")

        # Decryption (since we are using CTR, we can decrypt with encrypt func)
        # Preferred cipher in Paramiko is AES-128 with CTR; hence why we're
        #   using CTR in this test

        # 1. Encrypt w. SEcube and decrypt w. SEcube
        print("> ENC. SEcube - DEC. SEcube <")
        secube_secube = secube_wrapper.crypt(ALGORITHM_AES, FEEDBACK_CTR,
                                             AES_KEY_ID, secube_enc_out,
                                             CTR_NONCE)

        print(f"Output length: {len(secube_secube)}")
        print(f"Output HEX 0x{secube_secube.hex()}")
        print(f"Output text: {secube_secube.decode()}")
        assert(secube_secube == plaintext)

        # 2. Encrypt w. OpenSSL and decrypt w. SEcube
        print("> ENC. OpenSSL - DEC. SEcube <")
        openssl_secube = secube_wrapper.crypt(ALGORITHM_AES, FEEDBACK_CTR,
                                              AES_KEY_ID, openssl_enc_out,
                                              CTR_NONCE)
        print(f"Output length: {len(openssl_secube)}")
        print(f"Output HEX 0x{openssl_secube.hex()}")
        print(f"Output text: {openssl_secube.decode()}")
        assert(openssl_secube == plaintext)

        # 3. Encrypt w. SEcube and decrypt w. OpenSSL
        print("> ENC. SEcube - DEC. OpenSSL <")
        secube_openssl = dec_engine.update(secube_enc_out)
        print(f"Output length: {len(secube_openssl)}")
        print(f"Output HEX 0x{secube_openssl.hex()}")
        print(f"Output text: {secube_openssl.decode()}")
        assert(secube_openssl == plaintext)

        # Remove the test key
        secube_wrapper.delete_key(AES_KEY_ID)

    except PySEcubeException as e:
        print(e)
        return 1
    return 0

if __name__ == "__main__":
    exit(main())
