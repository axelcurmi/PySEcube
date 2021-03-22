import logging

from pysecube import (Wrapper,
                      PySEcubeException,
                      ALGORITHM_AES,
                      FEEDBACK_CTR)

# Set logger to INFO, this can be ommitted to produce no logs
logging.basicConfig()
logging.getLogger("pysecube").setLevel(logging.INFO)

# Use key with ID 2000 stored in the SEcube device
AES_KEY_ID = 2000

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

        # Once the function exits the __del__ function of the wrapper is called,
        #   performing the following:
        # 1. If the wrapper is logged in, the wrapper will logout
        # 2. Destroy L1 library handle
        # 3. Destroy L0 library handle

        # Set the crypto time to now, this is equivalent to executing
        #   L1CryptoSetTime(time(0)), from the C++ host libraries
        secube_wrapper.crypto_set_time_now()

        # Plaintext to Encrypt as bytes
        plaintext = b"PySEcube"
        print(f"Plaintext Length: {len(plaintext)}")
        print(f"Plaintext in HEX: 0x{plaintext.hex()}")
        # stdout >
        #   Plaintext Length: 8
        #   Plaintext in HEX: 0x5079534563756265

        # Encryption of the plaintext is performed using following arguments:
        # 1. key_id:    Key ID stored on the SEcube device
        # 2. algorithm: Algorithm to be used for encryption
        # 3. mode:      Algorithm mode to be used for encryption
        # 4. data_in:   The plaintext to encrypt
        enc_out_len, enc_out = secube_wrapper.encrypt(AES_KEY_ID,
                                                      ALGORITHM_AES,
                                                      FEEDBACK_CTR,
                                                      plaintext)

        print(f"Encrypted output length: {enc_out_len}")
        print(f"Ciphertext output in HEX: 0x{enc_out.hex()}")
        # stdout >
        #   Encrypted output length: 16
        #   Ciphertext output in HEX: 0x2c620845f53ef014a61d3361ac89bcb5

        # Decryption is performed using the following arguments:
        # 1. key_id:    Key ID stored on the SEcube device
        # 2. algorithm: Algorithm to be used for decryption
        # 3. mode:      Algorithm mode to be used for decryption
        # 4. data_in:   The ciphertext to decrypt
        dec_out_len, dec_out = secube_wrapper.decrypt(AES_KEY_ID,
                                                  ALGORITHM_AES,
                                                  FEEDBACK_CTR,
                                                  enc_out)

        print(f"Decrypted output length: {dec_out_len}")
        print(f"Plaintext output in HEX 0x{dec_out.hex()}")
        print(f"Plaintext output as text: {dec_out.decode('ascii')}")
        # stdout > 
        #   Decrypted output length: 16
        #   Plaintext output in HEX 0x50795345637562650000000000000000
        #   Plaintext output as text: PySEcube
        
        print("Successful encryption-decryption? ", end="")
        print("\033[92mOK\033[0m" if dec_out == plaintext else \
              "\033[91mNO\033[0m")
        # stdout >
        #   Successful encryption-decryption? YES (There is a small issue with
        #   this comparison as the output from the digest contains trailing
        #   zeros; thus, resulting in the two not matching as expected)

    except PySEcubeException as e:
        print(e)
        return 1
    return 0

if __name__ == "__main__":
    exit(main())
