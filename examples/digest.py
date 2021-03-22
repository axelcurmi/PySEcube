import hashlib
import logging

from pysecube import (Wrapper,
                      PySEcubeException)

# Set logger to INFO, this can be ommitted to produce no logs
logging.basicConfig()
logging.getLogger("pysecube").setLevel(logging.INFO)

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

        # Digest of some bytes (in this case the plaintext bytes):
        dig_out_len, dig_out = secube_wrapper.digest(plaintext)

        print(f"Digest output length: {dig_out_len}")
        print(f"Digest out in HEX 0x{dig_out.hex()}")
        # stdout >
        #   Digest output length: 32
        #   Digest out in HEX 0x1271397c7edec16bdb5600913cac23898fb48da6100471008f23b7e8e2deb817

        # To be sure the digest is correct, the SHA256 engine provided by the
        # hashlib module is used on the same bytes to compare with the one
        # provided by the SEcube device.
        m = hashlib.sha256()
        m.update(plaintext)
        hlib_dig_out = m.digest()

        print(f"Hashlib digest output length: {len(hlib_dig_out)}")
        print(f"Hashlib digest in HEX 0x{hlib_dig_out.hex()}")
        # stdout >
        #   Hashlib digest output length: 32
        #   Hashlib digest in HEX 0x1271397c7edec16bdb5600913cac23898fb48da6100471008f23b7e8e2deb817

        print("Successful digest? ", end="")
        print("\033[92mOK\033[0m" if hlib_dig_out == dig_out else \
              "\033[91mNO\033[0m")
        # stdout >
        #   Successful digest? YES
    except PySEcubeException as e:
        print(e)
        return 1
    return 0

if __name__ == "__main__":
    exit(main())