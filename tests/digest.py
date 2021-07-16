# Import hashlib and hmac for testing
import hashlib
from hmac import HMAC

import logging

from pysecube import (Wrapper,
                      PySEcubeException,
                      HMACSHA256)

# Set logger to INFO, this can be ommitted to produce no logs
logging.basicConfig()
logging.getLogger("pysecube").setLevel(logging.INFO)

# Use key with ID 10 stored in the SEcube device
HMAC_KEY_ID = 20
HMAC_KEY_BYTES = b"\x01\x02\x03\x04\x05\x06\x07\x08" + \
                 b"\x09\x10\x11\x12\x13\x14\x15\x16" + \
                 b"\x17\x18\x19\x20\x21\x22\x23\x24" + \
                 b"\x25\x26\x27\x28\x29\x30\x31\x32" # 32 byte key for HMAC

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
        if secube_wrapper.key_exists(HMAC_KEY_ID):
            secube_wrapper.delete_key(HMAC_KEY_ID)
        
        # Add key (only for testing; hence the 1 minute valid time)
        # Will be deleted at the end of the test
        secube_wrapper.add_key(HMAC_KEY_ID, b"HMACTestKey", HMAC_KEY_BYTES, 60)

        # Once the function exits the __del__ function of the wrapper is called,
        #   performing the following:
        # 1. If the wrapper is logged in, the wrapper will logout
        # 2. Destroy L1 library handle
        # 3. Destroy L0 library handle

        # Set the crypto time to now, this is equivalent to executing
        #   L1CryptoSetTime(time(0)), from the C++ host libraries
        secube_wrapper.crypto_set_time_now()

        # Plaintext to Encrypt as bytes
        plaintext = b"PySEcubePySEcubePySEcubePySEcube"

        # Digest of some bytes (in this case the plaintext bytes):
        dig_out = secube_wrapper.sha256(plaintext)

        print(f"Digest output length: {len(dig_out)}")
        print(f"Digest out in HEX 0x{dig_out.hex()}")
        # stdout >
        #   Digest output length: 32
        #   Digest out in HEX 0x1271397c7edec16bdb5600913cac23898fb48da6100471008f23b7e8e2deb817

        hmac_out = HMACSHA256(secube_wrapper, HMAC_KEY_ID, plaintext).digest()
        print(f"HMAC output length: {len(hmac_out)}")
        print(f"HMAC out in HEX 0x{hmac_out.hex()}")
        # stdout >
        #   HMAC output length: 32
        #   HMAC out in HEX 0x055ae4228245dfc262309b6f840dcbfc670c7946b909fa29963c2e806c5d7dd8

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

        py_hmac_out = HMAC(HMAC_KEY_BYTES, plaintext, hashlib.sha256).digest()
        print(f"Python HMAC output length: {len(py_hmac_out)}")
        print(f"Python HMAC out in HEX 0x{py_hmac_out.hex()}")
        # stdout >
        #   Python HMAC output length: 32
        #   Python HMAC out in HEX 0x055ae4228245dfc262309b6f840dcbfc670c7946b909fa29963c2e806c5d7dd8

        print("Successful digest? ", end="")
        print("\033[92mYES\033[0m" if hlib_dig_out == dig_out else \
              "\033[91mNO\033[0m")
        # stdout >
        #   Successful digest? YES

        print("Same HMAC? ", end="")
        print("\033[92mYES\033[0m" if py_hmac_out == hmac_out else \
              "\033[91mNO\033[0m")
        # stdout > 
        #   Same HMAC? YES

        secube_wrapper.destroy()

    except PySEcubeException as e:
        print(e)
        return 1
    return 0

if __name__ == "__main__":
    exit(main())
