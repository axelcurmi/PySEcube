import argparse
import logging

from pysecube import (Wrapper,
                      PySEcubeException)

# Set logger to INFO, this can be ommitted to produce no logs
logging.basicConfig()
logging.getLogger("pysecube").setLevel(logging.INFO)

DIGEST_KEY_ID = 0
VALID_FOR_SECS = 3600 * 24 * 365 # 1 Year

# This script will add/remove a zero key for SHA256. This is due to a bug in the
# SEcube source code, as every operation (even hashing)
# requires a valid key id. Hence, we will be adding a key with all zero bytes
# for the purpose of hashing.
def main() -> int:
    argparser = argparse.ArgumentParser(description=f"PySEcube {__file__}")
    argparser.add_argument("--rollback", "-r", action="store_true",
                           help="Rollback the addition of zero key.")
    args = argparser.parse_args()

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

        if not args.rollback and secube_wrapper.key_exists(DIGEST_KEY_ID):
            print(f"Key with ID:{DIGEST_KEY_ID} already exists")
            return 1
        elif args.rollback and not secube_wrapper.key_exists(DIGEST_KEY_ID):
            print(f"Key with ID:{DIGEST_KEY_ID} does not exist")
            return 1

        if not args.rollback:
            secube_wrapper.add_key(DIGEST_KEY_ID, b"DigestKey", b"\00" * 32,
                                   VALID_FOR_SECS)
            print(f"Key with ID:{DIGEST_KEY_ID} added for {VALID_FOR_SECS}s")
        else:
            secube_wrapper.delete_key(DIGEST_KEY_ID)    
            print(f"Key with ID:{DIGEST_KEY_ID} removed") 

    except PySEcubeException as e:
        print(e)
        return 1
    return 0
if __name__ == "__main__":
    exit(main())
