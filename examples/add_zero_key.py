import logging

from pysecube import (Wrapper,
                      PySEcubeException,
                      ALGORITHM_AES,
                      FEEDBACK_CTR)

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

        secube_wrapper.delete_key(1)

        # TODO: Add note on why we are adding a key for SHA256, eventhough it is
        #       a hash function; thus, does not use a key.
        secube_wrapper.add_key(1, b"SHA256", b"\00" * 32, 3600)

    except PySEcubeException as e:
        print(e)
        return 1
    return 0
if __name__ == "__main__":
    exit(main())
