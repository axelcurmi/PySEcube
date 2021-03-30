import argparse
import logging

from pysecube import (Wrapper,
                      PySEcubeException)

# Set logger to INFO, this can be ommitted to produce no logs
logging.basicConfig()
logging.getLogger("pysecube").setLevel(logging.INFO)

# This script will add/remove a zero key for SHA256. This is due to a bug in the
# SEcube source code, as every operation (even hashing)
# requires a valid key id. Hence, we will be adding a key with all zero bytes
# for the purpose of hashing.
def main() -> int:
    argparser = argparse.ArgumentParser(description=f"PySEcube {__file__}")
    argparser.add_argument("--key-ids", "-k", type=int, nargs="+",
                           required=True,
                           help="Key IDs to remove from the SEcube device.")
    args = argparser.parse_args()

    secube_wrapper = None

    try:
        secube_wrapper = Wrapper(b"test")

        for key_id in args.key_ids:
            print(f"Removing key with ID:{key_id}")
            secube_wrapper.delete_key(key_id)

    except PySEcubeException as e:
        print(e)
        return 1
    return 0
if __name__ == "__main__":
    exit(main())
