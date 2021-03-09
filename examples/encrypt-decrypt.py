import logging

from pysecube import (Wrapper,
                      NoSEcubeDeviceConnected)

# Set logger level to DEBUG
logging.basicConfig()
logging.getLogger("pysecube").setLevel(logging.DEBUG)

def main() -> int:
    print("PySEcubeWrapper")

    secube_wrapper = None

    try:
        secube_wrapper = Wrapper()
    except NoSEcubeDeviceConnected as e:
        print(e)
        return 1
    return 0

if __name__ == "__main__":
    exit(main())
