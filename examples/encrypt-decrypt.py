import logging

from pysecube import (Wrapper,
                      PySEcubeException)

# Set logger level to DEBUG
logging.basicConfig()
logging.getLogger("pysecube").setLevel(logging.INFO)

def main() -> int:
    print("PySEcubeWrapper")

    secube_wrapper = None

    try:
        secube_wrapper = Wrapper("test")
    except PySEcubeException as e:
        print(e)
        return 1
    return 0

if __name__ == "__main__":
    exit(main())
