import logging

from pysecube import (Wrapper,
                      PySEcubeException,
                      ALGORITHM_AES,
                      MODE_ENCRYPT,
                      MODE_DECRYPT,
                      FEEDBACK_CTR)

# Set logger level to DEBUG
logging.basicConfig()
logging.getLogger("pysecube").setLevel(logging.INFO)

AES_KEY_ID = 2000

def main() -> int:
    print("PySEcube Sample")

    secube_wrapper = None

    try:
        secube_wrapper = Wrapper("test")

        secube_wrapper.crypto_set_time_now()

        plaintext = "PySEcube".encode("ascii")
        enc_out_len, enc_out = secube_wrapper.encrypt(AES_KEY_ID,
                                                      ALGORITHM_AES,
                                                      FEEDBACK_CTR,
                                                      plaintext)
        print(enc_out_len)
        print(enc_out.hex())

        dec_len, dec_out = secube_wrapper.decrypt(AES_KEY_ID,
                                                  ALGORITHM_AES,
                                                  FEEDBACK_CTR,
                                                  enc_out)
        print(dec_len)
        print(dec_out.hex())
        print(dec_out.decode("ascii"))

    except PySEcubeException as e:
        print(e)
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
