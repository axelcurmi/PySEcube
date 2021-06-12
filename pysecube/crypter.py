from logging import (getLogger, DEBUG)

from pysecube.common import (CRYPTO_UPDATE_SETIV,
                             CRYPTO_UPDATE_FINIT, MODE_ENCRYPT)
from pysecube.util import calc_enc_buffer_size

"""
Designed to be a one-time set class containing all of  the required information
to perform encryption/decryption using the PySEcube wrapper. It is important
to note that this class does not add/remove the key to/from the SEcube device.
"""
class Crypter(object):
    LOGGER_NAME = "pysecube.crypter"

    def __init__(self, wrapper, algorithm: int, flags: int,
                 key_id: int, iv: bytes = None):
        self._logger = getLogger(Crypter.LOGGER_NAME)

        self.__session_id = None
        self.__wrapper = wrapper
        self.__algorithm = algorithm
        self.__flags = flags

        # Create crypto session
        self.__session_id = self.__wrapper.crypto_init(algorithm, flags, key_id)

        # Set IV (if not None)
        if iv is not None:
            self.__wrapper.crypto_update(self.__session_id,
                                         CRYPTO_UPDATE_SETIV,
                                         data1=iv)

    def close(self) -> None:
        if self.__session_id is not None:
            self.__wrapper.crypto_update(self.__session_id, CRYPTO_UPDATE_FINIT)

        self._logger.log(DEBUG, "Crypto session terminated for %s",
            "encryption " if self.__flags & MODE_ENCRYPT > 0 else "decryption")

    def update(self, data_in: bytes) -> bytes:
        if data_in == b"" or data_in is None:
            return data_in

        max_out_len = len(data_in)

        if self.__flags & MODE_ENCRYPT:
            max_out_len = calc_enc_buffer_size(self.__algorithm, max_out_len)

        return self.__wrapper.crypto_update(self.__session_id, self.__flags,
                                            data2=data_in,
                                            max_out_len=max_out_len)
