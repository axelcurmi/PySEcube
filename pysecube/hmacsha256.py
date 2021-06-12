from logging import (getLogger, DEBUG)

from pysecube.common import (DIGEST_SIZE_TABLE,
                             CRYPTO_UPDATE_FINIT,
                             ALGORITHM_HMACSHA256)

class HMACSHA256(object):
    LOGGER_NAME = "pysecube.crypter"

    def __init__(self, wrapper, key_id: int, data_in: bytes = None):
        self._logger = getLogger(HMACSHA256.LOGGER_NAME)

        self.__session_id = None
        self.__wrapper = wrapper

        self.__session_id = self.__wrapper.crypto_init(
            ALGORITHM_HMACSHA256, 0, key_id)
        self._logger.log(DEBUG, "HMACSHA256 session created with ID: %d",
            self.__session_id)

        if data_in is not None:
            self.update(data_in)

    def update(self, data_in: bytes):
        if data_in == b"" or data_in is None:
            return

        self.__wrapper.crypto_update(self.__session_id, 0, data1=data_in)

    def digest(self):
        return self.__wrapper.crypto_update(
            self.__session_id,
            CRYPTO_UPDATE_FINIT,
            max_out_len=DIGEST_SIZE_TABLE[ALGORITHM_HMACSHA256])
