from pysecube import Wrapper

"""
Designed to be a one-time set class containing all of  the required information
to perform encryption/decryption using the PySEcube wrapper. It is important
to note that this class does not add/remove the key to/from the SEcube device.
"""
class Crypter(object):
    def __init__(self, wrapper: Wrapper, algorithm: int, flags: int,
                 key_id: int, iv: bytes = None):
        self._wrapper = wrapper
        self._algorithm = algorithm
        self._flags = flags
        self._key_id = key_id
        self._iv = iv

    def update(self, data_in: bytes) -> bytes:
        return self._wrapper.crypt(self._algorithm, self._flags, self._key_id,
                                   data_in, iv=self._iv)
