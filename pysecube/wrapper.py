import time
import threading

from _secube import ffi, lib

from logging import (getLogger, DEBUG, INFO)
from typing import (List, Union)

from pysecube.crypter import Crypter
from pysecube.secube_exception import (PySEcubeException,
                                       NoSEcubeDeviceConnected,
                                       InvalidPinException,
                                       SE3KeyInvalidSizeException)
from pysecube.common import (MAX_LENGTH_L1KEY_DATA,
                             MAX_LENGTH_PIN,
                             MAX_LENGTH_L1KEY_NAME,
                             ACCESS_MODE_USER,
                             DIGEST_SIZE_TABLE,
                             ALGORITHM_SHA256,
                             ALGORITHM_HMACSHA256,
                             KEY_EDIT_OP_INSERT,
                             KEY_EDIT_OP_DELETE)

class Wrapper(object):
    LOGGER_NAME = "pysecube.wrapper"

    def __init__(self, pin: Union[List[int], bytes] = None):
        self._logger = getLogger(Wrapper.LOGGER_NAME)

        self._l0 = None
        self._l1 = None
        self._lock = threading.Lock()

        self.logged_in = False
        self.crypto_sessions = []

        self._create_libraries()
        
        if pin is not None:
            self.login(pin, ACCESS_MODE_USER)

    def destroy(self) -> None:
        # Close all crypto sessions prior to logging out
        for session in self.crypto_sessions:
            session.close()

        if self.logged_in:
            self.logout()

        if self._l1 is not None:
            lib.L1_Destroy(self._l1)
            self._l1 = None
            self._logger.log(DEBUG, "L1 destroyed")

        if self._l0 is not None:
            lib.L0_Destroy(self._l0)
            self._l0 = None
            self._logger.log(DEBUG, "L0 destroyed")

    def login(self, pin: Union[List[int], bytes], access: int,
              force: bool = True) -> None:
        if len(pin) > MAX_LENGTH_PIN:
            raise InvalidPinException(f"Pin exceeds length of {MAX_LENGTH_PIN}")

        c_pin = None
        if isinstance(pin, bytes):
            c_pin = ffi.new("char[32]", pin)
        else:
            raise Exception("NOT IMPLEMENTED YET") # TODO

        res = lib.L1_Login(self._l1, c_pin, access, force)
        if res < 0:
            raise InvalidPinException("Invalid pin")
        self.logged_in = True
        self._logger.log(INFO, "Logged in")

    def logout(self) -> None:
        res = lib.L1_Logout(self._l1)
        self.logged_in = False
        if res < 0:
            raise PySEcubeException("Failed during logout")
        self._logger.log(INFO, "Logged out")

    def key_exists(self, id: int) -> bool:
        self._lock.acquire()
        try:
            key_exists = lib.L1_FindKey(self._l1, id) == 1
        finally:
            self._lock.release()
        return key_exists

    def delete_key(self, id: int) -> None:
        self._lock.acquire()
        try:
            res = lib.L1_KeyEdit(self._l1, id, 0, 0, 0, ffi.NULL, ffi.NULL,
                                 KEY_EDIT_OP_DELETE)
        finally:
            self._lock.release()
        if res < 0:
            raise PySEcubeException("Failed to delete key")
        self._logger.log(DEBUG, "Key with ID:%d deleted successfully", id)

    def add_key(self, id: int, name: bytes, data: bytes, validity: int) -> None:
        name_size = len(name)
        data_size = len(data)

        if name_size >= MAX_LENGTH_L1KEY_NAME:
            raise SE3KeyInvalidSizeException("SE3Key name exceeds {} bytes",
                                             MAX_LENGTH_L1KEY_NAME - 1)
        if data_size > MAX_LENGTH_L1KEY_DATA:
            raise SE3KeyInvalidSizeException("SE3Key data exceeds {} bytes",
                                             MAX_LENGTH_L1KEY_DATA)
        validity = int(time.time()) + 3600

        self._lock.acquire()
        try:
            res = lib.L1_KeyEdit(self._l1, id, validity, data_size, name_size,
                                 ffi.from_buffer(data), ffi.from_buffer(name),
                                 KEY_EDIT_OP_INSERT)
        finally:
            self._lock.release()
        if res < 0:
            raise PySEcubeException("Failed to add key")
        self._logger.log(DEBUG, "Key with ID:%d added successfully", id)

    def crypto_set_time_now(self) -> None:
        res = lib.L1_CryptoSetTimeNow(self._l1)
        if res < 0:
            raise PySEcubeException("Failed to set crypto time")
        self._logger.log(DEBUG, "Crypto time set to now")

    def get_crypter(self, algorithm: int, flags: int, key_id: int,
                    iv: bytes = None) -> Crypter:
        session = Crypter(self, algorithm, flags, key_id, iv)
        self.crypto_sessions.append(session)

        return session

    def crypto_init(self, algorithm: int, flags: int, key_id: int) -> int:
        session_id = ffi.new("uint32_t *")

        self._lock.acquire()
        try:
            res = lib.CryptoInit(self._l1, algorithm, flags, key_id,
                                 session_id)
        finally:
            self._lock.release()
        if res < 0:
            raise PySEcubeException("Failed to initialise crypto session")
        return session_id[0]

    def crypto_update(self, session_id: int, flags: int, data1: bytes = None,
                      data2: bytes = None, max_out_len: int = 0) -> bytes:
        # Data 1
        data1_len = 0
        data1_buffer = ffi.NULL
        if data1 is not None:
            data1_len = len(data1)
            data1_buffer = ffi.from_buffer(data1)

        # Data 2
        data2_len = 0
        data2_buffer = ffi.NULL
        if data2 is not None:
            data2_len = len(data2)
            data2_buffer = ffi.from_buffer(data2)

        out_len = ffi.NULL
        out_buffer = ffi.NULL
        if max_out_len > 0:
            out_len = ffi.new("uint16_t *")
            out_buffer = ffi.new("uint8_t[]", max_out_len)

        self._lock.acquire()
        try:
            res = lib.CryptoUpdate(self._l1, session_id, flags, data1_len,
                                   data1_buffer, data2_len, data2_buffer,
                                   out_len, out_buffer)
        finally:
            self._lock.release()

        if res < 0:
            raise PySEcubeException("Failed to perform crypto update")
        return None if out_len == ffi.NULL else \
            ffi.buffer(out_buffer, out_len[0])[:]

    def sha256(self, data_in: bytes) -> bytes:
        data_in_buffer = ffi.from_buffer(data_in)

        data_out_len = ffi.new("uint16_t *")
        data_out_buffer = ffi.new(
            "uint8_t[]", DIGEST_SIZE_TABLE[ALGORITHM_SHA256]
        )

        self._lock.acquire()
        try:
            if lib.DigestSHA256(self._l1, len(data_in), data_in_buffer,
                                data_out_len, data_out_buffer) < 0:
                raise PySEcubeException("Failed to create SHA256 digest")
        finally:
            self._lock.release()
        return ffi.buffer(data_out_buffer, data_out_len[0])[:]

    def compute_hmac(self, key_id: int, data_in: bytes) -> bytes:
        data_in_buffer = ffi.from_buffer(data_in)

        data_out_len = ffi.new("uint16_t *")
        data_out_buffer = ffi.new(
            "uint8_t[]", DIGEST_SIZE_TABLE[ALGORITHM_HMACSHA256]
        )

        self._lock.acquire()
        try:
            if lib.DigestHMACSHA256(self._l1, key_id, len(data_in),
                                    data_in_buffer, data_out_len,
                                    data_out_buffer) < 0:
                raise PySEcubeException("Failed to create SHA256 HMAC")
        finally:
            self._lock.release()
        return ffi.buffer(data_out_buffer, data_out_len[0])[:]

    def _create_libraries(self) -> None:
        self._l0 = lib.L0_Create()
        self._logger.log(DEBUG, "L0 created")

        device_count = lib.L0_GetNumberDevices(self._l0)
        if device_count < 1:
            raise NoSEcubeDeviceConnected("No SEcube device connected")
        self._logger.log(DEBUG, "SEcube devices connected: %d", device_count)

        self._l1 = lib.L1_Create()
        self._logger.log(DEBUG, "L1 created")
