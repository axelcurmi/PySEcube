import os
import time
import threading

from ctypes import (CDLL,
                    c_byte,
                    c_bool,
                    c_int8,
                    c_uint8,
                    c_uint16,
                    c_uint32,
                    c_double,
                    POINTER,
                    cast,
                    byref,
                    create_string_buffer,
                    string_at)
from logging import (getLogger, DEBUG, INFO)
from typing import (List, Union)

from pysecube.crypter import Crypter
from pysecube.secube_exception import (PySEcubeException,
                                       NoSEcubeDeviceConnected,
                                       InvalidPinException,
                                       SE3KeyInvalidSizeException)
from pysecube.common import (ENV_NAME_SHARED_LIB_PATH,
                             DLL_NAME,
                             MAX_LENGTH_L1KEY_DATA,
                             MAX_LENGTH_PIN,
                             MAX_LENGTH_L1KEY_NAME,
                             ACCESS_MODE_USER,
                             DIGEST_SIZE_TABLE,
                             ALGORITHM_SHA256,
                             KEY_EDIT_OP_INSERT,
                             KEY_EDIT_OP_DELETE)

LibraryHandle = POINTER(c_byte)

class Wrapper(object):
    PYSECUBEPATH = os.environ[ENV_NAME_SHARED_LIB_PATH]
    LOGGER_NAME = "pysecube.wrapper"

    def __init__(self, pin: Union[List[int], bytes] = None,
                 lib_path: str = None):
        self._logger = getLogger(Wrapper.LOGGER_NAME)
        self._lib = None
        self._l0 = None
        self._l1 = None
        self._lock = threading.Lock()

        self.logged_in = False
        self.crypto_sessions = []

        self._load_library(lib_path)
        self._setup_boilerplate()
        self._create_libraries()
        
        if pin is not None:
            self.login(pin, ACCESS_MODE_USER)

    def destroy(self) -> None:
        # Close all crypto sessions prior to logging out
        for session in self.crypto_sessions:
            try:
                session.close()
            except PySEcubeException:
                pass
        
        if self.logged_in:
            self.logout()

        if self._l1 is not None:
            self._lock.acquire()
            try:
                self._lib.L1_Destroy(self._l1)
            finally:
                self._lock.release()
            self._l1 = None
            self._logger.log(DEBUG, "L1 destroyed")

        if self._l0 is not None:
            self._lock.acquire()
            try:
                self._lib.L0_Destroy(self._l0)
            finally:
                self._lock.release()
            self._l0 = None
            self._logger.log(DEBUG, "L0 destroyed")

    def get_metrics(self) -> dict:

        find_key_count = c_uint32()
        find_key_time = c_double()

        key_edit_count = c_uint32()
        key_edit_time = c_double()

        crypto_init_count = c_uint32()
        crypto_init_time = c_double()

        crypto_update_count = c_uint32()
        crypto_update_time = c_double()

        self._lock.acquire()
        try:
            self._lib.L1_GetMetrics(self._l1,
                                    byref(find_key_count),
                                    byref(find_key_time),
                                    byref(key_edit_count),
                                    byref(key_edit_time),
                                    byref(crypto_init_count),
                                    byref(crypto_init_time),
                                    byref(crypto_update_count),
                                    byref(crypto_update_time))
        finally:
            self._lock.release()
        
        return {
            "find_key_count": find_key_count.value,
            "find_key_time": find_key_time.value,
            "key_edit_count": key_edit_count.value,
            "key_edit_time": key_edit_time.value,
            "crypto_init_count": crypto_init_count.value,
            "crypto_init_time": crypto_init_time.value,
            "crypto_update_count": crypto_update_count.value,
            "crypto_update_time": crypto_update_time.value
        }

    def login(self, pin: Union[List[int], bytes], access: int,
              force: bool = True) -> None:
        if len(pin) > MAX_LENGTH_PIN:
            raise InvalidPinException(f"Pin exceeds length of {MAX_LENGTH_PIN}")

        c_pin = None
        if isinstance(pin, bytes):
            c_pin = cast(create_string_buffer(pin, MAX_LENGTH_PIN),
                         POINTER(c_uint8))
        else:
            c_pin = (c_uint8 * MAX_LENGTH_PIN)(*pin)

        res = self._lib.L1_Login(self._l1, c_pin, access, force)
        if res < 0:
            raise InvalidPinException("Invalid pin")
        self.logged_in = True
        self._logger.log(INFO, "Logged in")

    def logout(self) -> None:
        self._lock.acquire()
        try:
            res = self._lib.L1_Logout(self._l1)
        finally:
            self._lock.release()

        self.logged_in = False
        if res < 0:
            raise PySEcubeException("Failed during logout")
        self._logger.log(INFO, "Logged out")

    def key_exists(self, id: int) -> bool:
        key_exists = False

        self._lock.acquire()
        try:
            key_exists = self._lib.L1_FindKey(self._l1, id) == 1
        finally:
            self._lock.release()

        return key_exists

    def delete_key(self, id: int) -> None:
        self._lock.acquire()
        try:
            res = self._lib.L1_KeyEdit(self._l1,
                                    id,      # id
                                    0,       # validity
                                    0,       # data size
                                    0,       # name size
                                    None,    # data buffer
                                    None,    # name buffer
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

        data_buffer = cast(create_string_buffer(data, data_size),
                           POINTER(c_uint8))
        name_buffer = cast(create_string_buffer(name, name_size),
                           POINTER(c_uint8))

        self._lock.acquire()
        try:
            res = self._lib.L1_KeyEdit(self._l1,
                                    id,
                                    int(time.time()) + validity,
                                    data_size,
                                    name_size + 1,
                                    data_buffer,
                                    name_buffer,
                                    KEY_EDIT_OP_INSERT)
        finally:
            self._lock.release()

        if res < 0:
            raise PySEcubeException("Failed to add key")
        self._logger.log(DEBUG, "Key with ID:%d added successfully", id)

    def crypto_set_time_now(self) -> None:
        self._lock.acquire()
        try:
            res = self._lib.L1_CryptoSetTimeNow(self._l1)
        finally:
            self._lock.release()

        if res < 0:
            raise PySEcubeException("Failed to set crypto time")
        self._logger.log(DEBUG, "Crypto time set to now")

    def get_crypter(self, algorithm: int, flags: int, key_id: int,
                    iv: bytes = None) -> Crypter:
        session = Crypter(self, algorithm, flags, key_id, iv)
        self.crypto_sessions.append(session)
        return session

    def crypto_init(self, algorithm: int, flags: int, key_id: int) -> int:
        session_id = c_uint32()
        
        self._lock.acquire()
        try:
            res = self._lib.CryptoInit(self._l1, algorithm, flags, key_id,
                byref(session_id))
        finally:
            self._lock.release()

        if res < 0:
            raise PySEcubeException("Failed to initialise crypto session")
        return session_id.value

    def crypto_update(self, session_id: int, flags: int, data1: bytes = None,
                      data2: bytes = None, max_out_len: int = 0) -> bytes:
        # Data 1
        data1_len = 0
        data1_buffer = None
        if data1 is not None:
            data1_len = len(data1)
            data1_buffer = cast(create_string_buffer(data1, data1_len),
                                POINTER(c_uint8))

        # Data 2
        data2_len = 0
        data2_buffer = None
        if data2 is not None:
            data2_len = len(data2)
            data2_buffer = cast(create_string_buffer(data2, data2_len),
                                POINTER(c_uint8))

        out_len = None
        out_buffer = None
        if max_out_len > 0:
            out_len = c_uint16()
            out_buffer = cast(create_string_buffer(max_out_len),
                              POINTER(c_uint8))

        self._lock.acquire()
        try:
            res = self._lib.CryptoUpdate(self._l1, session_id, flags, data1_len,
                                         data1_buffer, data2_len, data2_buffer,
                                         None if out_len is None \
                                             else byref(out_len),
                                         out_buffer)
        finally:
            self._lock.release()

        if res < 0:
            raise PySEcubeException("Failed to perform crypto update")
        return None if out_len is None else string_at(out_buffer,
                                                      out_len.value)

    def sha256(self, data_in: bytes) -> bytes:
        data_in_len = len(data_in)
        data_in_buffer = cast(create_string_buffer(data_in, data_in_len),
                              POINTER(c_uint8))

        data_out_len = c_uint16()
        data_out_buffer = cast(
            create_string_buffer(DIGEST_SIZE_TABLE[ALGORITHM_SHA256]),
            POINTER(c_uint8))

        self._lock.acquire()
        try:
            if self._lib.DigestSHA256(self._l1, data_in_len, data_in_buffer,
                                    byref(data_out_len), data_out_buffer) < 0:
                raise PySEcubeException("Failed to create SHA256 digest")
        finally:
            self._lock.release()
        return string_at(data_out_buffer, data_out_len.value)

    # internal
    def _load_library(self, lib_path: str = None) -> None:
        if lib_path is None:
            lib_path = os.path.join(Wrapper.PYSECUBEPATH, DLL_NAME)
        self._logger.log(DEBUG, "Loading library from %s", lib_path)
        self._lib = CDLL(lib_path, winmode=0x00000008)

    def _setup_boilerplate(self) -> None:
        # L0
        self._lib.L0_Create.restype = LibraryHandle
        self._lib.L0_Destroy.argtypes = [LibraryHandle]

        self._lib.L0_GetNumberDevices.argtypes = [LibraryHandle]
        self._lib.L0_GetNumberDevices.restype = c_uint8

        # L1
        self._lib.L1_Create.restype = LibraryHandle
        self._lib.L1_Destroy.argtypes = [LibraryHandle]

        self._lib.L1_GetMetrics.argtypes = [LibraryHandle,
                                            POINTER(c_uint32), POINTER(c_double),
                                            POINTER(c_uint32), POINTER(c_double),
                                            POINTER(c_uint32), POINTER(c_double),
                                            POINTER(c_uint32), POINTER(c_double)]

        self._lib.L1_Login.argtypes = [LibraryHandle, POINTER(c_uint8),
                                       c_uint16, c_bool]
        self._lib.L1_Login.restype = c_int8

        self._lib.L1_Logout.argtypes = [LibraryHandle]
        self._lib.L1_Logout.restype = c_int8

        self._lib.L1_FindKey.argtypes = [LibraryHandle, c_uint32]
        self._lib.L1_FindKey.restype = c_int8

        self._lib.L1_KeyEdit.argtypes = [LibraryHandle, c_uint32, c_uint32,
                                         c_uint16, c_uint16, POINTER(c_uint8),
                                         POINTER(c_uint8), c_uint16]
        self._lib.L1_KeyEdit.restype = c_int8

        self._lib.L1_CryptoSetTimeNow.argtypes = [LibraryHandle]
        self._lib.L1_CryptoSetTimeNow.restype = c_int8

        self._lib.CryptoInit.argtypes = [LibraryHandle, c_uint16, c_uint16,
                                         c_uint32, POINTER(c_uint32)]
        self._lib.CryptoInit.restype = c_int8

        self._lib.CryptoUpdate.argtypes = [LibraryHandle, c_uint32, c_uint16,
                                           c_uint16, POINTER(c_uint8), c_uint16,
                                           POINTER(c_uint8), POINTER(c_uint16),
                                           POINTER(c_uint8)]
        self._lib.CryptoUpdate.restype = c_int8

        self._lib.DigestSHA256.argtypes = [LibraryHandle, c_uint16,
                                           POINTER(c_uint8), POINTER(c_uint16),
                                           POINTER(c_uint8)]
        self._lib.DigestSHA256.restype = c_int8

    def _create_libraries(self) -> None:
        self._l0 = self._lib.L0_Create()
        self._logger.log(DEBUG, "L0 created")

        device_count = self._lib.L0_GetNumberDevices(self._l0)
        if device_count < 1:
            raise NoSEcubeDeviceConnected("No SEcube device connected")
        self._logger.log(DEBUG, "SEcube devices connected: %d", device_count)

        self._l1 = self._lib.L1_Create()
        self._logger.log(DEBUG, "L1 created")
