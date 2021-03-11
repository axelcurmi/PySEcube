import math
import os

from ctypes import (CDLL,
                    c_byte,
                    c_bool,
                    c_size_t,
                    c_int8,
                    c_uint8,
                    c_uint16,
                    c_uint32,
                    POINTER,
                    cast,
                    byref,
                    create_string_buffer,
                    string_at)
from logging import (getLogger,
                     DEBUG,
                     INFO)
from typing import (List,
                    Tuple,
                    Union)

from pysecube.common import (ENV_NAME_SHARED_LIB_PATH,
                             DLL_NAME,
                             MAX_LENGTH_PIN,
                             ACCESS_MODE_USER,
                             BLOCK_SIZE_TABLE)
from pysecube.secube_exception import (NoSEcubeDeviceConnected,
                                       InvalidPinException, PySEcubeException)

LibraryHandle = POINTER(c_byte)


def calculate_buffer_size(algorithm: int, data_len: int) -> int:
    block_size = BLOCK_SIZE_TABLE[algorithm]
    return math.ceil(data_len / block_size) * block_size


class Wrapper(object):
    PYSECUBEPATH = os.environ[ENV_NAME_SHARED_LIB_PATH]
    LOGGER_NAME = "pysecube.wrapper"

    def __init__(self, pin: Union[List[int], str] = None):
        self._logger = getLogger(Wrapper.LOGGER_NAME)
        self._lib = None
        self._l0 = None
        self._l1 = None

        self.logged_in = False

        self._load_library()
        self._setup_boilerplate()
        self._create_libraries()
        
        if pin is not None:
            self.login(pin, ACCESS_MODE_USER)

    def __del__(self) -> None:
        if self.logged_in:
            self.logout()

        if self._l1 is not None:
            self._lib.L1_Destroy(self._l1)
            self._l1 = None
            self._logger.log(INFO, "L1 destroyed")

        if self._l0 is not None:
            self._lib.L0_destroy(self._l0)
            self._l0 = None
            self._logger.log(INFO, "L0 destroyed")

    def login(self, pin: Union[List[int], str], access: int,
              force: bool = True) -> None:
        if len(pin) > MAX_LENGTH_PIN:
            raise InvalidPinException(f"Pin exceeds length of {MAX_LENGTH_PIN}")

        c_pin = None
        if isinstance(pin, str):
            c_pin = cast(
                create_string_buffer(pin.encode("ascii"), MAX_LENGTH_PIN),
                POINTER(c_uint8))
        else:
            c_pin = (c_uint8 * MAX_LENGTH_PIN)(*pin)

        res = self._lib.L1_Login(self._l1, c_pin, access, force)
        if res < 0:
            raise InvalidPinException("Invalid pin")
        self.logged_in = True
        self._logger.log(INFO, "Logged in")

    def logout(self) -> None:
        res = self._lib.L1_Logout(self._l1)
        self.logged_in = False
        if res < 0:
            raise PySEcubeException("Failed during logout")
        self._logger.log(INFO, "Logged out")

    def crypto_set_time_now(self) -> None:
        res = self._lib.L1_CryptoSetTimeNow(self._l1)
        if res < 0:
            raise PySEcubeException("Failed to set crypto time")
        self._logger.log(INFO, "Crypto time set")

    def encrypt(self, key_id: int, algorithm: int, mode: int,
                data_in: bytes) -> Tuple[int, bytes]:
        data_in_len = len(data_in)
        buffer_len = calculate_buffer_size(algorithm, data_in_len)

        data_out_len = c_size_t(0)
        buffer_in = cast(create_string_buffer(data_in, buffer_len),
                       POINTER(c_int8))
        buffer_out = cast(create_string_buffer(buffer_len), POINTER(c_int8))

        res = self._lib.L1_Encrypt(self._l1, buffer_len, buffer_in,
                                   byref(data_out_len), buffer_out, algorithm,
                                   mode, key_id)
        if res < 0:
            raise PySEcubeException("Failed to encrypt")
        return (data_out_len.value, string_at(buffer_out, data_out_len.value))

    def decrypt(self, key_id: int, algorithm: int, mode: int,
                data_in: bytes) -> Tuple[int, bytes]:
        data_in_len = len(data_in)
        print(data_in_len)

        data_out_len = c_size_t(0)
        buffer_in = cast(create_string_buffer(data_in, data_in_len),
                         POINTER(c_int8))
        buffer_out = cast(create_string_buffer(data_in_len), POINTER(c_int8))

        res = self._lib.L1_Decrypt(self._l1, data_in_len, buffer_in,
                                   byref(data_out_len), buffer_out, algorithm,
                                   mode, key_id)
        if res < 0:
            raise PySEcubeException("Failed to decrypt")
        return (data_out_len.value, string_at(buffer_out, data_out_len.value))

    def crypto_init(self, algorithm: int, mode: int, key_id: int) -> int:
        session_id = c_uint32(0)
        res = self._lib.L1_CryptoInit(self._l1, algorithm, mode, key_id,
                                      byref(session_id))
        if res < 0:
            raise PySEcubeException("Failed to initialise crypto session")
        return session_id.value

    def crypto_update(self, session_id: int, flags: int, data_in_length: bytes):
        pass

    # internal
    def _load_library(self) -> None:
        dll_path = os.path.join(Wrapper.PYSECUBEPATH, DLL_NAME)
        self._logger.log(DEBUG, "Loading library from %s", dll_path)
        self._lib = CDLL(dll_path, winmode=0x00000008)

    def _setup_boilerplate(self) -> None:
        # L0
        self._lib.L0_create.restype = LibraryHandle
        self._lib.L0_destroy.argtypes = [LibraryHandle]

        self._lib.L0_getNumberDevices.argtypes = [LibraryHandle]
        self._lib.L0_getNumberDevices.restype = c_uint8

        # L1
        self._lib.L1_Create.restype = LibraryHandle
        self._lib.L1_Destroy.argtypes = [LibraryHandle]

        self._lib.L1_Login.argtypes = [LibraryHandle, POINTER(c_uint8),
                                      c_uint16, c_bool]
        self._lib.L1_Login.restype = c_int8

        self._lib.L1_Logout.argtypes = [LibraryHandle]
        self._lib.L1_Logout.restype = c_int8

        self._lib.L1_CryptoSetTimeNow.argtypes = [LibraryHandle]
        self._lib.L1_CryptoSetTimeNow.restype = c_int8

        self._lib.L1_Encrypt.argtypes = [LibraryHandle, c_size_t,
                                         POINTER(c_int8), POINTER(c_size_t),
                                         POINTER(c_int8), c_uint16, c_uint16,
                                         c_uint32]
        self._lib.L1_Encrypt.restype = c_int8

        self._lib.L1_Decrypt.argtypes = [LibraryHandle, c_size_t,
                                         POINTER(c_int8), POINTER(c_size_t),
                                         POINTER(c_int8), c_uint16, c_uint16,
                                         c_uint32]
        self._lib.L1_Decrypt.restype = c_int8

        self._lib.L1_CryptoInit.argtypes = [LibraryHandle, c_uint16, c_uint16,
                         c_uint32, POINTER(c_uint32)]
        self._lib.L1_CryptoInit.restype = c_int8

        self._lib.L1_CryptoUpdate.argtypes = [LibraryHandle, c_uint32, c_uint16,
                                              c_uint16, POINTER(c_uint8),
                                              POINTER(c_uint16), POINTER(c_uint8)]
        self._lib.L1_CryptoUpdate.restype = c_int8

    def _create_libraries(self) -> None:
        self._l0 = self._lib.L0_create()
        self._logger.log(INFO, "L0 created")

        device_count = self._lib.L0_getNumberDevices(self._l0)
        if device_count < 1:
            raise NoSEcubeDeviceConnected("No SEcube device connected")
        self._logger.log(INFO, "SEcube devices connected: %d", device_count)

        self._l1 = self._lib.L1_Create()
        self._logger.log(INFO, "L1 created")
