import os

from ctypes import (CDLL,
                    c_byte,
                    c_bool,
                    c_int8,
                    c_uint8,
                    c_uint16,
                    POINTER,
                    cast,
                    create_string_buffer)
from logging import (getLogger,
                     DEBUG,
                     INFO)
from typing import (List,
                    Union)

from pysecube.common import (ENV_NAME_SHARED_LIB_PATH,
                             DLL_NAME,
                             MAX_LENGTH_PIN,
                             ACCESS_MODE_USER)
from pysecube.secube_exception import (NoSEcubeDeviceConnected,
                                       InvalidPinException, PySEcubeException)

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
            self._lib.L1_destroy(self._l1)
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

    # internal
    def _load_library(self) -> None:
        dll_path = os.path.join(Wrapper.PYSECUBEPATH, DLL_NAME)
        self._logger.log(DEBUG, "Loading library from %s", dll_path)
        self._lib = CDLL(dll_path, winmode=0x00000008)

    def _setup_boilerplate(self) -> None:
        lib_handle = POINTER(c_byte)

        # L0
        self._lib.L0_create.restype = lib_handle
        self._lib.L0_destroy.argtypes = [lib_handle]

        self._lib.L0_getNumberDevices.argtypes = [lib_handle]
        self._lib.L0_getNumberDevices.restype = c_uint8

        # L1
        self._lib.L1_create.restype = lib_handle
        self._lib.L0_destroy.argtypes = [lib_handle]

        self._lib.L1_Login.argtypes = [lib_handle, POINTER(c_uint8),
                                      c_uint16, c_bool]
        self._lib.L1_Login.restype = c_int8

        self._lib.L1_Logout.argtypes = [lib_handle]
        self._lib.L1_Logout.restype = c_int8

    def _create_libraries(self) -> None:
        self._l0 = self._lib.L0_create()
        self._logger.log(INFO, "L0 created")

        device_count = self._lib.L0_getNumberDevices(self._l0)
        if device_count < 1:
            raise NoSEcubeDeviceConnected("No SEcube device connected")
        self._logger.log(INFO, "SEcube devices connected: %d", device_count)

        self._l1 = self._lib.L1_create()
        self._logger.log(INFO, "L1 created")
