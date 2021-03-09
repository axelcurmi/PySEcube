import os

from ctypes import (CDLL,
                    c_byte,
                    c_uint8,
                    POINTER)
from logging import (getLogger,
                     DEBUG,
                     INFO)

from pysecube.common import (ENV_NAME_SHARED_LIB_PATH, DLL_NAME)
from pysecube.secube_exception import NoSEcubeDeviceConnected

class Wrapper(object):
    PYSECUBEPATH = os.environ[ENV_NAME_SHARED_LIB_PATH]
    LOGGER_NAME = "pysecube.wrapper"

    def __init__(self):
        self.logger = getLogger(Wrapper.LOGGER_NAME)

        self.lib = self.load_library()
        self.setup_boilerplate()

        # Setting up L0 and L1
        self.l0 = self.lib.L0_create()
        self.logger.log(INFO, "L0 library created")

        device_count = self.lib.L0_getNumberDevices(self.l0)
        if device_count < 1:
            raise NoSEcubeDeviceConnected("No SEcube device connected")
        self.logger.log(INFO, "SEcube devices connected: %d", device_count)

        self.l1 = self.lib.L1_create()
        self.logger.log(INFO, "L1 library created")

    def __del__(self) -> None:
        self.lib.L0_destroy(self.l0)
        self.lib.L1_destroy(self.l1)
        
        self.l0 = None
        self.l1 = None

        self.logger.log(INFO, "L0 and L1 libraries destroyed")

    def load_library(self) -> CDLL:
        dll_path = os.path.join(Wrapper.PYSECUBEPATH, DLL_NAME)
        self.logger.log(DEBUG, "Loading library from %s", dll_path)
        return CDLL(dll_path, winmode=0x00000008)

    def setup_boilerplate(self) -> None:
        libHandle = POINTER(c_byte)

        # L0
        self.lib.L0_create.restype = libHandle
        self.lib.L0_destroy.argtypes = [libHandle]

        self.lib.L0_getNumberDevices.argtypes = [libHandle]
        self.lib.L0_getNumberDevices.restype = c_uint8

        # L1
        self.lib.L1_create.restype = libHandle
        self.lib.L0_destroy.argtypes = [libHandle]
