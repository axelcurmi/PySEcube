import math
import os
import time

from cffi import FFI

from logging import (getLogger,
                     DEBUG,
                     INFO)
from typing import (List,
                    Union)

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
                             BLOCK_SIZE_TABLE,
                             DIGEST_SIZE_TABLE,
                             ALGORITHM_SHA256,
                             ALGORITHM_HMACSHA256,
                             KEY_EDIT_OP_INSERT,
                             KEY_EDIT_OP_DELETE)

# TODO: Maybe move to a seperate python file (like the cryptography module)
CDEF = """\
// Type definitions
typedef ... L0_handler_t;
typedef ... L1_handle_t;

typedef struct se3Key_ {
	uint32_t id;
	uint32_t validity;
	uint16_t dataSize;
	uint16_t nameSize;
	uint8_t* data;
	uint8_t name[32];
} se3Key;

// L0
L0_handler_t *L0_Create();
void L0_Destroy(L0_handler_t *l0);

uint8_t L0_GetNumberDevices(L0_handler_t *l0);

// L1
L1_handle_t *L1_Create();
void L1_Destroy(L1_handle_t *l1);

int8_t L1_Login(L1_handle_t *l1, const uint8_t *pin, uint16_t access,
    bool force);
int8_t L1_Logout(L1_handle_t *l1);

int8_t L1_FindKey(L1_handle_t *l1, uint32_t keyID);
int8_t L1_KeyEdit(L1_handle_t *l1, se3Key* key, uint16_t op);

int8_t L1_CryptoSetTimeNow(L1_handle_t *l1);

int8_t CryptoInit(L1_handle_t *l1, uint16_t algorithm, uint16_t flags,
    uint32_t keyId, uint32_t* sessionId);
int8_t CryptoUpdate(L1_handle_t *l1, uint32_t sessionId, uint16_t flags,
    uint16_t data1Len, uint8_t* data1, uint16_t data2Len, uint8_t* data2,
    uint16_t* dataOutLen, uint8_t* dataOut);

int8_t DigestSHA256(L1_handle_t *l1, uint16_t dataInLen, uint8_t *dataIn,
    uint16_t *dataOutLen, uint8_t *dataOut);
int8_t DigestHMACSHA256(L1_handle_t *l1, uint32_t keyId,
    uint16_t dataInLen, uint8_t *dataIn, uint16_t *dataOutLen,
    uint8_t *dataOut);
"""


class Wrapper(object):
    PYSECUBEPATH = os.environ[ENV_NAME_SHARED_LIB_PATH]
    LOGGER_NAME = "pysecube.wrapper"

    def __init__(self, pin: Union[List[int], bytes] = None):
        self._logger = getLogger(Wrapper.LOGGER_NAME)
        self._ffi = None
        self._lib = None

        self._l0 = None
        self._l1 = None

        self.logged_in = False

        self._load_library()
        self._create_libraries()
        
        if pin is not None:
            self.login(pin, ACCESS_MODE_USER)

    def __del__(self) -> None:
        if self.logged_in:
            self.logout()

        if self._l1 is not None:
            self._lib.L1_Destroy(self._l1)
            self._l1 = None
            self._logger.log(DEBUG, "L1 destroyed")

        if self._l0 is not None:
            self._lib.L0_Destroy(self._l0)
            self._l0 = None
            self._logger.log(DEBUG, "L0 destroyed")

    def login(self, pin: Union[List[int], bytes], access: int,
              force: bool = True) -> None:
        if len(pin) > MAX_LENGTH_PIN:
            raise InvalidPinException(f"Pin exceeds length of {MAX_LENGTH_PIN}")

        c_pin = None
        if isinstance(pin, bytes):
            c_pin = self._ffi.new("char[32]", pin)
        else:
            raise Exception("NOT IMPLEMENTED YET") # TODO

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

    def key_exists(self, id: int) -> bool:
        return self._lib.L1_FindKey(self._l1, id) == 1

    def delete_key(self, id: int) -> None:
        key = self._ffi.new("se3Key *", { "id": id })
        res = self._lib.L1_KeyEdit(self._l1, key, KEY_EDIT_OP_DELETE)
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

        key = self._ffi.new("se3Key *", {
            "id": id,
            "validity": int(time.time()) + 3600,
            "dataSize": data_size,
            "nameSize": name_size,
            "data": self._ffi.from_buffer(data),
            "name": name,
        })

        res = self._lib.L1_KeyEdit(self._l1, key, KEY_EDIT_OP_INSERT)
        if res < 0:
            raise PySEcubeException("Failed to add key")
        self._logger.log(DEBUG, "Key with ID:%d added successfully", id)

    def crypto_set_time_now(self) -> None:
        res = self._lib.L1_CryptoSetTimeNow(self._l1)
        if res < 0:
            raise PySEcubeException("Failed to set crypto time")
        self._logger.log(DEBUG, "Crypto time set to now")

    def get_crypter(self, algorithm: int, flags: int, key_id: int,
                    iv: bytes = None) -> Crypter:
        return Crypter(self, algorithm, flags, key_id, iv)

    def crypto_init(self, algorithm: int, flags: int, key_id: int) -> int:
        session_id = self._ffi.new("uint32_t *")
        res = self._lib.CryptoInit(self._l1, algorithm, flags, key_id,
                                   session_id)
        if res < 0:
            raise PySEcubeException("Failed to initialise crypto session")
        return session_id[0]

    def crypto_update(self, session_id: int, flags: int, data1: bytes = None,
                      data2: bytes = None, max_out_len: int = 0) -> bytes:
        # Data 1
        data1_len = 0
        data1_buffer = self._ffi.NULL
        if data1 is not None:
            data1_len = len(data1)
            data1_buffer = self._ffi.from_buffer(data1)

        # Data 2
        data2_len = 0
        data2_buffer = self._ffi.NULL
        if data2 is not None:
            data2_len = len(data2)
            data2_buffer = self._ffi.from_buffer(data2)

        out_len = self._ffi.NULL
        out_buffer = self._ffi.NULL
        if max_out_len > 0:
            out_len = self._ffi.new("uint16_t *")
            out_buffer = self._ffi.new("uint8_t[]", max_out_len)

        res = self._lib.CryptoUpdate(self._l1, session_id, flags, data1_len,
                                     data1_buffer, data2_len, data2_buffer,
                                     out_len, out_buffer)
        if res < 0:
            raise PySEcubeException("Failed to perform crypto update")
        return None if out_len == self._ffi.NULL else \
            self._ffi.buffer(out_buffer, out_len[0])[:]

    def sha256(self, data_in: bytes) -> bytes:
        data_in_buffer = self._ffi.from_buffer(data_in)

        data_out_len = self._ffi.new("uint16_t *")
        data_out_buffer = self._ffi.new(
            "uint8_t[]", DIGEST_SIZE_TABLE[ALGORITHM_SHA256]
        )

        if self._lib.DigestSHA256(self._l1, len(data_in), data_in_buffer,
                                  data_out_len, data_out_buffer) < 0:
            raise PySEcubeException("Failed to create SHA256 digest")
        return self._ffi.buffer(data_out_buffer, data_out_len[0])[:]

    def compute_hmac(self, key_id: int, data_in: bytes) -> bytes:
        data_in_buffer = self._ffi.from_buffer(data_in)

        data_out_len = self._ffi.new("uint16_t *")
        data_out_buffer = self._ffi.new(
            "uint8_t[]", DIGEST_SIZE_TABLE[ALGORITHM_HMACSHA256]
        )

        if self._lib.DigestHMACSHA256(self._l1, key_id, len(data_in),
                                  data_in_buffer, data_out_len,
                                  data_out_buffer) < 0:
            raise PySEcubeException("Failed to create SHA256 HMAC")
        return self._ffi.buffer(data_out_buffer, data_out_len[0])[:]

    # internal
    def _load_library(self) -> None:
        self._ffi = FFI()
        self._ffi.cdef(CDEF)

        self._lib = self._ffi.dlopen(
            os.path.join(Wrapper.PYSECUBEPATH, DLL_NAME)
        )

    def _create_libraries(self) -> None:
        self._l0 = self._lib.L0_Create()
        self._logger.log(DEBUG, "L0 created")

        device_count = self._lib.L0_GetNumberDevices(self._l0)
        if device_count < 1:
            raise NoSEcubeDeviceConnected("No SEcube device connected")
        self._logger.log(DEBUG, "SEcube devices connected: %d", device_count)

        self._l1 = self._lib.L1_Create()
        self._logger.log(DEBUG, "L1 created")
