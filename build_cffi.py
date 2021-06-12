import os

from cffi import FFI

CDEF = """\
typedef ... L0_handler_t;

L0_handler_t *L0_Create();
void L0_Destroy(L0_handler_t *l0);

uint8_t L0_GetNumberDevices(L0_handler_t *l0);

struct L1_handle;
typedef struct L1_handle L1_handle_t;

L1_handle_t *L1_Create();
void L1_Destroy(L1_handle_t *l1);

int8_t L1_Login(L1_handle_t *l1, const uint8_t *pin, uint16_t access,
    uint8_t force);
int8_t L1_Logout(L1_handle_t *l1);

int8_t L1_FindKey(L1_handle_t *l1, uint32_t keyID);
int8_t L1_KeyEdit(L1_handle_t *l1, uint32_t id, uint32_t validity,
    uint16_t dataSize, uint16_t nameSize, uint8_t* data, uint8_t* name,
    uint16_t op);

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

SRC = """\
#include "L0_wrapper.h"
#include "L1_wrapper.h"
"""

# Paths
SECUBE_CLONE = os.environ["SECUBE_CLONE"]
SECUBE_SOURCE = os.path.join(SECUBE_CLONE, "SEcubeSources")
L0_SECUBE_SOURCE = os.path.join(SECUBE_SOURCE, "L0")
L0_BASE_SECUBE_SOURCE = os.path.join(L0_SECUBE_SOURCE, "L0Base")

L1_SECUBE_SOURCE = os.path.join(SECUBE_SOURCE, "L1")
L1_BASE_SECUBE_SOURCE = os.path.join(L1_SECUBE_SOURCE, "L1Base")
L1_CRYPTO_LIBS_SECUBE_SOURCE = os.path.join(L1_SECUBE_SOURCE, "CryptoLibraries")

ffi = FFI()
ffi.cdef(CDEF)

ffi.set_source(
    module_name="_secube",
    source=SRC,
    sources=[
        os.path.join(L0_BASE_SECUBE_SOURCE, "L0_base.cpp"),
        os.path.join(L0_SECUBE_SOURCE, "L0_commodities.cpp"),
        os.path.join(L0_SECUBE_SOURCE, "L0_communication.cpp"),
        os.path.join(L0_SECUBE_SOURCE, "L0_provision.cpp"),
        os.path.join(L0_SECUBE_SOURCE, "L0.cpp"),

        os.path.join(L1_CRYPTO_LIBS_SECUBE_SOURCE, "aes256.cpp"),
        os.path.join(L1_CRYPTO_LIBS_SECUBE_SOURCE, "sha256.c"),
        os.path.join(L1_CRYPTO_LIBS_SECUBE_SOURCE, "pbkdf2.c"),
        os.path.join(L1_BASE_SECUBE_SOURCE, "L1_base.cpp"),
        os.path.join(L1_SECUBE_SOURCE, "L1_login_logout.cpp"),
        os.path.join(L1_SECUBE_SOURCE, "L1_security.cpp"),
        os.path.join(L1_SECUBE_SOURCE, "L1.cpp"),

        os.path.join(SECUBE_CLONE, "L0_wrapper.cpp"),
        os.path.join(SECUBE_CLONE, "L1_wrapper.cpp")
    ],
    include_dirs=[SECUBE_CLONE]
)

if __name__ == "__main__":
    ffi.compile(verbose=True)
