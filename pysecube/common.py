ENV_NAME_SHARED_LIB_PATH = "PYSECUBEPATH"

DLL_NAME = "SEcubeWrapper.dll"

MAX_LENGTH_PIN        = 32
MAX_LENGTH_L1KEY_NAME = 32
MAX_LENGTH_L1KEY_DATA = 2048

ACCESS_MODE_USER = 100

KEY_EDIT_OP_INSERT = 1
KEY_EDIT_OP_DELETE = 2
KEY_EDIT_OP_UPSERT = 3

ALGORITHM_AES            = 0 # AES
ALGORITHM_SHA256         = 1 # SHA256
ALGORITHM_HMACSHA256     = 2 # HMAC-SHA256
ALGORITHM_AES_HMACSHA256 = 3 # AES + HMAC-SHA256

DIGEST_SIZE_TABLE = {
    ALGORITHM_SHA256: 32
}

BLOCK_SIZE_TABLE = {
    ALGORITHM_AES: 16
}

# One Feedback and one Mode may be combined to specify the desired mode
# Example:
#   Encrypt in CBC mode
#   MODE_ENCRYPT | FEEDBACK_CBC 
MODE_SHIFT_BY = 8
MODE_ENCRYPT  = 1 << MODE_SHIFT_BY
MODE_DECRYPT  = 2 << MODE_SHIFT_BY

FEEDBACK_ECB = 1
FEEDBACK_CBC = 2
FEEDBACK_OFB = 3
FEEDBACK_CTR = 4
FEEDBACK_CFB = 5

CRYPTO_UPDATE_FINIT = 1 << 15
CRYPTO_UPDATE_RESET = 1 << 14
CRYPTO_UPDATE_SETIV = CRYPTO_UPDATE_RESET
CRYPTO_UPDATE_SETNONCE = 1 << 13
CRYPTO_UPDATE_AUTH = 1 << 12
