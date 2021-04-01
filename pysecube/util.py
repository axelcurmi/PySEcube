import math

from pysecube.common import BLOCK_SIZE_TABLE

def calc_enc_buffer_size(algorithm: int, data_len: int) -> int:
    block_size = BLOCK_SIZE_TABLE[algorithm]
    return math.ceil(data_len / block_size) * block_size
