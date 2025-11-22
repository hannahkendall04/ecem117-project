from langchain_core.tools import tool
import zlib

@tool
def compute_checksum(value: str):
    '''
    Function to compute checksum of a given string.
    Arguments:
        value: the value to compute the checksum of
    Returns: 
        hashed: the hashed value
    '''

    bytes = value.encode("utf-8")
    hashed = zlib.crc32(bytes)

    return hashed