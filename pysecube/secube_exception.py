class PySEcubeException(Exception):
    """
    Exception raised by failures in SEcube wrapper internals or logic errors. 
    """
    pass

class NoSEcubeDeviceConnected(PySEcubeException):
    """
    Attempted to initialise PySEcube wrapper without no SEcube device connected.
    """
    pass
