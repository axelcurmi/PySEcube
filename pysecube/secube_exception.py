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

class InvalidPinException(PySEcubeException):
    """
    Pin provided for L1 login is invalid.
    """
    pass
