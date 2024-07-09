class NoRootPrivilegesException(BaseException):
    """
    Exception raised when the user does not have root privileges.
    """

    def __init__(self, message: str = None):
        super().__init__(message)


class RequirementInstallationFailedException(BaseException):
    """
    Exception raised when the installation of a software requirement fails.
    """

    def __init__(self, message: str = None):
        super().__init__(message)


class WirelessAdapterNotFoundException(BaseException):
    """
    Exception raised when the wireless adapter is not found.
    """

    def __init__(self, message: str = None):
        super().__init__(message)
