from enum import Enum


class KeysManagementError(RuntimeError):
    pass


class OnKeyChangedCallbackErrorStrategy(Enum):
    RAISE_IMMEDIATELY = 1,
    SKIP_AND_RAISE = 2,
    SKIP = 3,
    HALT = 4