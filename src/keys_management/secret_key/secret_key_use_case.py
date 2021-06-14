from __future__ import annotations
from enum import Enum
from ..consts import BACK_PATH_FLOW_STATE, FORWARD_PATH_FLOW_STATE
from ..errors import KeysManagementError
from .errors import InvalidFlowNameError


class SecretKeyFlow(Enum):
    DEFAULT = 1
    AUTHENTICATION = 1
    FORWARD_PATH = 2
    BACK_PATH = 3
    ENCRYPTION = 2
    DECRYPTION = 3

    @staticmethod
    def get(str_val: str) -> SecretKeyFlow:
        if str_val == FORWARD_PATH_FLOW_STATE:
            return SecretKeyFlow.FORWARD_PATH
        if str_val == BACK_PATH_FLOW_STATE:
            return SecretKeyFlow.BACK_PATH
        try:
            return SecretKeyFlow[str_val.upper()]
        except KeyError:
            raise InvalidFlowNameError(str_val)


class SecretKeyUseCase(Enum):
    ROUND_TRIP = 1
    ONE_WAY_TRIP = 2
    ENCRYPTION_DECRYPTION = 1
