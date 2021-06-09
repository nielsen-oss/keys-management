from __future__ import annotations
from enum import Enum
from ..consts import DECRYPTED_STATE, ENCRYPTED_STATE
from ..errors import KeysManagementError

class SecretKeyFlow(Enum):
    DEFAULT = 1
    AUTHENTICATION = 1
    FORWARD_PATH = 2
    BACK_PATH = 3
    ENCRYPTION = 2
    DECRYPTION = 3

    @staticmethod
    def get(str_val: str) -> SecretKeyFlow:
        if str_val == ENCRYPTED_STATE:
            return SecretKeyUseCase.DECRYPTION
        if str_val == DECRYPTED_STATE:
            return SecretKeyUseCase.ENCRYPTION
        try:
            return SecretKeyFlow[str_val.upper()]
        except KeyError:
            raise InvalidUseCaseNameError(str_val)

class SecretKeyUseCase(Enum):
    ROUND_TRIP = 1
    ONE_WAY_TRIP = 2
    ENCRYPTION_DECRYPTION = 1
    AAA = 1

    @staticmethod
    def get(str_val: str) -> SecretKeyUseCase:
        if str_val == ENCRYPTED_STATE:
            return SecretKeyUseCase.DECRYPTION
        if str_val == DECRYPTED_STATE:
            return SecretKeyUseCase.ENCRYPTION
        try:
            return SecretKeyUseCase[str_val.upper()]
        except KeyError:
            raise InvalidUseCaseNameError(str_val)
