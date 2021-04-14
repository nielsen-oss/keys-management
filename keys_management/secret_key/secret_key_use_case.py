from __future__ import annotations
from enum import Enum
from ..errors import KeysManagementError
from ..consts import ENCRYPTED_STATE, DECRYPTED_STATE


class SecretKeyUseCase(Enum):
    ENCRYPTION_DECRYPTION = 1
    ENCRYPTION = 2
    DECRYPTION = 3
    AUTHENTICATION = 4

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


class InvalidUseCaseNameError(KeysManagementError):
    def __init__(self, bad_value: str) -> None:
        super().__init__(
            'Failed to parse "" to SecretKeyUseCase' % bad_value
        )
