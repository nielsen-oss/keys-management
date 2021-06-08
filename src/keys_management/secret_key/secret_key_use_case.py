from __future__ import annotations
from enum import Enum
from ..consts import DECRYPTED_STATE, ENCRYPTED_STATE
from ..errors import KeysManagementError

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



