from typing import Any
from ..errors import KeysManagementError
from .consts import (
    SECRET_KEY_DEFINITION_TYPE_NAME,
    SECRET_KEY_PAIR_TYPE_NAME,
    SECRET_KEY_TYPE_NAME,
)

INIT_ERR_MSG_FRMT = "Failed to init {what_to_init}: {why}"
SECRET_KEY_ERR_MSG_FRMT = "secret_key_value type is %s"
PAIR_INIT_ERR_MSG_FRMT = "secret_key_pair_values type is %s"
FLOW_NAME_ERR_MSG_FRMT = "Failed to parse %s to SecretKeyFlow"


class InitError(KeysManagementError):
    def __init__(self, what_to_init: str, why: str) -> None:
        super().__init__(INIT_ERR_MSG_FRMT.format(what_to_init=what_to_init, why=why))


class SecretKeyInitError(InitError):
    def __init__(self, secret_key_value: Any) -> None:
        super().__init__(
            SECRET_KEY_TYPE_NAME, SECRET_KEY_ERR_MSG_FRMT % str(type(secret_key_value))
        )


class SecretKeyPairInitError(InitError):
    def __init__(self, secret_key_pair_values: Any) -> None:
        super().__init__(
            SECRET_KEY_PAIR_TYPE_NAME,
            PAIR_INIT_ERR_MSG_FRMT % str(type(secret_key_pair_values)),
        )


class InvalidFlowNameError(KeysManagementError):
    def __init__(self, bad_value: str) -> None:
        super().__init__(FLOW_NAME_ERR_MSG_FRMT % bad_value)


class SecretKeyDefinitionInitError(InitError):
    def __init__(self, reason: str) -> None:
        super().__init__(SECRET_KEY_DEFINITION_TYPE_NAME, reason)
