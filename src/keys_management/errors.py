from __future__ import annotations
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from keys_management.key_changed_utils import KeyChangedContext

FETCH_AND_SET_ERROR_MSG_FORMAT = (
    "Failed to fetch and set key state for {key_name} from_repo: {why}"
)
KEY_IS_NOT_DEFINED_ERROR_MSG_FORMAT = "KeyIsNotDefinedError: key_name is '%s'"
KEY_CHANGED_ERROR_MSG_FORMAT = "KeyChangedError: key_name is '%s'"
GET_KEY_ERROR_MSG_FORMAT = "failed to get key for {key_name}: {reason}"


class KeysManagementError(RuntimeError):
    pass


class OnKeyChangedCallbackErrorStrategy(Enum):
    RAISE_IMMEDIATELY = (1,)
    SKIP_AND_RAISE = (2,)
    SKIP = (3,)
    HALT = (4,)


class GetKeyError(KeysManagementError):
    def __init__(self, key_name: str, reason: str = None) -> None:
        super().__init__(
            GET_KEY_ERROR_MSG_FORMAT.format(
                key_name=key_name, reason=reason if reason else ""
            )
        )


class KeyChangedError(KeysManagementError):
    def __init__(
        self, key_name: str, key_changed_context: KeyChangedContext = None
    ) -> None:
        super().__init__(key_name, key_changed_context)

    def __str__(self) -> str:
        return KEY_CHANGED_ERROR_MSG_FORMAT % self.args[0]


class KeyIsNotDefinedError(KeysManagementError):
    def __init__(self, key_name: str) -> None:
        super().__init__(key_name)

    def __str__(self) -> str:
        return KEY_IS_NOT_DEFINED_ERROR_MSG_FORMAT % self.args[0]


class FetchAndSetStateFromRepoError(KeysManagementError):
    def __init__(self, key_name: str, why: str = None) -> None:
        super().__init__(
            FETCH_AND_SET_ERROR_MSG_FORMAT.format(
                key_name=key_name, why=why if why else ""
            )
        )


class InvalidKeyStateError(FetchAndSetStateFromRepoError):
    def __init__(self, key_name: str, why: str = None) -> None:
        super().__init__(key_name, why)
