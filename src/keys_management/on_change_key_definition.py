from __future__ import annotations
from typing import TYPE_CHECKING, Any, Optional, Union
from .secret_key import (
    BaseSecretKeyDefinition,
    InitError,
    SecretKeyFlow,
    SecretKeyState,
    SecretKeyUseCase,
)

if TYPE_CHECKING:
    from .secret_key import (
        KeysStore,
        SecretKeyPair,
        SecretKeyValue,
        StrOrBytes,
        StrOrBytesPair,
    )

ERROR_MSG_FRMT = "original_key_definition type is %s"


class OnChangeKeyDefinition(SecretKeyState):
    __original_key_definition: BaseSecretKeyDefinition
    __key_state: SecretKeyState

    def __init__(self, original_key_definition: BaseSecretKeyDefinition):
        if not isinstance(original_key_definition, BaseSecretKeyDefinition):
            raise OnChangeKeyDefinitionInitError(original_key_definition)
        self.__original_key_definition = original_key_definition
        self.__state = original_key_definition.get_key_state()

    @property
    def name(self) -> str:
        return self.__original_key_definition.name

    @property
    def keys_store(self) -> KeysStore:
        return self.__original_key_definition.keys_store

    def is_stateless(self) -> bool:
        return self.__original_key_definition.is_stateless()

    def is_stated(self) -> bool:
        return not self.__original_key_definition.is_stated()

    @property
    def use_case(self) -> SecretKeyUseCase:
        return self.__original_key_definition.use_case

    def is_keep_in_cache(self) -> bool:
        return self.__original_key_definition.is_keep_in_cache()

    def get_last_flow(self) -> Optional[SecretKeyFlow]:
        return self.__state.get_last_flow()

    def set_last_flow(self, last_use: SecretKeyFlow) -> None:
        self.__state.set_last_flow(last_use)

    def get_previous_keys(self) -> Optional[Union[SecretKeyValue, SecretKeyPair]]:
        return self.__state.get_previous_keys()

    def set_previous_keys(self, keys: Union[StrOrBytes, StrOrBytesPair]) -> None:
        self.__state.set_previous_keys(keys)

    def clean_state(self) -> None:
        self.__state.clean_state()


class OnChangeKeyDefinitionInitError(InitError):
    def __init__(self, original_key_definition: Any) -> None:
        super().__init__(
            "OnChangeKeyDefinition",
            ERROR_MSG_FRMT % str(type(original_key_definition)),
        )
