from __future__ import annotations
from typing import TYPE_CHECKING, Any, Optional, Union
from .secret_key import (
    BaseSecretKeyDefinition,
    InitError,
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

    def is_target_data_accessible(self) -> bool:
        return self.__original_key_definition.is_target_data_accessible()

    def is_keep_in_cache(self) -> bool:
        return self.__original_key_definition.is_keep_in_cache()

    def get_last_use_case(self) -> Optional[SecretKeyUseCase]:
        return self.__state.get_last_use_case()

    def set_last_use_case(self, last_use: SecretKeyUseCase) -> None:
        self.__state.set_last_use_case(last_use)

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
            "original_key_definition type is %s" % str(type(original_key_definition)),
        )
