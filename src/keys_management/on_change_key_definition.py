from __future__ import annotations
from typing import TYPE_CHECKING, Any
from .secret_key import (
    SecretKeyUseCase,
    SecretKeyState,
    BaseSecretKeyDefinition,
    InitError,
)

if TYPE_CHECKING:
    from .secret_key import KeysStore, SecretKeyPairValues


class OnChangeKeyDefinition(SecretKeyState):
    __originalKeyDefinition: BaseSecretKeyDefinition
    __key_state: SecretKeyState

    def __init__(self, original_key_definition: BaseSecretKeyDefinition):
        if not isinstance(
            original_key_definition, BaseSecretKeyDefinition
        ):
            raise OnChangeKeyDefinitionInitError(original_key_definition)
        self.__originalKeyDefinition = original_key_definition
        self.__state = original_key_definition.get_key_state()

    @property
    def name(self) -> str:
        return self.__originalKeyDefinition.name

    @property
    def keys_store(self) -> KeysStore:
        return self.__originalKeyDefinition.keys_store

    def is_stateless(self) -> bool:
        return self.__originalKeyDefinition.is_stateless()

    def is_stated(self) -> bool:
        return not self.__originalKeyDefinition.is_stated()

    @property
    def use_case(self) -> SecretKeyUseCase:
        return self.__originalKeyDefinition.use_case

    def is_target_data_accessible(self) -> bool:
        return self.__originalKeyDefinition.is_target_data_accessible()

    def is_keep_in_cache(self) -> bool:
        return self.__originalKeyDefinition.is_keep_in_cache()

    def get_last_use_case(self) -> SecretKeyUseCase:
        return self.__state.get_last_use_case()

    def set_last_use_case(self, last_use: SecretKeyUseCase) -> None:
        self.__state.set_last_use_case(last_use)

    def get_previous_keys(self):
        return self.__state.get_previous_keys()

    def set_previous_keys(self, keys: SecretKeyPairValues) -> None:
        self.__state.set_previous_keys(keys)

    def clean_state(self) -> None:
        self.__state.clean_state()


class OnChangeKeyDefinitionInitError(InitError):
    def __init__(self, original_key_definition: Any) -> None:
        super().__init__(
            'OnChangeKeyDefinition',
            "original_key_definition type is %s"
            % str(type(original_key_definition)),
        )
