from __future__ import annotations
import inspect
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Dict, Optional, Union
from unittest.mock import Mock
from ..errors import OnKeyChangedCallbackErrorStrategy
from .consts import (
    CALLBACK_ERROR_STRATEGY_ARG,
    KEEP_IN_CACHE_ARG,
    KEEP_IN_CACHE_PROP,
    LAST_FLOW_PROP,
    NAME_PROP,
    STATELESS_ARG,
    STATELESS_PROP,
    USE_CASE_ARG,
    USE_CASE_PROP,
)
from .errors import InitError, SecretKeyDefinitionInitError
from .key_state import SecretKeyState
from .log_messages_consts import (
    ERROR_STRATEGY_TYPE_ERR_MSG,
    KEEP_IN_CACHE_NOT_BOOL_ERR_MSG,
    NAME_PROPERTY_IS_EMPTY_MSG,
    SHOULD_NOT_CONTAINS_ARGS_MSG,
    STATELESS_NOT_BOOL_ERR_MSG,
    STORE_IS_NOT_CALLABLE_MSG,
    USE_CASE_PROP_TYPE_ERR,
)
from .secret_key import SecretKeyFactory, SecretKeyPair, SecretKeyValue
from .secret_key_use_case import SecretKeyFlow, SecretKeyUseCase

if TYPE_CHECKING:
    from ..key_changed_utils import KeyChangedCallback
    from .types import KeysStore, StrOrBytes, StrOrBytesPair


class BaseSecretKeyDefinition(ABC):
    _name: str
    _store: KeysStore
    _use_case: SecretKeyUseCase
    _stateless: bool
    _keep_in_cache: bool
    _on_key_changed_callback_error_strategy: OnKeyChangedCallbackErrorStrategy
    _on_change_callbacks: Dict[str, KeyChangedCallback]

    def __init__(self, name: str, keys_store: KeysStore, **kwargs: Any):
        self._name = name
        self._keys_store = keys_store
        self._use_case = kwargs.get(
            USE_CASE_ARG, SecretKeyUseCase.ENCRYPTION_DECRYPTION
        )
        self._stateless = kwargs.get(STATELESS_ARG, True)
        self._keep_in_cache = kwargs.get(KEEP_IN_CACHE_ARG, True)
        self._on_key_changed_callback_error_strategy = kwargs.get(
            CALLBACK_ERROR_STRATEGY_ARG,
            OnKeyChangedCallbackErrorStrategy.HALT,
        )
        self._on_change_callbacks = OrderedDict()
        self._validate_properties()

    def _validate_properties(self) -> None:
        if not isinstance(self._name, str) or len(self._name) == 0:
            raise SecretKeyDefinitionInitError(NAME_PROPERTY_IS_EMPTY_MSG)
        if not callable(self._keys_store):
            raise SecretKeyDefinitionInitError(STORE_IS_NOT_CALLABLE_MSG)
        if (
            not isinstance(self._keys_store, Mock)
            and len(inspect.signature(self._keys_store).parameters) > 0
        ):
            raise SecretKeyDefinitionInitError(SHOULD_NOT_CONTAINS_ARGS_MSG)
        if not isinstance(self._use_case, SecretKeyUseCase):
            raise SecretKeyDefinitionInitError(USE_CASE_PROP_TYPE_ERR)
        if not isinstance(self._stateless, bool):
            raise SecretKeyDefinitionInitError(STATELESS_NOT_BOOL_ERR_MSG)
        if not isinstance(self._keep_in_cache, bool):
            raise SecretKeyDefinitionInitError(KEEP_IN_CACHE_NOT_BOOL_ERR_MSG)
        if not isinstance(
            self._on_key_changed_callback_error_strategy,
            OnKeyChangedCallbackErrorStrategy,
        ):
            raise SecretKeyDefinitionInitError(ERROR_STRATEGY_TYPE_ERR_MSG)

    @property
    def name(self) -> str:
        return self._name

    @property
    def keys_store(self) -> KeysStore:
        return self._keys_store

    def is_stateless(self) -> bool:
        return self._stateless

    def is_stated(self) -> bool:
        return not self._stateless

    @property
    def use_case(self) -> SecretKeyUseCase:
        return self._use_case

    @property
    def on_change_callbacks(self) -> Dict[str, KeyChangedCallback]:
        return self._on_change_callbacks

    def is_keep_in_cache(self) -> bool:
        return self._keep_in_cache

    @abstractmethod
    def get_key_state(self) -> SecretKeyState:
        pass

    @abstractmethod
    def set_key_state(self, key_state: SecretKeyState) -> None:
        pass

    @property
    def on_key_changed_callback_error_strategy(
        self,
    ) -> OnKeyChangedCallbackErrorStrategy:
        return self._on_key_changed_callback_error_strategy

    def __str__(self) -> str:
        return str(self.asdict())

    def asdict(self) -> Dict[str, Any]:
        return {
            NAME_PROP: self._name,
            USE_CASE_PROP: self._use_case.name,
            STATELESS_PROP: self._stateless,
            KEEP_IN_CACHE_PROP: self._keep_in_cache,
        }

    def __call__(self) -> Union[StrOrBytes, StrOrBytesPair]:
        return self._keys_store()


KeyContent = Optional[Union[SecretKeyValue, SecretKeyPair]]


class SecretKeyDefinition(BaseSecretKeyDefinition, SecretKeyState):
    _last_use: Optional[SecretKeyFlow]
    _current_keys: KeyContent
    _previous_keys: KeyContent

    def __init__(self, name: str, keys_store: KeysStore, **kwargs: Any) -> None:
        super(SecretKeyDefinition, self).__init__(name, keys_store, **kwargs)
        self._last_use = None
        self._current_keys = None
        self._previous_keys = None

    def set_keys_from_store(self) -> None:
        self._previous_keys = self._current_keys
        self._current_keys = SecretKeyPair(self._keys_store())

    @property
    def keys(self) -> KeyContent:
        return self._current_keys

    @property
    def previous_keys(self) -> KeyContent:
        return self._previous_keys

    def set_previous_keys(
        self,
        keys: Optional[
            Union[StrOrBytes, StrOrBytesPair, SecretKeyValue, SecretKeyPair]
        ],
    ) -> None:
        if isinstance(keys, (SecretKeyValue, SecretKeyPair)):
            self._current_keys = keys
        else:
            self._current_keys = SecretKeyPair(keys)  # type: ignore[arg-type]

    def get_keys_or_previous(self) -> KeyContent:
        if self._current_keys is not None:
            return self._current_keys
        else:
            return self._previous_keys

    def get_previous_or_current_keys(self) -> KeyContent:
        if self._previous_keys is not None:
            return self._previous_keys
        return self._current_keys

    def get_last_flow(self) -> Optional[SecretKeyFlow]:
        return self._last_use

    def set_last_flow(self, use_case: Optional[SecretKeyFlow]) -> None:
        self._last_use = use_case

    def has_keys(self) -> bool:
        return self._current_keys is not None or self._previous_keys is not None

    def clean_keys(self) -> None:
        self._previous_keys = self.get_keys_or_previous()
        self._current_keys = None

    def clean_previous_keys(self) -> None:
        self._previous_keys = None

    def get_key_state(self) -> SecretKeyState:
        return self

    def set_key_state(self, key_state: SecretKeyState) -> None:
        self.set_last_flow(key_state.get_last_flow())
        previous_keys: Optional[
            Union[SecretKeyValue, SecretKeyPair]
        ] = key_state.get_previous_keys()
        if previous_keys != self._previous_keys and previous_keys is not None:
            self.set_previous_keys(previous_keys)

    def clean_state(self) -> None:
        self.clean_keys()
        self.clean_previous_keys()

    def asdict(self) -> Dict[str, Any]:
        rv = super(SecretKeyDefinition, self).asdict()
        rv.update({LAST_FLOW_PROP: str(self._last_use)})
        return rv

    def get_previous_keys(self) -> Optional[Union[SecretKeyValue, SecretKeyPair]]:
        pass
