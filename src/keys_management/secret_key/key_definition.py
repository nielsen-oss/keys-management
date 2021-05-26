from __future__ import annotations
from typing import TYPE_CHECKING, Dict, Optional
from abc import ABC, abstractmethod
import inspect
from unittest.mock import Mock
from collections import OrderedDict
from .secret_key import SecretKeyPair
from .secret_key_use_case import SecretKeyUseCase
from .key_state import SecretKeyState
from .errors import InitError
from ..errors import OnKeyChangedCallbackErrorStrategy
if TYPE_CHECKING:
    from ..key_changed_utils import KeyChangedCallback
    from .types import KeysStore, SecretKeyPairValues

NAME_PROP = 'name'
USE_CASE_PROP = 'useCase'
STATELESS_PROP = 'stateless'
TARGET_DATA_ACCESSIBLE_PROP = 'targetDataAccessible'
KEEP_IN_CACHE_PROP = 'keepInCache'
LAST_USE_PROP = 'lastUse'

ERROR_STRATEGY_TYPE_ERR_MSG = '"on_key_changed_callback_error_strategy" property is not type of "OnKeyChangedCallbackErrorStrategy"'
KEEP_IN_CACHE_NOT_BOOL_ERR_MSG = '"keep_in_cache" property is not boolean'
TARGET_DATA_ACCESSIBLE_NOT_BOOL_ERR_MSG = (
    '"target_data_accessible" property is not boolean'
)
STATELESS_NOT_BOOL_ERR_MSG = '"stateless" property is not boolean'
USE_CASE_PROP_TYPE_ERR = (
    '"use_case" property is not type of "SecretKeyUseCase"'
)
SHOULD_NOT_CONTAINS_ARGS_MSG = (
    '"keys_store" signature should not contains args'
)
STORE_IS_NOT_CALLABLE_MSG = '"keys_store" is not callable'
NAME_PROPERTY_IS_EMPTY_MSG = '"name" property is empty'

CALLBACK_ERROR_STRATEGY_ARG = 'on_key_changed_callback_error_strategy'
KEEP_IN_CACHE_ARG = 'keep_in_cache'
TARGET_DATA_ACCESSIBLE_ARG = 'target_data_accessible'
STATELESS_ARG = 'stateless'
USE_CASE_ARG = 'use_case'


class BaseSecretKeyDefinition(ABC):
    _name: str
    _store: KeysStore
    _use_case: SecretKeyUseCase
    _stateless: bool
    _target_data_accessible: bool
    _keep_in_cache: bool
    _on_key_changed_callback_error_strategy: OnKeyChangedCallbackErrorStrategy
    _on_change_callbacks: Dict[str, KeyChangedCallback]

    def __init__(self, name: str, keys_store: KeysStore, **kwargs):
        self._name = name
        self._keys_store = keys_store
        self._use_case = kwargs.get(
            USE_CASE_ARG, SecretKeyUseCase.ENCRYPTION_DECRYPTION
        )
        self._stateless = kwargs.get(STATELESS_ARG, True)
        self._target_data_accessible = kwargs.get(
            TARGET_DATA_ACCESSIBLE_ARG, True
        )
        self._keep_in_cache = kwargs.get(KEEP_IN_CACHE_ARG, True)
        self._on_key_changed_callback_error_strategy = kwargs.get(
            CALLBACK_ERROR_STRATEGY_ARG,
            OnKeyChangedCallbackErrorStrategy.HALT,
        )
        self._on_change_callbacks = OrderedDict()
        self._validate_properties()

    def _validate_properties(self):
        if not isinstance(self._name, str) or len(self._name) == 0:
            raise SecretKeyDefinitionInitError(NAME_PROPERTY_IS_EMPTY_MSG)
        if not callable(self._keys_store):
            raise SecretKeyDefinitionInitError(STORE_IS_NOT_CALLABLE_MSG)
        if (
            not isinstance(self._keys_store, Mock)
            and len(inspect.signature(self._keys_store).parameters) > 0
        ):
            raise SecretKeyDefinitionInitError(
                SHOULD_NOT_CONTAINS_ARGS_MSG
            )
        if not isinstance(self._use_case, SecretKeyUseCase):
            raise SecretKeyDefinitionInitError(USE_CASE_PROP_TYPE_ERR)
        if not isinstance(self._stateless, bool):
            raise SecretKeyDefinitionInitError(STATELESS_NOT_BOOL_ERR_MSG)
        if not isinstance(self._target_data_accessible, bool):
            raise SecretKeyDefinitionInitError(
                TARGET_DATA_ACCESSIBLE_NOT_BOOL_ERR_MSG
            )
        if not isinstance(self._keep_in_cache, bool):
            raise SecretKeyDefinitionInitError(
                KEEP_IN_CACHE_NOT_BOOL_ERR_MSG
            )
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

    def is_target_data_accessible(self) -> bool:
        return self._target_data_accessible

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

    def __str__(self):
        return str(self.asdict())

    def asdict(self) -> Dict:
        return {
            NAME_PROP: self._name,
            USE_CASE_PROP: self._use_case.name,
            STATELESS_PROP: self._stateless,
            KEEP_IN_CACHE_PROP: self._keep_in_cache,
            TARGET_DATA_ACCESSIBLE_PROP: self._target_data_accessible,
        }


class SecretKeyDefinition(BaseSecretKeyDefinition, SecretKeyState):
    _last_use: Optional[SecretKeyUseCase]
    _current_keys: Optional[SecretKeyPair]
    _previous_keys: Optional[SecretKeyPair]

    def __init__(self, name: str, keys_store: KeysStore, **kwargs):
        super(SecretKeyDefinition, self).__init__(
            name, keys_store, **kwargs
        )
        self._last_use = None
        self._current_keys = None
        self._previous_keys = None

    def set_keys_from_store(self) -> None:
        self._previous_keys = self._current_keys
        self._current_keys = SecretKeyPair(self._keys_store())

    @property
    def keys(self) -> SecretKeyPair:
        return self._current_keys

    @property
    def previous_keys(self) -> SecretKeyPair:
        return self._previous_keys

    def set_previous_keys(self, keys: SecretKeyPairValues):
        self._current_keys = SecretKeyPair(keys)

    def get_keys_or_previous(self) -> SecretKeyPair:
        if self._current_keys is not None:
            return self._current_keys
        else:
            return self._previous_keys

    def get_previous_or_current_keys(self) -> SecretKeyPair:
        if self._previous_keys is not None:
            return self._previous_keys
        return self._current_keys

    def get_last_use_case(self) -> SecretKeyUseCase:
        return self._last_use

    def set_last_use_case(self, use_case: SecretKeyUseCase) -> None:
        self._last_use = use_case

    def has_keys(self) -> bool:
        return (
            self._current_keys is not None
            or self._previous_keys is not None
        )

    def clean_keys(self) -> None:
        self._previous_keys = self.get_keys_or_previous()
        self._current_keys = None

    def clean_previous_keys(self) -> None:
        self._previous_keys = None

    def get_key_state(self) -> SecretKeyState:
        return self

    def set_key_state(self, key_state: SecretKeyState) -> None:
        self.set_last_use_case(key_state.get_last_use_case())
        previous_keys = key_state.get_previous_keys()
        if (
            previous_keys != self._previous_keys
            and previous_keys is not None
        ):
            self.set_previous_keys(previous_keys)

    def get_previous_keys(self):
        pass

    def clean_state(self):
        self.clean_keys()
        self.clean_previous_keys()

    def asdict(self):
        rv = super(SecretKeyDefinition, self).asdict()
        rv.update({LAST_USE_PROP: str(self._last_use)})
        return rv


class SecretKeyDefinitionInitError(InitError):
    def __init__(self, reason: str) -> None:
        super().__init__('SecretKeyDefinition', reason)
