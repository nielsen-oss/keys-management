from __future__ import annotations
from typing import Callable, Union, Dict, TYPE_CHECKING
from enum import Enum
import logging
from .on_change_key_definition import OnChangeKeyDefinition
from .errors import OnKeyChangedCallbackErrorStrategy, KeyChangedError

logger = logging.getLogger(__name__)


class CallbackStatus(Enum):
    PENDING = 0
    IN_PROGRESS = 1
    FAILED = 2
    SUCCEEDED = 3


if TYPE_CHECKING:
    from .secret_key import SecretKeyPairValues
    from .secret_key.key_definition import SecretKeyDefinition

    KeyChangedCallback = Callable[
        [
            Union[SecretKeyPairValues],
            Union[SecretKeyPairValues],
            OnChangeKeyDefinition,
        ],
        None,
    ]
    Callbacks = Dict[
        str, Dict[str, Union[str, KeyChangedCallback, CallbackStatus]]
    ]


class KeyChangedContext:
    _key_name: str
    _on_change_key_definition: OnChangeKeyDefinition
    _on_key_changed_callback_error_strategy: OnKeyChangedCallbackErrorStrategy
    _strategy_function: callable
    _callbacks: Callbacks
    _has_error: bool
    _old_keys: SecretKeyPairValues
    _new_keys: SecretKeyPairValues

    def __init__(
        self,
        key_definition: SecretKeyDefinition,
        on_error_strategy: callable,
        old_keys: SecretKeyPairValues,
        new_keys: SecretKeyPairValues,
    ) -> None:
        self._key_name = key_definition.name
        self._on_change_key_definition = OnChangeKeyDefinition(
            key_definition
        )
        self._on_key_changed_callback_error_strategy = (
            key_definition.on_key_changed_callback_error_strategy
        )
        self._strategy_function = on_error_strategy
        self._callbacks = self._create_callbacks(
            key_definition.on_change_callbacks
        )
        self._old_keys = old_keys
        self._new_keys = new_keys
        self._has_error = False

    def __getitem__(self, item):
        return self._callbacks[item]

    @staticmethod
    def _create_callbacks(
        on_change_callbacks: Dict[str, KeyChangedCallback]
    ) -> Callbacks:
        return {
            callback_name: {
                'name': callback_name,
                'callback': callback,
                'status': CallbackStatus.PENDING,
            }
            for callback_name, callback in on_change_callbacks.items()
        }

    def run_callbacks(self):
        for callback_name, callback_ctx in self._callbacks.items():
            try:
                logger.info(
                    'Going to execute the callback "%s"' % callback_name
                )
                callback_ctx['status'] = CallbackStatus.IN_PROGRESS
                callback_ctx['callback'](
                    self._old_keys,
                    self._new_keys,
                    self._on_change_key_definition,
                )
                callback_ctx['status'] = CallbackStatus.SUCCEEDED
            except Exception as e:
                self._has_error = True
                callback_ctx['status'] = CallbackStatus.FAILED
                callback_ctx['error'] = e
                self._strategy_function(
                    self._key_name, callback_name, self
                )
        if (
            self._on_key_changed_callback_error_strategy
            == OnKeyChangedCallbackErrorStrategy.SKIP_AND_RAISE
            and self._has_error
        ):
            raise KeyChangedError(self._key_name, self)
