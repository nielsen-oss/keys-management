from __future__ import annotations
from typing import Dict
from abc import ABC, abstractmethod
import logging
from keys_management import KeysStore
from ..secret_key import SecretKey

logger = logging.getLogger(__name__)


class KeyState(ABC):

    def __init__(self, opposite_state: KeyState = None):
        logger.debug('init state')
        self._opposite_state = opposite_state
        self._is_entered = False

    def enter(self) -> None:
        logger.debug('on enter')
        self._concrete_enter()
        self._is_entered = True

    def exit(self) -> None:
        logger.debug('on exit')
        self._concrete_exit()
        self._is_entered = False

    @abstractmethod
    def _concrete_enter(self):
        pass

    @abstractmethod
    def _concrete_exit(self):
        pass

    @abstractmethod
    def is_use_for_encrypt(self) -> bool:
        pass

    @abstractmethod
    def get_key(self) -> SecretKey:
        pass

    @abstractmethod
    def set_keys_store(self, key_store: KeysStore) -> None:
        pass

    @abstractmethod
    def get_name(self) -> str:
        pass

    @abstractmethod
    def set_key(self, secret_key: SecretKey):
        pass

    @abstractmethod
    def to_dict(self) -> Dict:
        pass

    def _validate_can_get_key(self) -> None:
        logger.debug('validate_can_get_key while %s' % self._is_entered)
        if self._is_entered is False:
            raise UndefinedOperationError('get_key', 'not entered first')

    def get_opposite_state(self) -> KeyState:
        return self._opposite_state

    def set_opposite_state(self, state: KeyState) -> None:
        self._opposite_state = state


class UndefinedOperationError(RuntimeError):
    def __init__(self, operation: str, reason: str):
        self.operation = operation
        self.reason = reason





