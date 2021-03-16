from __future__ import annotations
from typing import Dict, Callable, Optional, TYPE_CHECKING
from abc import ABC, abstractmethod
import logging
from keys_management.secret_key import SecretKeyUseCase, SecretKey
if TYPE_CHECKING:
    from keys_management.secret_key import KeysStore, SecretKeyUseCase

logger = logging.getLogger(__name__)
SecretKeyStore = Callable[[], SecretKey]


class KeyState(ABC):
    def __init__(self, opposite_state: KeyState = None):
        logger.debug('init "%s" state' % self.get_name())
        self._opposite_state = opposite_state
        self._is_entered = False

    def enter(self) -> None:
        logger.debug('enter to "%s"' % self.get_name())
        self._concrete_enter()
        self._is_entered = True

    def exit(self) -> None:
        logger.debug('exit from "%s"' % self.get_name())
        self._concrete_exit()
        self._is_entered = False

    @abstractmethod
    def _concrete_enter(self):
        pass

    @abstractmethod
    def _concrete_exit(self):
        pass

    @abstractmethod
    def get_use_case(self) -> SecretKeyUseCase:
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
        logger.debug('validate_can_get_key while _is_entered=%s' % self._is_entered)
        if self._is_entered is False:
            raise UndefinedOperationError('get_key', 'not entered first')

    def get_opposite_state(self) -> KeyState:
        return self._opposite_state

    def set_opposite_state(self, state: KeyState) -> None:
        self._opposite_state = state


class OneState(KeyState, ABC):
    _secret_key: Optional[SecretKey]
    _key_store: SecretKeyStore = None

    def __init__(self):
        super(OneState, self).__init__(self)
        self._secret_key = None

    def set_keys_store(self, key_store: KeysStore) -> None:
        self._key_store = lambda: SecretKey(key_store())

    def _concrete_exit(self):
        self._secret_key = None

    def _concrete_enter(self):
        if not callable(self._key_store):
            raise UndefinedOperationError('set key from key store', 'keys store is not callable')
        self._secret_key = self._key_store()

    def get_key(self) -> SecretKey:
        logger.debug('get key')
        self._validate_can_get_key()
        return self._secret_key

    def set_key(self, secret_key: SecretKey):
        self._secret_key = secret_key


class UndefinedOperationError(RuntimeError):
    def __init__(self, operation: str, reason: str):
        self.operation = operation
        self.reason = reason

