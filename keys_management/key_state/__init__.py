from __future__ import annotations
from typing import Optional
from abc import ABC, abstractmethod
import logging
from keys_management import Key, KeysStore
from keys_management.consts import ENCRYPTION_KEY_TYPE, DECRYPTION_KEY_TYPE, PUBLIC_KEY_TYPE, PRIVATE_KEY_TYPE

logger = logging.getLogger(__name__)


class KeyState(ABC):
    _keys_store: KeysStore = None
    _encrypt_key: Optional[Key] = None
    _decrypt_key: Optional[Key] = None

    def __init__(self, opposite_state: KeyState = None):
        logger.debug('init state')
        self._opposite_state = opposite_state
        self._is_entered = False

    def enter(self) -> None:
        logger.debug('on enter')
        self._set_keys_from_store()
        self._is_entered = True

    def _set_keys_from_store(self) -> None:
        if not callable(self._keys_store):
            raise UndefinedOperationError('set keys from key', 'keys store is not callable')
        logger.debug('setting keys from keys store')
        keys = self._keys_store()
        encrypt_key, decrypt_key = None, None
        if isinstance(keys, (str, bytes)):
            encrypt_key = keys
            decrypt_key = keys
        elif isinstance(keys, dict):
            encrypt_key = keys[ENCRYPTION_KEY_TYPE] if ENCRYPTION_KEY_TYPE in keys else keys.get(PUBLIC_KEY_TYPE, None)
            decrypt_key = keys[DECRYPTION_KEY_TYPE] if DECRYPTION_KEY_TYPE in keys else keys.get(PRIVATE_KEY_TYPE, None)
        elif isinstance(keys, tuple):
            encrypt_key, decrypt_key = keys
        self.set_encrypt_key(encrypt_key)
        self.set_decrypt_key(decrypt_key)

    def exit(self) -> None:
        logger.debug('on exit')
        self._encrypt_key = None
        self._decrypt_key = None
        self._is_entered = False

    @abstractmethod
    def is_use_for_encrypt(self) -> bool:
        pass

    @abstractmethod
    def get_key(self) -> Key:
        pass

    def _validate_can_get_key(self) -> None:
        logger.debug('validate_can_get_key while %s' % self._is_entered)
        if self._is_entered is False:
            raise UndefinedOperationError('get_key', 'not entered first')

    def get_opposite_state(self) -> KeyState:
        return self._opposite_state

    def set_opposite_state(self, state: KeyState) -> None:
        self._opposite_state = state

    @abstractmethod
    def set_keys_store(self, key_store: KeysStore) -> None:
        pass

    @abstractmethod
    def get_name(self) -> str:
        pass

    @abstractmethod
    def set_key(self, key):
        pass

    def set_encrypt_key(self, key):
        self._encrypt_key = key

    def set_decrypt_key(self, key):
        self._decrypt_key = key


class UndefinedOperationError(RuntimeError):
    def __init__(self, operation: str, reason: str):
        self.operation = operation
        self.reason = reason





