from __future__ import annotations
from typing import Optional
from abc import ABC, abstractmethod
import logging
from keys_management import Key, KeysStore
from keys_management.consts import ENCRYPTION_KEY_TYPE, DECRYPTION_KEY_TYPE, PUBLIC_KEY_TYPE, PRIVATE_KEY_TYPE, ENCRYPTED_STATE, DECRYPTED_STATE

logger = logging.getLogger(__name__)


class KeyState(ABC):
    _keys_store: KeysStore = None
    _encrypt_key: Optional[Key] = None
    _decrypt_key: Optional[Key] = None

    def __init__(self, opposite_state: KeyState = None):
        logger.debug('init state')
        self._opposite_state = opposite_state
        self._is_entered = False

    def on_enter(self) -> None:
        logger.debug('on enter')
        self._set_keys_from_store()
        self._is_entered = True

    def _set_keys_from_store(self) -> None:
        if not isinstance(self._keys_store, KeysStore):
            raise UndefinedOperationError('set keys from key', 'keys store is not callable')
        logger.debug('setting keys from keys store')
        keys = self._keys_store()
        if isinstance(keys, (str, bytes)):
            self._encrypt_key = keys
            self._decrypt_key = keys
        elif isinstance(keys, dict):
            self._encrypt_key = keys[ENCRYPTION_KEY_TYPE] if ENCRYPTION_KEY_TYPE in keys else keys.get(PUBLIC_KEY_TYPE, None)
            self._decrypt_key = keys[DECRYPTION_KEY_TYPE] if DECRYPTION_KEY_TYPE in keys else keys.get(PRIVATE_KEY_TYPE, None)
        elif isinstance(keys, tuple):
            self._encrypt_key, self._decrypt_key = keys

    def on_exit(self) -> None:
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

    def _validate_can_get_key(self):
        logger.debug('validate_can_get_key while %s' % self._is_entered)
        if self._is_entered is False:
            raise UndefinedOperationError('get_key', 'not entered first')

    @property
    def opposite_state(self) -> KeyState:
        return self._opposite_state

    @opposite_state.setter
    def opposite_state(self, state):
        self._opposite_state = state

    @abstractmethod
    def set_keys_store(self, key_store: KeysStore) -> None:
        pass


class UnknownState(KeyState):
    def __init__(self):
        super().__init__(None)

    def on_enter(self) -> None:
        raise UndefinedOperationError('on_enter', 'in UnknownState')

    def on_exit(self) -> None:
        raise UndefinedOperationError('on_exit', 'in UnknownState')

    def is_use_for_encrypt(self) -> bool:
        raise UndefinedOperationError('is_use_for_encrypt', 'in UnknownState')

    def get_key(self) -> Key:
        raise UndefinedOperationError('get_key', 'in UnknownState')

    def set_keys_store(self, key_store: KeysStore) -> None:
        raise UndefinedOperationError('set_keys_store', 'in UnknownState')


class DecryptedState(KeyState):
    def __init__(self, opposite_state: KeyState = None):
        super(DecryptedState, self).__init__(opposite_state)

    def on_exit(self) -> None:
        super(DecryptedState, self).on_exit()
        self._opposite_state._decrypt_key = self._decrypt_key

    def get_key(self) -> Key:
        logger.debug('get key')
        self._validate_can_get_key()
        return self._encrypt_key

    def is_use_for_encrypt(self) -> bool:
        return True

    def set_keys_store(self, key_store: KeysStore) -> None:
        self._keys_store = key_store


class EncryptedState(KeyState):
    def __init__(self, opposite_state: KeyState = None):
        super(EncryptedState, self).__init__(opposite_state)

    def on_enter(self) -> None:
        logger.debug('on enter')
        if not self._decrypt_key:
            raise UndefinedOperationError('on_enter', 'decrypt key is not defined')
        self._is_entered = True

    def on_exit(self) -> None:
        super(EncryptedState, self).on_exit()

    def get_key(self) -> Key:
        logger.debug('get key')
        self._validate_can_get_key()
        return self._decrypt_key

    def is_use_for_encrypt(self) -> bool:
        return False

    def set_keys_store(self, keys_store: KeysStore) -> None:
        self._opposite_state.set_keys_store(keys_store)


class UndefinedOperationError(RuntimeError):
    def __init__(self, operation, reason):
        self.operation = operation
        self.reason = reason


class StateFactory(object):
    @staticmethod
    def create_state(state_name: str) -> KeyState:
        state_name = state_name.lower()
        if state_name in {ENCRYPTED_STATE, DECRYPTED_STATE}:
            decrypted_state = DecryptedState()
            encrypted_state = EncryptedState()
            decrypted_state.opposite_state = encrypted_state
            encrypted_state.opposite_state = decrypted_state
            return decrypted_state if state_name == DECRYPTED_STATE else encrypted_state
        else:
            raise UndefinedOperationError('create_state', 'the state name "%s" is not defined' % state_name)


