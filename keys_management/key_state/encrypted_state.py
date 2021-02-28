import logging
from . import KeyState, KeysStore, UndefinedOperationError
from .. import Key

logger = logging.getLogger(__name__)


class EncryptedState(KeyState):
    def __init__(self, opposite_state: KeyState = None):
        super(EncryptedState, self).__init__(opposite_state)

    def set_key(self, key):
        if key is None:
            raise UndefinedOperationError("set_key", "cannot set None key in EncryptedState")
        self.set_decrypt_key(key)

    def enter(self) -> None:
        logger.debug('on enter')
        if not self._decrypt_key:
            raise UndefinedOperationError('enter', 'decrypt key is not defined')
        self._is_entered = True

    def exit(self) -> None:
        super(EncryptedState, self).exit()

    def get_key(self) -> Key:
        logger.debug('get key')
        self._validate_can_get_key()
        return self._decrypt_key

    def is_use_for_encrypt(self) -> bool:
        return False

    def set_keys_store(self, keys_store: KeysStore) -> None:
        self._opposite_state.set_keys_store(keys_store)

    def get_name(self) -> str:
        return 'EncryptedState'
