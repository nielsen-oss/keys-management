import logging
from . import KeyState, KeysStore, UndefinedOperationError
from .. import Key

logger = logging.getLogger(__name__)


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

    @property
    def name(self):
        return 'EncryptedState'