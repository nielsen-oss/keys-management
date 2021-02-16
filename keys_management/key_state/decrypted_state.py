import logging
from . import KeyState, KeysStore
from .. import Key

logger = logging.getLogger(__name__)


class DecryptedState(KeyState):
    def __init__(self, opposite_state: KeyState = None):
        super(DecryptedState, self).__init__(opposite_state)

    def on_exit(self) -> None:
        self._opposite_state._decrypt_key = self._decrypt_key
        super(DecryptedState, self).on_exit()

    def get_key(self) -> Key:
        logger.debug('get key')
        self._validate_can_get_key()
        return self._encrypt_key

    def is_use_for_encrypt(self) -> bool:
        return True

    def set_keys_store(self, key_store: KeysStore) -> None:
        self._keys_store = key_store

    @property
    def name(self):
        return 'DecryptedState'
