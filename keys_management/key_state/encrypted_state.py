import logging
from typing import Optional, Dict
from . import KeyState, UndefinedOperationError
from .. import KeysStore
from ..consts import STATE, ENCRYPTED_STATE, KEY
from ..secret_key import SecretKey

logger = logging.getLogger(__name__)


class EncryptedState(KeyState):
    _decrypt_key: Optional[SecretKey]

    def __init__(self, opposite_state: KeyState = None):
        super(EncryptedState, self).__init__(opposite_state)
        self._decrypt_key = None

    def _concrete_enter(self) -> None:
        if not self._decrypt_key:
            raise UndefinedOperationError('enter', 'decrypt key is not defined')

    def to_dict(self) -> Dict:
        return {
            STATE: ENCRYPTED_STATE,
            KEY: self.get_key()
        }

    def set_key(self, key: SecretKey):
        if key is None:
            raise UndefinedOperationError("set_key", "cannot set None key in EncryptedState")
        self._decrypt_key = key

    def _concrete_exit(self) -> None:
        self._decrypt_key = None

    def get_key(self) -> SecretKey:
        logger.debug('get key')
        self._validate_can_get_key()
        return self._decrypt_key

    def is_use_for_encrypt(self) -> bool:
        return False

    def set_keys_store(self, keys_store: KeysStore) -> None:
        self._opposite_state.set_keys_store(keys_store)

    def get_name(self) -> str:
        return 'EncryptedState'
