import logging
from typing import Dict, Optional, Callable
from . import KeyState, UndefinedOperationError
from .. import KeysStore
from ..consts import STATE, DECRYPTED_STATE
from ..secret_key import SecretKey, SecretKeyPair

logger = logging.getLogger(__name__)

ProcessedKeyStore = Callable[[], SecretKeyPair]


class DecryptedState(KeyState):
    _keys_store: ProcessedKeyStore = None
    _secret_key_pair: Optional[SecretKeyPair]

    def __init__(self, opposite_state: KeyState = None):
        super(DecryptedState, self).__init__(opposite_state)
        self._secret_key_pair = None

    def _concrete_enter(self):
        if not callable(self._keys_store):
            raise UndefinedOperationError('set keys from key', 'keys store is not callable')
        self._secret_key_pair = self._keys_store()

    def to_dict(self) -> Dict:
        return {STATE: DECRYPTED_STATE}

    def _concrete_exit(self) -> None:
        self._opposite_state.set_key(self._secret_key_pair.decrypt_key)
        self._secret_key_pair = None

    def set_key(self, key: SecretKey):
        pass

    def get_key(self) -> SecretKey:
        logger.debug('get key')
        self._validate_can_get_key()
        return self._secret_key_pair.encrypt_key

    def is_use_for_encrypt(self) -> bool:
        return True

    def set_keys_store(self, key_store: KeysStore) -> None:
        self._keys_store = lambda: SecretKeyPair(key_store())

    def get_name(self) -> str:
        return 'DecryptedState'
