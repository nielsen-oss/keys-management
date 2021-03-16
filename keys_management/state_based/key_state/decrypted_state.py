from __future__ import annotations
import logging
from typing import Dict, Optional, Callable, TYPE_CHECKING
from . import KeyState, UndefinedOperationError
from keys_management import SecretKeyUseCase
from keys_management.consts import STATE, DECRYPTED_STATE
from keys_management.secret_key import SecretKey, SecretKeyPair
if TYPE_CHECKING:
    from keys_management import KeysStore
logger = logging.getLogger(__name__)

SecretKeyPairStore = Callable[[], SecretKeyPair]


class DecryptedState(KeyState):
    _secret_key_pair: Optional[SecretKeyPair]
    _keys_store: SecretKeyPairStore = None

    def __init__(self, opposite_state: KeyState = None):
        super(DecryptedState, self).__init__(opposite_state)
        self._secret_key_pair = None

    def set_keys_store(self, key_store: KeysStore) -> None:
        self._keys_store = lambda: SecretKeyPair(key_store())

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

    def get_name(self) -> str:
        return 'DecryptedState'

    def get_use_case(self) -> SecretKeyUseCase:
        return SecretKeyUseCase.ENCRYPTION
