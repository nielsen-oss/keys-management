from __future__ import annotations
from typing import Optional, TYPE_CHECKING
from . import KeyState, UndefinedOperationError
from .decrypted_state import DecryptedState
from .encrypted_state import EncryptedState
from .authentication_state import AuthenticationState
from .stateless_state import StatelessState
from keys_management.secret_key import SecretKey
from ..consts import DECRYPTED_STATE, ENCRYPTED_STATE, AUTHENTICATION_STATE, TEMP_STATE_NAME
if TYPE_CHECKING:
    from keys_management import SecretKeyValue, KeysStore


class StateFactory(object):
    @staticmethod
    def create_state(state_name: str, keys_store: Optional[KeysStore] = None, key: Optional[SecretKeyValue] = None) -> KeyState:
        state_name = state_name.lower()
        if state_name in {ENCRYPTED_STATE, DECRYPTED_STATE, AUTHENTICATION_STATE, TEMP_STATE_NAME}:
            rv_state = StateFactory._create_rv_state(state_name)
            rv_state.set_keys_store(keys_store)
            if key is not None:
                rv_state.set_key(SecretKey(key))
            return rv_state
        else:
            raise UndefinedOperationError('create_state', 'the state name "%s" is not defined' % state_name)

    @staticmethod
    def _create_rv_state(state_name):
        if state_name in {ENCRYPTED_STATE, DECRYPTED_STATE}:
            decrypted_state = DecryptedState()
            encrypted_state = EncryptedState()
            decrypted_state.set_opposite_state(encrypted_state)
            encrypted_state.set_opposite_state(decrypted_state)
            rv_state = decrypted_state if state_name == DECRYPTED_STATE else encrypted_state
        elif state_name == AUTHENTICATION_STATE:
            rv_state = AuthenticationState()
        else:
            rv_state = StatelessState()
        return rv_state

