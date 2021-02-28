from typing import Optional
from . import KeyState, UndefinedOperationError
from .decrypted_state import DecryptedState
from .encrypted_state import EncryptedState
from ..consts import ENCRYPTED_STATE, DECRYPTED_STATE
from .. import KeysStore, Key


class StateFactory(object):
    @staticmethod
    def create_state(state_name: str, keys_store: Optional[KeysStore] = None, key: Optional[Key] = None) -> KeyState:
        state_name = state_name.lower()
        if state_name in {ENCRYPTED_STATE, DECRYPTED_STATE}:
            decrypted_state = DecryptedState()
            encrypted_state = EncryptedState()
            decrypted_state.set_opposite_state(encrypted_state)
            encrypted_state.set_opposite_state(decrypted_state)
            rv_state = decrypted_state if state_name == DECRYPTED_STATE else encrypted_state
            rv_state.set_keys_store(keys_store)
            rv_state.set_key(key)
            return rv_state
        else:
            raise UndefinedOperationError('create_state', 'the state name "%s" is not defined' % state_name)