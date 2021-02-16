from . import KeyState, UndefinedOperationError
from .decrypted_state import DecryptedState
from .encrypted_state import EncryptedState
from ..consts import ENCRYPTED_STATE, DECRYPTED_STATE


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