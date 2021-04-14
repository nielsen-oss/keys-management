from typing import Dict

from keys_management.secret_key import SecretKeyUseCase
from keys_management.state_based.key_state import OneState
from keys_management.state_based.key_state.unknown_state import (
    UnknownState,
)
from keys_management.state_based.key_state.decrypted_state import (
    DecryptedState,
)
from keys_management.state_based.key_state.encrypted_state import (
    EncryptedState,
)


def create_unknown_state() -> UnknownState:
    return UnknownState()


def create_decrypted_state() -> DecryptedState:
    decrypted_state = DecryptedState()
    encrypted_state = EncryptedState()
    decrypted_state.set_opposite_state(encrypted_state)
    encrypted_state.set_opposite_state(decrypted_state)
    return decrypted_state


def create_encrypted_state() -> EncryptedState:
    decrypted_state = DecryptedState()
    encrypted_state = EncryptedState()
    decrypted_state.set_opposite_state(encrypted_state)
    encrypted_state.set_opposite_state(decrypted_state)
    return encrypted_state


def create_one_state():
    return StubOneState()


class StubOneState(OneState):
    def get_use_case(self) -> SecretKeyUseCase:
        return SecretKeyUseCase.ENCRYPTION_DECRYPTION

    def get_name(self) -> str:
        return "OneState"

    def to_dict(self) -> Dict:
        pass

    def __init__(self):
        super().__init__()


def create_symmetry_key_store():
    return lambda: 'key'


def create_asymmetric_key_store():
    return lambda: {'encrypt': 'encrypt_key', 'decrypt': 'decrypt_key'}
