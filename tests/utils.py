from keys_management.key_state.unknown_state import UnknownState
from keys_management.key_state.decrypted_state import DecryptedState
from keys_management.key_state.encrypted_state import EncryptedState


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


def create_symmetry_key_store():
    return lambda: 'key'


def create_asymmetric_key_store():
    return lambda: {'encrypt': 'encrypt_key', 'decrypt': 'decrypt_key'}
