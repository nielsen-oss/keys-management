from keys_management.state import UnknownState, DecryptedState, EncryptedState


def create_unknown_state() -> UnknownState:
    return UnknownState()


def create_decrypted_state() -> DecryptedState:
    decrypted_state = DecryptedState()
    encrypted_state = EncryptedState()
    decrypted_state.opposite_state = encrypted_state
    encrypted_state.opposite_state = decrypted_state
    return decrypted_state


def create_encrypted_state() -> EncryptedState:
    decrypted_state = DecryptedState()
    encrypted_state = EncryptedState()
    decrypted_state.opposite_state = encrypted_state
    encrypted_state.opposite_state = decrypted_state
    return encrypted_state


def create_symmetry_key_store():
    return lambda: 'key'


def create_asymmetric_key_store():
    return lambda: {'encrypt': 'encrypt_key', 'decrypt': 'decrypt_key'}
