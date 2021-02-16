import pytest
from ..utils import create_encrypted_state, create_symmetry_key_store
from keys_management.key_state import UndefinedOperationError
from keys_management.key_state.decrypted_state import DecryptedState


def test_on_enter__decrypt_key_was_not_set_error_is_raised():
    state = create_encrypted_state()
    assert state._decrypt_key is None
    with pytest.raises(UndefinedOperationError):
        state.on_enter()
    assert state._is_entered is False


def test_on_enter__decrypt_key_was_set():
    state = create_encrypted_state()
    key_store = create_symmetry_key_store()
    state._decrypt_key = key_store()
    state.on_enter()
    assert state._is_entered is True


def test_get_key__without_entering_first_error_is_raised():
    state = create_encrypted_state()
    with pytest.raises(UndefinedOperationError):
        state.get_key()


def test_get_key():
    state = create_encrypted_state()
    key_store = create_symmetry_key_store()
    expected_key = key_store()
    state._decrypt_key = key_store()
    state.set_keys_store(key_store)
    state.on_enter()
    assert state.get_key() == expected_key


def test_on_exit():
    state = create_encrypted_state()
    state._decrypt_key = 'key'
    state.on_enter()
    state.on_exit()
    assert state.opposite_state._decrypt_key == state._decrypt_key
    assert state._is_entered is False
    assert state._decrypt_key is None


def test_is_use_for_encrypt():
    state = create_encrypted_state()
    assert state.is_use_for_encrypt() is False


def test_opposite_state():
    state = create_encrypted_state()
    assert isinstance(state.opposite_state, DecryptedState)
    assert state.opposite_state.opposite_state == state


def test_set_keys_store():
    state = create_encrypted_state()
    excepted_key_store = create_symmetry_key_store()
    state.set_keys_store(excepted_key_store)
    assert state._keys_store is None
    assert state.opposite_state._keys_store == excepted_key_store
