import pytest
from ..utils import create_decrypted_state, create_symmetry_key_store, create_asymmetric_key_store
from keys_management.key_state import UndefinedOperationError
from keys_management.key_state.encrypted_state import EncryptedState
from keys_management.consts import ENCRYPTION_KEY_TYPE, DECRYPTION_KEY_TYPE


def test_on_enter__without_key_store_error_is_raised():
    state = create_decrypted_state()
    with pytest.raises(UndefinedOperationError):
        state.on_enter()
    assert state._is_entered is False


def test_on_enter__with_symmetric_key_store_keys_were_set():
    state = create_decrypted_state()
    key_store = create_symmetry_key_store()
    assert state._encrypt_key is None
    assert state._decrypt_key is None
    state.set_keys_store(key_store)
    assert state._encrypt_key is None
    assert state._decrypt_key is None
    expected_key = key_store()
    state.on_enter()
    assert state._encrypt_key == expected_key
    assert state._decrypt_key == expected_key
    assert state._is_entered is True


def test_on_enter__with_asymmetric_key_store_keys_were_set():
    state = create_decrypted_state()
    key_store = create_asymmetric_key_store()
    assert state._encrypt_key is None
    assert state._decrypt_key is None
    state.set_keys_store(key_store)
    assert state._encrypt_key is None
    assert state._decrypt_key is None
    expected_keys = key_store()
    state.on_enter()
    assert state._encrypt_key == expected_keys[ENCRYPTION_KEY_TYPE]
    assert state._decrypt_key == expected_keys[DECRYPTION_KEY_TYPE]
    assert state._is_entered is True


def test_get_key__without_entering_first_error_is_raised():
    state = create_decrypted_state()
    with pytest.raises(UndefinedOperationError):
        state.get_key()


def test_get_key_with_symmetric_key():
    state = create_decrypted_state()
    key_store = create_symmetry_key_store()
    expected_key = key_store()
    state.set_keys_store(key_store)
    state.on_enter()
    assert state.get_key() == expected_key


def test_get_key_with_asymmetric_key():
    state = create_decrypted_state()
    key_store = create_asymmetric_key_store()
    expected_key = key_store()[ENCRYPTION_KEY_TYPE]
    state.set_keys_store(key_store)
    state.on_enter()
    assert state.get_key() == expected_key


def test_on_exit__with_symmetric_key_store_keys_were_set():
    state = create_decrypted_state()
    key_store = create_symmetry_key_store()
    state.set_keys_store(key_store)
    assert state.opposite_state._decrypt_key is None
    state.on_enter()
    expected_decrypt_key = state._decrypt_key
    assert state._is_entered is True
    assert state._encrypt_key is not None
    assert expected_decrypt_key is not None
    state.on_exit()
    assert state.opposite_state._decrypt_key == expected_decrypt_key
    assert state._is_entered is False
    assert state._encrypt_key is None
    assert state._decrypt_key is None


def test_on_exit__with_asymmetric_key_store_keys_were_set():
    state = create_decrypted_state()
    key_store = create_asymmetric_key_store()
    state.set_keys_store(key_store)
    assert state.opposite_state._decrypt_key is None
    state.on_enter()
    expected_decrypt_key = state._decrypt_key
    assert state._is_entered is True
    assert state._encrypt_key is not None
    assert expected_decrypt_key is not None
    state.on_exit()
    assert state.opposite_state._decrypt_key == expected_decrypt_key
    assert state._is_entered is False


def test_is_use_for_encrypt():
    state = create_decrypted_state()
    assert state.is_use_for_encrypt() is True


def test_opposite_state():
    state = create_decrypted_state()
    assert isinstance(state.opposite_state, EncryptedState)
    assert state.opposite_state.opposite_state == state


def test_set_keys_store():
    state = create_decrypted_state()
    excepted_key_store = create_symmetry_key_store()
    state.set_keys_store(excepted_key_store)
    assert state._keys_store == excepted_key_store
    assert state.opposite_state._keys_store is None
