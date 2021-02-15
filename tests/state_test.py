import pytest

from keys_management.state import UndefinedOperationError
from keys_management.consts import ENCRYPTION_KEY_TYPE, DECRYPTION_KEY_TYPE
from tests.utils import *


def test_on_enter_unknown_state__error_is_raised():
    state = create_unknown_state()
    with pytest.raises(UndefinedOperationError):
        state.on_enter()


def test_on_exit_unknown_state__error_is_raised():
    state = create_unknown_state()
    with pytest.raises(UndefinedOperationError):
        state.on_exit()


def test_is_use_for_encrypt_unknown_state__error_is_raised():
    state = create_unknown_state()
    with pytest.raises(UndefinedOperationError):
        state.is_use_for_encrypt()


def test_get_key_unknown_state__error_is_raised():
    state = create_unknown_state()
    with pytest.raises(UndefinedOperationError):
        state.get_key()


def test_opposite_state_unknown_state__error_is_raised():
    state = create_unknown_state()
    assert state.opposite_state is None


def test_set_keys_store_unknown_state__error_is_raised():
    state = create_unknown_state()
    with pytest.raises(UndefinedOperationError):
        state.set_keys_store(create_symmetry_key_store())


def test_on_enter_decrypted_state__without_key_store_error_is_raised():
    state = create_decrypted_state()
    with pytest.raises(UndefinedOperationError):
        state.on_enter()
    assert state._is_entered is False


def test_on_enter_decrypted_state__with_symmetric_key_store_keys_were_set():
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


def test_on_enter_decrypted_state__with_asymmetric_key_store_keys_were_set():
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


def test_get_key_decrypted_state__without_entering_first_error_is_raised():
    state = create_decrypted_state()
    with pytest.raises(UndefinedOperationError):
        state.get_key()


def test_get_key_decrypted_state_with_symmetric_key():
    state = create_decrypted_state()
    key_store = create_symmetry_key_store()
    expected_key = key_store()
    state.set_keys_store(key_store)
    state.on_enter()
    assert state.get_key() == expected_key


def test_get_key_decrypted_state_with_asymmetric_key():
    state = create_decrypted_state()
    key_store = create_asymmetric_key_store()
    expected_key = key_store()[ENCRYPTION_KEY_TYPE]
    state.set_keys_store(key_store)
    state.on_enter()
    assert state.get_key() == expected_key


def test_on_exit_decrypted_state__with_symmetric_key_store_keys_were_set():
    state = create_decrypted_state()
    key_store = create_symmetry_key_store()
    state.set_keys_store(key_store)
    assert state.opposite_state._decrypt_key is None
    state.on_enter()
    assert state._is_entered is True
    assert state._encrypt_key is not None
    assert state._decrypt_key is not None
    state.on_exit()
    assert state.opposite_state._decrypt_key == state._decrypt_key
    assert state._is_entered is False
    assert state._encrypt_key is None
    assert state._decrypt_key is None


def test_on_exit_decrypted_state__with_asymmetric_key_store_keys_were_set():
    state = create_decrypted_state()
    key_store = create_asymmetric_key_store()
    state.set_keys_store(key_store)
    assert state.opposite_state._decrypt_key is None
    state.on_enter()
    assert state._is_entered is True
    assert state._encrypt_key is not None
    assert state._decrypt_key is not None
    state.on_exit()
    assert state.opposite_state._decrypt_key == state._decrypt_key
    assert state._is_entered is False


def test_is_use_for_encrypt_decrypted_state():
    state = create_decrypted_state()
    assert state.is_use_for_encrypt() is True


def test_opposite_state_decrypted_state():
    state = create_decrypted_state()
    assert isinstance(state.opposite_state, EncryptedState)
    assert state.opposite_state.opposite_state == state


def test_set_keys_store_decrypted_state():
    state = create_decrypted_state()
    excepted_key_store = create_symmetry_key_store()
    state.set_keys_store(excepted_key_store)
    assert state._keys_store == excepted_key_store
    assert state.opposite_state._keys_store is None






def test_on_enter_encrypted_state__decrypt_key_was_not_set_error_is_raised():
    state = create_encrypted_state()
    assert state._decrypt_key is None
    with pytest.raises(UndefinedOperationError):
        state.on_enter()
    assert state._is_entered is False


def test_on_enter_encrypted_state__decrypt_key_was_set():
    state = create_encrypted_state()
    key_store = create_symmetry_key_store()
    state._decrypt_key = key_store()
    state.on_enter()
    assert state._is_entered is True


def test_get_key_encrypted_state__without_entering_first_error_is_raised():
    state = create_encrypted_state()
    with pytest.raises(UndefinedOperationError):
        state.get_key()


def test_get_key_encrypted_state():
    state = create_encrypted_state()
    key_store = create_symmetry_key_store()
    expected_key = key_store()
    state._decrypt_key = key_store()
    state.set_keys_store(key_store)
    state.on_enter()
    assert state.get_key() == expected_key


def test_on_exit_encrypted_state():
    state = create_encrypted_state()
    state._decrypt_key = 'key'
    state.on_enter()
    state.on_exit()
    assert state.opposite_state._decrypt_key == state._decrypt_key
    assert state._is_entered is False
    assert state._decrypt_key is None


def test_is_use_for_encrypt_encrypted_state():
    state = create_encrypted_state()
    assert state.is_use_for_encrypt() is False


def test_opposite_state_encrypted_state():
    state = create_encrypted_state()
    assert isinstance(state.opposite_state, DecryptedState)
    assert state.opposite_state.opposite_state == state


def test_set_keys_store_encrypted_state():
    state = create_encrypted_state()
    excepted_key_store = create_symmetry_key_store()
    state.set_keys_store(excepted_key_store)
    assert state._keys_store is None
    assert state.opposite_state._keys_store == excepted_key_store

