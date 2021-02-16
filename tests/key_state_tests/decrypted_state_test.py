import pytest
from ..utils import create_decrypted_state, create_symmetry_key_store, create_asymmetric_key_store
from keys_management.key_state import UndefinedOperationError
from keys_management.key_state.encrypted_state import EncryptedState
from keys_management.consts import ENCRYPTION_KEY_TYPE, DECRYPTION_KEY_TYPE


@pytest.fixture
def decrypted_state():
    return create_decrypted_state()


@pytest.fixture
def symmetry_key_store():
    return create_symmetry_key_store()


@pytest.fixture
def asymmetric_key_store():
    return create_asymmetric_key_store()


@pytest.fixture
def key_store():
    return create_symmetry_key_store()


class TestDecryptedState:
    def test_on_enter__without_key_store_error_is_raised(self, decrypted_state):
        with pytest.raises(UndefinedOperationError):
            decrypted_state.on_enter()
        assert decrypted_state._is_entered is False

    def test_on_enter__with_symmetric_key_store_keys_were_set(self, decrypted_state, symmetry_key_store):
        assert decrypted_state._encrypt_key is None
        assert decrypted_state._decrypt_key is None
        decrypted_state.set_keys_store(symmetry_key_store)
        assert decrypted_state._encrypt_key is None
        assert decrypted_state._decrypt_key is None
        expected_key = symmetry_key_store()
        decrypted_state.on_enter()
        assert decrypted_state._encrypt_key == expected_key
        assert decrypted_state._decrypt_key == expected_key
        assert decrypted_state._is_entered is True

    def test_on_enter__with_asymmetric_key_store_keys_were_set(self, decrypted_state, asymmetric_key_store):
        assert decrypted_state._encrypt_key is None
        assert decrypted_state._decrypt_key is None
        decrypted_state.set_keys_store(asymmetric_key_store)
        assert decrypted_state._encrypt_key is None
        assert decrypted_state._decrypt_key is None
        expected_keys = asymmetric_key_store()
        decrypted_state.on_enter()
        assert decrypted_state._encrypt_key == expected_keys[ENCRYPTION_KEY_TYPE]
        assert decrypted_state._decrypt_key == expected_keys[DECRYPTION_KEY_TYPE]
        assert decrypted_state._is_entered is True

    def test_get_key__without_entering_first_error_is_raised(self, decrypted_state):
        with pytest.raises(UndefinedOperationError):
            decrypted_state.get_key()

    def test_get_key_with_symmetric_key(self, decrypted_state, symmetry_key_store):
        expected_key = symmetry_key_store()
        decrypted_state.set_keys_store(symmetry_key_store)
        decrypted_state.on_enter()
        assert decrypted_state.get_key() == expected_key

    def test_get_key_with_asymmetric_key(self, decrypted_state, asymmetric_key_store):
        expected_key = asymmetric_key_store()[ENCRYPTION_KEY_TYPE]
        decrypted_state.set_keys_store(asymmetric_key_store)
        decrypted_state.on_enter()
        assert decrypted_state.get_key() == expected_key

    def test_on_exit__with_symmetric_key_store_keys_were_set(self, decrypted_state, symmetry_key_store):
        decrypted_state.set_keys_store(symmetry_key_store)
        assert decrypted_state.opposite_state._decrypt_key is None
        decrypted_state.on_enter()
        expected_decrypt_key = decrypted_state._decrypt_key
        assert decrypted_state._is_entered is True
        assert decrypted_state._encrypt_key is not None
        assert expected_decrypt_key is not None
        decrypted_state.on_exit()
        assert decrypted_state.opposite_state._decrypt_key == expected_decrypt_key
        assert decrypted_state._is_entered is False
        assert decrypted_state._encrypt_key is None
        assert decrypted_state._decrypt_key is None

    def test_on_exit__with_asymmetric_key_store_keys_were_set(self, decrypted_state, asymmetric_key_store):
        decrypted_state.set_keys_store(asymmetric_key_store)
        assert decrypted_state.opposite_state._decrypt_key is None
        decrypted_state.on_enter()
        expected_decrypt_key = decrypted_state._decrypt_key
        assert decrypted_state._is_entered is True
        assert decrypted_state._encrypt_key is not None
        assert expected_decrypt_key is not None
        decrypted_state.on_exit()
        assert decrypted_state.opposite_state._decrypt_key == expected_decrypt_key
        assert decrypted_state._is_entered is False

    def test_is_use_for_encrypt(self, decrypted_state):
        assert decrypted_state.is_use_for_encrypt() is True

    def test_opposite_state(self, decrypted_state):
        assert isinstance(decrypted_state.opposite_state, EncryptedState)
        assert decrypted_state.opposite_state.opposite_state == decrypted_state

    def test_set_keys_store(self, decrypted_state, symmetry_key_store):
        decrypted_state.set_keys_store(symmetry_key_store)
        assert decrypted_state._keys_store == symmetry_key_store
        assert decrypted_state.opposite_state._keys_store is None
