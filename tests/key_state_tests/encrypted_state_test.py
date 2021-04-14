import pytest
from ..utils import create_encrypted_state, create_symmetry_key_store
from keys_management.state_based.key_state import UndefinedOperationError
from keys_management.state_based.key_state.decrypted_state import (
    DecryptedState,
)
from keys_management.consts import STATE, ENCRYPTED_STATE, KEY
from keys_management.secret_key import SecretKey, SecretKeyUseCase


@pytest.fixture
def encrypted_state():
    return create_encrypted_state()


@pytest.fixture
def key_store():
    return create_symmetry_key_store()


class TestEncryptedState:
    def test_on_enter__decrypt_key_was_not_set_error_is_raised(
        self, encrypted_state
    ):
        assert encrypted_state._decrypt_key is None
        with pytest.raises(UndefinedOperationError):
            encrypted_state.enter()
        assert encrypted_state._is_entered is False

    def test_on_enter__decrypt_key_was_set(self, encrypted_state):
        key_store = create_symmetry_key_store()
        encrypted_state._decrypt_key = key_store()
        encrypted_state.enter()
        assert encrypted_state._is_entered is True

    def test_get_key__without_entering_first_error_is_raised(
        self, encrypted_state
    ):
        with pytest.raises(UndefinedOperationError):
            encrypted_state.get_key()

    def test_get_key(self, encrypted_state, key_store):
        expected_key = key_store()
        encrypted_state._decrypt_key = key_store()
        encrypted_state.set_keys_store(key_store)
        encrypted_state.enter()
        assert encrypted_state.get_key() == expected_key

    def test_on_exit(self, encrypted_state):
        encrypted_state._decrypt_key = SecretKey('key123')
        encrypted_state.enter()
        encrypted_state.exit()
        assert encrypted_state._is_entered is False
        assert encrypted_state._decrypt_key is None

    def test_get_use_case(self, encrypted_state):
        assert (
            encrypted_state.get_use_case() is SecretKeyUseCase.DECRYPTION
        )

    def test_opposite_state(self, encrypted_state):
        assert isinstance(
            encrypted_state.get_opposite_state(), DecryptedState
        )
        assert (
            encrypted_state.get_opposite_state().get_opposite_state()
            == encrypted_state
        )

    def test_set_keys_store(self, encrypted_state, key_store):
        assert encrypted_state.get_opposite_state()._keys_store is None
        encrypted_state.set_keys_store(key_store)
        assert encrypted_state.get_opposite_state()._keys_store is not None

    def test_to_dict_(self, encrypted_state, key_store):
        expected_key = key_store()
        encrypted_state._decrypt_key = expected_key
        encrypted_state.enter()
        assert encrypted_state.to_dict() == {
            STATE: ENCRYPTED_STATE,
            KEY: expected_key,
        }
