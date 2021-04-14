import pytest
from ..utils import (
    create_one_state,
    create_symmetry_key_store,
    create_asymmetric_key_store,
)
from keys_management.state_based.key_state import UndefinedOperationError
from keys_management.secret_key import SecretKeyUseCase


@pytest.fixture
def one_state():
    return create_one_state()


@pytest.fixture
def symmetry_key_store():
    return create_symmetry_key_store()


@pytest.fixture
def asymmetric_key_store():
    return create_asymmetric_key_store()


@pytest.fixture
def key_store():
    return create_symmetry_key_store()


class TestOneState:
    def test_on_enter__without_key_store_error_is_raised(self, one_state):
        with pytest.raises(UndefinedOperationError):
            one_state.enter()
        assert one_state._is_entered is False

    def test_on_enter__with_symmetric_key_store_keys_were_set(
        self, one_state, symmetry_key_store
    ):
        assert one_state._secret_key is None
        one_state.set_keys_store(symmetry_key_store)
        assert one_state._secret_key is None
        expected_key = symmetry_key_store()
        one_state.enter()
        assert one_state._secret_key is not None
        assert one_state._secret_key.get_value() == expected_key
        assert one_state._is_entered is True

    def test_on_enter__with_asymmetric_key_store_error_is_raised(
        self, one_state, asymmetric_key_store
    ):
        assert one_state._secret_key is None
        one_state.set_keys_store(asymmetric_key_store)
        assert one_state._secret_key is None
        with pytest.raises(ValueError):
            one_state.enter()
        assert one_state._is_entered is False
        assert one_state._secret_key is None

    def test_get_key__without_entering_first_error_is_raised(
        self, one_state
    ):
        with pytest.raises(UndefinedOperationError):
            one_state.get_key()

    def test_get_key(self, one_state, symmetry_key_store):
        expected_key = symmetry_key_store()
        one_state.set_keys_store(symmetry_key_store)
        one_state.enter()
        assert one_state.get_key().get_value() == expected_key

    def test_on_exit(self, one_state, symmetry_key_store):
        one_state.set_keys_store(symmetry_key_store)
        one_state.enter()
        assert one_state._is_entered is True
        assert one_state._secret_key is not None
        one_state.exit()
        assert one_state._is_entered is False
        assert one_state._secret_key is None

    def test_get_use_case(self, one_state):
        assert (
            one_state.get_use_case()
            is SecretKeyUseCase.ENCRYPTION_DECRYPTION
        )

    def test_opposite_state(self, one_state):
        assert one_state.get_opposite_state() == one_state

    def test_set_keys_store(self, one_state, symmetry_key_store):
        one_state.set_keys_store(symmetry_key_store)
        assert one_state._key_store is not None
        assert symmetry_key_store() == one_state._key_store().get_value()
