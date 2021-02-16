from keys_management.key_state import UndefinedOperationError
import pytest
from ..utils import create_unknown_state, create_symmetry_key_store


@pytest.fixture
def unknown_state():
    return create_unknown_state()


@pytest.fixture
def key_store():
    return create_symmetry_key_store()


class TestUnknownState:
    def test_on_enter__error_is_raised(self, unknown_state):
        with pytest.raises(UndefinedOperationError):
            unknown_state.on_enter()

    def test_on_exit__error_is_raised(self, unknown_state):
        with pytest.raises(UndefinedOperationError):
            unknown_state.on_exit()

    def test_is_use_for_encrypt__error_is_raised(self, unknown_state):
        with pytest.raises(UndefinedOperationError):
            unknown_state.is_use_for_encrypt()

    def test_get_key__error_is_raised(self, unknown_state):
        with pytest.raises(UndefinedOperationError):
            unknown_state.get_key()

    def test_opposite_state__error_is_raised(self, unknown_state):
        assert unknown_state.opposite_state is None

    def test_set_keys_store__error_is_raised(self, unknown_state, key_store):
        with pytest.raises(UndefinedOperationError):
            unknown_state.set_keys_store(key_store)
