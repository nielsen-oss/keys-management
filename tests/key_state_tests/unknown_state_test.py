from keys_management.key_state import UndefinedOperationError
import pytest
from ..utils import create_unknown_state, create_symmetry_key_store


def test_on_enter__error_is_raised():
    state = create_unknown_state()
    with pytest.raises(UndefinedOperationError):
        state.on_enter()


def test_on_exit__error_is_raised():
    state = create_unknown_state()
    with pytest.raises(UndefinedOperationError):
        state.on_exit()


def test_is_use_for_encrypt__error_is_raised():
    state = create_unknown_state()
    with pytest.raises(UndefinedOperationError):
        state.is_use_for_encrypt()


def test_get_key__error_is_raised():
    state = create_unknown_state()
    with pytest.raises(UndefinedOperationError):
        state.get_key()


def test_opposite_state__error_is_raised():
    state = create_unknown_state()
    assert state.opposite_state is None


def test_set_keys_store__error_is_raised():
    state = create_unknown_state()
    with pytest.raises(UndefinedOperationError):
        state.set_keys_store(create_symmetry_key_store())
