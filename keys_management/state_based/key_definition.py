from typing import List
from .key_state import KeyState
from .key_state.unknown_state import UnknownState
from .. import OnChange
from ..secret_key import KeysStore, BaseSecretKeyDefinition, SecretKeyUseCase, SecretKeyState
from keys_management.consts import ENCRYPTED_STATE, DECRYPTED_STATE


class SecretKeyDefinition(BaseSecretKeyDefinition):
    def get_key_state(self) -> SecretKeyState:
        pass

    def set_key_state(self, key_state: SecretKeyState) -> None:
        pass

    def get_last_use_case(self) -> SecretKeyUseCase:
        return self.state.get_use_case()

    def set_last_use_case(self, last_use: SecretKeyUseCase):
        opposite_state = self.state.get_opposite_state()
        if opposite_state.get_use_case() == last_use:
            self.change_state(opposite_state)

    _current_state: KeyState

    def __init__(self, name: str, keys_store: KeysStore, is_stateless: bool, use_case: SecretKeyUseCase, is_target_data_accessible: bool):
        super(SecretKeyDefinition, self).__init__(name, keys_store, use_case, is_stateless, is_target_data_accessible)
        self._current_state = UnknownState()

    @property
    def state(self) -> KeyState:
        return self._current_state

    def change_state(self, new_state: KeyState):
        self._current_state.exit()
        self._current_state = new_state
        new_state.enter()
