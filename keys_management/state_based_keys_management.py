from typing import Optional, Dict, Union
from keys_management import KeysManagementInterface, StateRepoInterface, CryptoTool, KeysStore, KeyIsNotDefinedError, \
    Key, OnChange
from keys_management.state import StateFactory, UnknownState, KeyState
from keys_management.consts import KEEP_STATE, STATE, KEYS_STORE

Keys = Dict[str, Dict[str, Union[bool, KeyState, KeysStore]]]


class KeysManagementStateBased(KeysManagementInterface):
    state_repo: StateRepoInterface
    crypto_tool: CryptoTool
    keys: Keys

    def __init__(self, state_repo: StateRepoInterface, crypto_tool: CryptoTool):
        self.state_repo = state_repo
        self.crypto_tool = crypto_tool
        self.keys = {}

    def define_key(self, key_name: str, initial_keys_store: KeysStore, keep_state: bool = False) -> KeysManagementInterface:
        initial_state: KeyState = UnknownState()
        self.keys[key_name] = {
            KEEP_STATE: keep_state,
            STATE: initial_state,
            KEYS_STORE: initial_keys_store
        }
        return self

    def get_key(self, key_name: str, is_for_encrypt: bool = None) -> Key:
        if key_name not in self.keys:
            raise KeyIsNotDefinedError(key_name)
        current_state: KeyState = self.get_state(key_name)
        rv_key: Key = current_state.get_key()
        if self.should_change_state(current_state, is_for_encrypt):
            self._change_state(key_name, current_state)
        return rv_key

    @staticmethod
    def should_change_state(current_state: KeyState, is_for_encrypt: bool = None) -> bool:
        return not isinstance(is_for_encrypt, bool) or current_state.is_use_for_encrypt() == is_for_encrypt

    def get_state(self, key_name: str) -> KeyState:
        current_state: KeyState = self.keys[key_name][STATE]
        if isinstance(current_state, UnknownState):
            self._fetch_state(key_name)
            return self.keys[key_name][STATE]
        else:
            return current_state

    def _fetch_state(self, key_name: str) -> None:
        raw_state = self.crypto_tool.decrypt(self.state_repo.read_state(key_name))
        state = StateFactory.create_state(raw_state[STATE])
        state.set_keys_store(self.keys[key_name][KEYS_STORE])
        self.keys[key_name][STATE] = state

    def _write_state(self, key_name: str):
        self.state_repo.write_state(key_name, {STATE: self.keys[key_name].__name__})

    def _change_state(self, key_name: str, current_state: KeyState) -> KeysManagementInterface:
        opposite_state: KeyState = current_state.opposite_state
        opposite_state.on_enter()
        current_state.on_exit()
        self.keys[key_name][STATE] = opposite_state
        return self

    def key_changed(self, key_name: str, old_key: Key, new_key: Key, new_key_store: Optional[KeysStore] = None):
        pass

    def on_change(self, key_name: str, on_change_func: OnChange):
        pass
