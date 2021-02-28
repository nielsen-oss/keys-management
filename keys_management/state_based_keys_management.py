from typing import Optional, Dict, Union, List
from . import KeysManagement, StateRepoInterface, CryptoTool, KeysStore, KeyIsNotDefinedError, \
    Key, OnChange
from .key_state import KeyState
from .key_state.state_factory import StateFactory
from .key_state.unknown_state import UnknownState
from .consts import KEEP_STATE, STATE, KEYS_STORE, ON_CHANGES_CALLBACKS, DECRYPTED_STATE, KEY
import logging


logger = logging.getLogger(__name__)

Keys = Dict[str, Dict[str, Union[bool, KeyState, KeysStore, List[OnChange]]]]


class KeysManagementStateBased(KeysManagement):
    state_repo: StateRepoInterface
    crypto_tool: CryptoTool
    keys: Keys

    def __init__(self, state_repo: StateRepoInterface, crypto_tool: CryptoTool):
        self.state_repo = state_repo
        self.crypto_tool = crypto_tool
        self.keys = {}

    def define_key(self, key_name: str, initial_keys_store: KeysStore, keep_state: bool = False) -> KeysManagement:
        logger.info('Defining the key "%s"' % key_name)
        initial_state: KeyState = UnknownState()
        self.keys[key_name] = {
            KEEP_STATE: keep_state,
            STATE: initial_state,
            KEYS_STORE: initial_keys_store,
            ON_CHANGES_CALLBACKS: []
        }
        return self

    def get_key(self, key_name: str, is_for_encrypt: bool = None) -> Key:
        logger.info('requested to get key for "%s"' % key_name)
        self._validate_key_name(key_name)
        current_state: KeyState = self._get_state(key_name)
        logger.debug('current state for "{}" is "{}"'.format(key_name, current_state.get_name()))
        rv_key: Key = current_state.get_key()
        if self._should_change_state(current_state, is_for_encrypt):
            self._change_state(key_name, current_state)
        return rv_key

    def _validate_key_name(self, key_name: str) -> None:
        if key_name not in self.keys:
            raise KeyIsNotDefinedError(key_name)

    @staticmethod
    def _should_change_state(current_state: KeyState, is_for_encrypt: bool = None) -> bool:
        return not isinstance(is_for_encrypt, bool) or current_state.is_use_for_encrypt() == is_for_encrypt

    def _get_state(self, key_name: str) -> KeyState:
        current_state: KeyState = self.keys[key_name][STATE]
        if current_state.get_name() == 'UnknownState':
            self._set_state(key_name)
            return self.keys[key_name][STATE]
        else:
            return current_state

    def _set_state(self, key_name: str) -> None:
        keys_store = self.keys[key_name][KEYS_STORE]
        if self.keys[key_name][KEEP_STATE]:
            state = self._fetch_state(key_name, keys_store)
        else:
            state = StateFactory.create_state(DECRYPTED_STATE, keys_store)
        state.enter()
        self.keys[key_name][STATE] = state

    def _fetch_state(self, key_name: str, keys_store: KeysStore) -> KeyState:
        raw_state = self.crypto_tool.decrypt(self.state_repo.read_state(key_name))
        return StateFactory.create_state(raw_state[STATE], keys_store, raw_state.get(KEY, None))

    def _write_state(self, key_name: str, state: Dict) -> None:
        self.state_repo.write_state(key_name, self.crypto_tool.encrypt(state))

    def _change_state(self, key_name: str, current_state: KeyState) -> KeysManagement:
        opposite_state: KeyState = current_state.get_opposite_state()
        logger.debug('going to change the key state for "{}" from "{}" to "{}"'.format(key_name, current_state.get_name(), opposite_state.get_name()))
        current_state.exit()
        opposite_state.enter()
        self.keys[key_name][STATE] = opposite_state
        return self

    def key_changed(self, key_name: str, old_key: Key, new_key: Key, new_key_store: Optional[KeysStore] = None) -> None:
        logger.info('the key "{}" is changed, registered callbacks will be executed'.format(key_name))
        for callback in self.keys[key_name][ON_CHANGES_CALLBACKS]:
            callback(old_key, new_key)

    def on_change(self, key_name: str, on_change_func: OnChange) -> None:
        logger.info('registering new OnChange callback for "%s"' % key_name)
        self._validate_key_name(key_name)
        self.keys[key_name][ON_CHANGES_CALLBACKS].append(on_change_func)

    def save_state(self, key_name: str):
        self._validate_key_name(key_name)
        raw_state = self.keys[key_name][STATE].to_dict()
        self._write_state(key_name, raw_state)

    def save_states(self):
        for key, item in self.keys.items():
            if item[KEEP_STATE]:
                self.save_state(key)
